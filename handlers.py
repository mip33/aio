from sqlite3 import IntegrityError

import bcrypt
from aiohttp import web
from sqlalchemy.orm import Session

from auth import password_auth, token_auth, owner_token_auth
from errors import HttpError
from models import UserModel, TokenModel, Advertisement
from validators import validate, CreateUserValidator, GetOrDeleteAllTokenValidator, DeleteTokenValidator, \
    CreateAdvertisementValidator, PatchAdvertisementValidator


async def index(request):
    return web.Response(text="success")


async def user_register(request):
    user_data = validate(await request.json(), CreateUserValidator)
    user_data['password_hash'] = bcrypt.hashpw(user_data.pop('password').encode(), bcrypt.gensalt()).decode()

    with Session() as session:
        user = UserModel(**user_data)
        session.add(user)

        try:
            session.commit()
        except IntegrityError:
            raise HttpError(409, 'user with such email already exists')

        return web.json_response({'status': 'success', 'id': user.id, 'email': user.email})


async def token_register(request):
    user_data = validate(await request.json(), GetOrDeleteAllTokenValidator)

    with Session() as session:
        user = password_auth(session, user_data)
        token = TokenModel(user=user)
        session.add(token)

        try:
            session.commit()
        except IntegrityError:
            raise HttpError(418, 'something terrible and almost impossible happened, please try to get token again')

        return web.json_response({
            'token': str(token.id),
            'message': 'save your token, you will not be able to get it again, only to create the new one'
        })


async def token_delete(request):
    user_data = validate(await request.json(), DeleteTokenValidator)

    with Session() as session:
        user = password_auth(session, user_data)

        try:
            token = session.query(TokenModel).filter(TokenModel.id == user_data['token']).first()
        except (ValueError, TypeError):
            raise HttpError(401, 'incorrect token')

        if (not token) or (token.user_id != user.id):
            raise HttpError(404, 'indicated token does not exist')

        session.delete(token)
        session.commit()

        return web.json_response({'status': 'success'})


async def token_delete_all(request):
    user_data = validate(await request.json(), GetOrDeleteAllTokenValidator)

    with Session() as session:
        user = password_auth(session, user_data)

        session.query(TokenModel).filter(TokenModel.user_id == user.id).delete()
        session.commit()

        return web.json_response({'status': 'success'})


async def adv_create(request):
    adv_data = validate(await request.json(), CreateAdvertisementValidator)

    with Session() as session:
        token = token_auth(session, request.headers.get('token'))
        adv_data['owner'] = token.user_id
        new_adv = Advertisement(**adv_data)

        session.add(new_adv)
        session.commit()

        return web.json_response({'status': 'success', 'id': new_adv.id, 'title': new_adv.title,
                                  'description': new_adv.description, 'created_at': str(new_adv.created_at)})


async def adv_read(request):
    adv_id = request.match_info['adv_id']

    with Session() as session:
        adv = session. \
            query(Advertisement). \
            filter(Advertisement.id == adv_id). \
            join(Advertisement.user). \
            first()

        if not adv:
            raise HttpError(404, 'indicated advertisement does not exist')

        return web.json_response({'id': adv.id,
                                  'title': adv.title,
                                  'owner_email': adv.user.email,
                                  'description': adv.description,
                                  'created_at': str(adv.created_at)})


async def adv_update(request):
    adv_id = request.match_info['adv_id']
    adv_data = validate(await request.json(), PatchAdvertisementValidator)

    with Session() as session:
        token = token_auth(session, request.headers.get('token'))
        advertisement = owner_token_auth(session, adv_id, token)

        for field, value in adv_data.items():
            setattr(advertisement, field, value)

        session.add(advertisement)
        session.commit()

        return web.json_response({'status': 'success', 'id': advertisement.id, 'title': advertisement.title,
                                  'description': advertisement.description})


async def adv_delete(request):
    adv_id = request.match_info['adv_id']
    with Session() as session:
        token = token_auth(session, request.headers.get('token'))
        advertisement = owner_token_auth(session, adv_id, token)

        session.delete(advertisement)
        session.commit()

        return web.json_response({'status': 'success'})
