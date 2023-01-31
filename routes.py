from aiohttp import web

from handlers import index, user_register, token_register, token_delete, token_delete_all, adv_create, adv_read, \
    adv_delete, adv_update


def setup_routes(app: web.Application):
    app.router.add_get('/', index)

    app.router.add_post('/create_user/', user_register)

    app.router.add_post('/token/create/', token_register)
    app.router.add_delete('/token/delete_all/', token_delete_all)
    app.router.add_delete('/token/delete/', token_delete)

    app.router.add_post('/advertisement', adv_create)
    app.router.add_get('/advertisement/{adv_id}', adv_read)
    app.router.add_patch('/advertisement/{adv_id}', adv_update)
    app.router.add_delete('/advertisement/{adv_id}', adv_delete)
