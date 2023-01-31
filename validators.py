import re
from typing import Optional, Type

import pydantic

from errors import HttpError


class CreateUserValidator(pydantic.BaseModel):
    email: pydantic.EmailStr
    password: str

    @classmethod
    @pydantic.validator('password')
    def check_password(cls, value: str):
        if len(value) > 40:
            raise ValueError('password should be not longer than 40 symbols')

        password_regex = re.compile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])*.{8,40}$")

        if not re.search(password_regex, value):
            raise ValueError('password is too easy')

        return value


class GetOrDeleteAllTokenValidator(pydantic.BaseModel):
    email: pydantic.EmailStr
    password: str


class DeleteTokenValidator(pydantic.BaseModel):
    email: pydantic.EmailStr
    password: str
    token: str


class CreateAdvertisementValidator(pydantic.BaseModel):
    title: str
    description: Optional[str]


class PatchAdvertisementValidator(pydantic.BaseModel):
    title: Optional[str]
    description: Optional[str]


def validate(data_to_validate: dict, validation_model: Type[pydantic.BaseModel]):
    try:
        return validation_model(**data_to_validate).dict(exclude_none=True)
    except pydantic.ValidationError as er:
        raise HttpError(400, er.errors())
