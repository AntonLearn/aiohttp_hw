import json
import bcrypt
import schema
from aiohttp import web
from settings import HOST_LOCATION, PORT_LOCATION
from models import init_orm, close_orm, Session, User, Adv
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from pydantic import ValidationError


def hash_password(password: str):
    password = password.encode()
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_password.decode()


def check_password(password: str, hashed_password: str):
    password = password.encode()
    hashed_password = hashed_password.encode()
    return bcrypt.checkpw(password, hashed_password)


app = web.Application()


async def orm_context(app):
    await init_orm()
    yield
    await close_orm()


@web.middleware
async def session_middleware(request: web.Request, handler):
    async with Session() as session:
        request.session = session
        response = await handler(request)
        return response

app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)


def get_http_error(error_cls, error_msg):
    error = error_cls(
        text=json.dumps({
            "error": error_msg
        }),
        content_type="application/json")
    return error


def validate(json_data: dict,
             schema_cls: type[schema.UpdateUser] | type[schema.CreateUser] |
                         type[schema.UpdateAdv]  | type[schema.CreateAdv]):
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop('ctx', None)
        raise get_http_error(web.HTTPBadRequest, errors)


async def get_user_by_id(session: AsyncSession, user_id: int):
    user_object = (await session.execute(select(User).where(User.id == user_id))).scalars().first()
    if user_object is None:
        raise get_http_error(web.HTTPNotFound, "User not found!")
    return user_object


async def get_user_by_all(session: AsyncSession):
    user_object_list = (await session.execute(select(User))).scalars().all()
    if not user_object_list:
        raise get_http_error(web.HTTPNotFound, "Users not found!")
    return user_object_list


async def add_user(session: AsyncSession, user: User):
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        raise get_http_error(web.HTTPConflict, "User already exist!")
    return user


class UserView(web.View):

    @property
    def session(self) -> AsyncSession:
        return self.request.session

    @property
    def user_id(self):
        if "user_id" in self.request.match_info:
            return int(self.request.match_info["user_id"])
        else:
            return None

    async def get(self):
        if self.user_id is None:
            user_object_list = await get_user_by_all(self.session)
            user_list = list()
            for user_object in user_object_list:
                user_list.append(user_object.json)
            return web.json_response(user_list)
        else:
            user_object = await get_user_by_id(self.session, self.user_id)
            return web.json_response(user_object.json)

    async def post(self):
        json_data = validate(await self.request.json(), schema.CreateUser)
        json_data['password'] = hash_password(json_data['password'])
        user_object = User(**json_data)
        user_object = await add_user(self.session, user_object)
        return web.json_response(user_object.json)

    async def patch(self):
        json_data = validate(await self.request.json(), schema.UpdateUser)
        if 'password' in json_data:
            json_data['password'] = hash_password(json_data['password'])
        user_object = await get_user_by_id(self.session, self.user_id)
        for field, value in json_data.items():
            setattr(user_object, field, value)
        user_object = await add_user(self.session, user_object)
        return web.json_response(user_object.json)

    async def delete(self):
        user_object = await get_user_by_id(self.session, self.user_id)
        await self.session.delete(user_object)
        await self.session.commit()
        return web.json_response({'status': 'deleted'})


async def get_owner_by_id(session: AsyncSession, owner_id: int):
    owner_object = (await session.execute(select(User).where(User.id == owner_id))).scalars().first()
    if owner_object is None:
        raise get_http_error(web.HTTPNotFound, "Owner not found!")
    return owner_object


async def get_adv_by_id(session: AsyncSession, adv_id: int):
    adv_object = (await session.execute(select(Adv).where(Adv.id == adv_id))).scalars().first()
    if adv_object is None:
        raise get_http_error(web.HTTPNotFound, "Advertisement not found!")
    return adv_object


async def get_adv_by_all(session: AsyncSession):
    adv_object_list = (await session.execute(select(Adv))).scalars().all()
    if not adv_object_list:
        raise get_http_error(web.HTTPNotFound, "Advertisements not found!")
    return adv_object_list


def raise_post_error(user_found, authorization):
    if not user_found:
        raise get_http_error(web.HTTPNotFound, "Owner not found!")
    if not authorization:
        raise get_http_error(web.HTTPNotFound, "Owner is found but not authorized!")


def raise_patch_delete_error(user_is_owner, user_found, authorization):
    if not user_is_owner:
        raise get_http_error(web.HTTPNotFound, "User is not owner!")
    if not user_found:
        raise get_http_error(web.HTTPNotFound, "User is owner but not found!")
    if not authorization:
        raise get_http_error(web.HTTPNotFound, "User is owner and found but not authorized!")


async def add_adv(session: AsyncSession, adv, password, user_id):
    user_object_list = (await session.execute(select(User))).scalars().all()
    if not user_object_list:
        raise get_http_error(web.HTTPNotFound, "Users not found!")
    user_is_owner = False
    user_found = False
    authorization = False
    if user_id is None:
        for user_object in user_object_list:
            user_id_db = getattr(user_object, User.id.key)
            if adv.owner_id == user_id_db:
                user_found = True
                hashed_password = getattr(user_object, User.password.key)
                if check_password(password, hashed_password):
                    authorization = True
        raise_post_error(user_found, authorization)
    else:
        if user_id == adv.owner_id:
            user_is_owner = True
            for user_object in user_object_list:
                user_id_db = getattr(user_object, User.id.key)
                if adv.owner_id == user_id_db:
                    user_found = True
                    hashed_password = getattr(user_object, User.password.key)
                    if check_password(password, hashed_password):
                        authorization = True
        raise_patch_delete_error(user_is_owner, user_found, authorization)
    session.add(adv)
    try:
        await session.commit()
    except IntegrityError:
        raise get_http_error(web.HTTPConflict, "Advertisement already exists!")
    return adv


async def delete_adv(session: AsyncSession, adv, password, user_id):
    user_object_list = (await session.execute(select(User))).scalars().all()
    if not user_object_list:
        raise get_http_error(web.HTTPNotFound, "Users not found!")
    authorization = False
    user_found = False
    user_is_owner = False
    if user_id is None:
        raise get_http_error(web.HTTPNotFound, 'User ID is missing!')
    else:
        if user_id == adv.owner_id:
            user_is_owner = True
            for user_object in user_object_list:
                user_id_db = getattr(user_object, User.id.key)
                if adv.owner_id == user_id_db:
                    user_found = True
                    hashed_password = getattr(user_object, User.password.key)
                    if check_password(password, hashed_password):
                        authorization = True
        raise_patch_delete_error(user_is_owner, user_found, authorization)
    await session.delete(adv)
    await session.commit()
    return adv


class AdvView(web.View):

    @property
    def session(self) -> AsyncSession:
        return self.request.session

    @property
    def adv_id(self):
        if "adv_id" in self.request.match_info:
            return int(self.request.match_info["adv_id"])
        else:
            return None

    async def get(self):
        if self.adv_id is None:
            adv_object_list = await get_adv_by_all(self.session)
            adv_list = list()
            for adv_object in adv_object_list:
                adv_list.append(adv_object.json)
            return web.json_response(adv_list)
        else:
            adv_object = await get_adv_by_id(self.session, self.adv_id)
            return web.json_response(adv_object.json)

    async def post(self):
        json_data = validate(await self.request.json(), schema.CreateAdv)
        adv_object = Adv(**json_data)
        password = self.request.headers['Authorization']
        adv_object = await add_adv(self.session, adv_object, password, user_id=None)
        return web.json_response(adv_object.json)

    async def patch(self):
        json_data = validate(await self.request.json(), schema.UpdateAdv)
        adv_object = await get_adv_by_id(self.session, self.adv_id)
        for field, value in json_data.items():
            setattr(adv_object, field, value)
        user_id = self.request.headers['Id']
        password = self.request.headers['Authorization']
        adv_object = await add_adv(self.session, adv_object, password, user_id=int(user_id))
        return web.json_response(adv_object.json)

    async def delete(self):
        user_id = self.request.headers['Id']
        password = self.request.headers['Authorization']
        adv_object = await get_adv_by_id(self.session, self.adv_id)
        await delete_adv(self.session, adv_object, password, user_id=int(user_id))
        return web.json_response({'status': 'deleted'})


app.add_routes(
    [
        web.get("/user/{user_id:\\d+}", UserView),
        web.get("/user/", UserView),
        web.patch("/user/{user_id:\\d+}", UserView),
        web.delete("/user/{user_id:\\d+}", UserView),
        web.post("/user/", UserView),
        web.get("/adv/{adv_id:\\d+}", AdvView),
        web.get("/adv/", AdvView),
        web.patch("/adv/{adv_id:\\d+}", AdvView),
        web.delete("/adv/{adv_id:\\d+}", AdvView),
        web.post("/adv/", AdvView)
    ]
)

web.run_app(app, host=HOST_LOCATION, port=PORT_LOCATION)