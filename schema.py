import pydantic


class UserBase(pydantic.BaseModel):
    name: str
    password: str

    @pydantic.field_validator("password")
    @classmethod
    def check_password(cls, value):
        if len(value) < 8:
            raise ValueError("Password is too short!")
        return value


class CreateUser(UserBase):
    name: str
    password: str


class UpdateUser(UserBase):
    name: str | None = None
    password: str | None = None


class AdvBase(pydantic.BaseModel):
    header: str
    owner_id: int
    description: str


class CreateAdv(AdvBase):
    header: str
    owner_id: int
    description: str


class UpdateAdv(AdvBase):
    header: str | None = None
    owner_id: int | None = None
    description: str | None = None
