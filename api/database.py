# Database wrapper for intellisense
# Copyright (C) 2023  Alec Jensen
# Full license at LICENSE.md

from typing import Any
import motor.motor_asyncio


def convert_except_none(value, type):
    if value is None:
        return None

    return type(value)


def remove_none_values(dictionary: dict) -> dict:
    return {key: value for key, value in dictionary.items() if value is not None}


class Schemas:
    class BaseSchema:
        def __init__(self) -> None:
            pass

        @classmethod
        def from_dict(cls, data: dict) -> 'Schemas.BaseSchema':
            raise NotImplementedError(
                'This method must be implemented in a subclass.')

        def to_dict(self) -> dict:
            raise NotImplementedError(
                'This method must be implemented in a subclass.')

        def __str__(self) -> str:
            string_repr = self.__class__.__name__ + '('
            for key, value in self.__dict__.items():
                string_repr += f'{key}={value}, '
            string_repr = string_repr[:-2] + ')'
            return string_repr

        def __repr__(self) -> str:
            return self.__str__()

        def __iter__(self):
            for key, value in self.__dict__.items():
                yield key, value

        def __getitem__(self, key: str) -> Any:
            return getattr(self, key)

    class AgentSchema(BaseSchema):
        def __init__(self, uuid: str | None = None, secret: str | None = None, name: str | None = None, description: str | None = None, version: int | None = None, created_at: int | None = None) -> None:
            self.uuid: str | None = convert_except_none(uuid, str)
            self.secret: str | None = convert_except_none(secret, str)
            self.name: str | None = convert_except_none(name, str)
            self.description: str | None = convert_except_none(
                description, str)
            self.version: int | None = convert_except_none(version, int)
            self.created_at: int | None = convert_except_none(created_at, int)

        @classmethod
        def from_dict(cls, data: dict | None) -> 'Schemas.AgentSchema':
            if data is None:
                return cls()

            return cls(data.get('uuid', None), data.get('secret', None), data.get('name', None), data.get('description', None), data.get('version', None), data.get('created_at', None))

        def to_dict(self) -> dict:
            return remove_none_values({
                'uuid': self.uuid,
                'secret': self.secret,
                'name': self.name,
                'description': self.description,
                'version': self.version,
                'created_at': self.created_at
            })
        
    class UserSchema(BaseSchema):
        def __init__(self, uuid: str | None = None, username: str | None = None, password: str | None = None, created_at: int | None = None, is_allowed: bool | None = None, auth_token: str | None = None, auth_timeout: int | None = None) -> None:
            self.uuid: str | None = convert_except_none(uuid, str)
            self.username: str | None = convert_except_none(username, str)
            self.password: str | None = convert_except_none(password, str)
            self.created_at: int | None = convert_except_none(created_at, int)
            self.is_allowed: bool | None = convert_except_none(is_allowed, bool)
            self.auth_token: str | None = convert_except_none(auth_token, str)
            self.auth_timeout: int | None = convert_except_none(auth_timeout, int)

        @classmethod
        def from_dict(cls, data: dict | None) -> 'Schemas.UserSchema':
            if data is None:
                return cls()

            return cls(data.get('uuid', None), data.get('username', None), data.get('password', None), data.get('created_at', None), data.get('is_allowed', None), data.get('auth_token', None), data.get('auth_timeout', None))
        
        def to_dict(self) -> dict:
            return remove_none_values({
                'uuid': self.uuid,
                'username': self.username,
                'password': self.password,
                'created_at': self.created_at,
                'is_allowed': self.is_allowed,
                'auth_token': self.auth_token,
                'auth_timeout': self.auth_timeout
            })


class Collection:
    """Wrapper for motor.motor_asyncio.AsyncIOMotorCollection. If a schema is provided, all queries will be converted to the schema."""

    def __init__(self, collection: motor.motor_asyncio.AsyncIOMotorCollection, schema: Schemas.BaseSchema = None) -> None:
        self.collection: motor.motor_asyncio.AsyncIOMotorCollection = collection
        self.schema: Schemas.BaseSchema = schema

    """Find one document in the collection. If a schema is provided, it will be converted to the schema."""
    async def find_one(self, query: Schemas.BaseSchema | dict, schema: Schemas.BaseSchema = None) -> dict | Schemas.BaseSchema:
        if isinstance(query, Schemas.BaseSchema):
            schema = query.__class__
            query = query.to_dict()

        document = await self.collection.find_one(query)
        if schema is None:
            schema = self.schema

        return document if schema is None else schema.from_dict(document)

    """Find all documents in the collection. If a schema is provided, it will be converted to the schema."""
    async def find(self, query: Schemas.BaseSchema | dict, schema: Schemas.BaseSchema | dict = None) -> list[dict] | list[Schemas.BaseSchema]:
        if isinstance(query, Schemas.BaseSchema):
            schema = query.__class__
            query = query.to_dict()

        documents = await self.collection.find(query)
        if schema is None:
            schema = self.schema

        if schema is None:
            return documents

        return [schema.from_dict(document) for document in documents]

    """Update one document in the collection."""
    async def update_one(self, query: dict | Schemas.BaseSchema, update: dict) -> None:
        if isinstance(query, Schemas.BaseSchema):
            query = query.to_dict()

        await self.collection.update_one(query, update)

    """Delete one document in the collection."""
    async def delete_one(self, query: dict | Schemas.BaseSchema) -> None:
        if isinstance(query, Schemas.BaseSchema):
            query = query.to_dict()

        await self.collection.delete_one(query)

    """Insert one document in the collection."""
    async def insert_one(self, document: dict | Schemas.BaseSchema) -> None:
        if isinstance(document, Schemas.BaseSchema):
            document = document.to_dict()

        await self.collection.insert_one(document)

    """Count the number of documents in the collection."""
    async def count_documents(self, query: dict | Schemas.BaseSchema) -> int:
        if isinstance(query, Schemas.BaseSchema):
            query = query.to_dict()

        return await self.collection.count_documents(query)


class Database:
    def __init__(self, dbstring: str) -> None:
        self.client: motor.motor_asyncio.AsyncIOMotorClient = motor.motor_asyncio.AsyncIOMotorClient(
            dbstring)

        self.database: motor.motor_asyncio.AsyncIOMotorDatabase = self.client.data

    @property
    def agents(self) -> Collection:
        return Collection(self.database.agents)
    
    @property
    def users(self) -> Collection:
        return Collection(self.database.users)
