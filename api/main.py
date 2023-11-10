import fastapi
from fastapi import responses, WebSocket
import uvicorn
from uuid import uuid4
import secrets
from passlib.context import CryptContext
import time
from pydantic import BaseModel
import json
import asyncio

from config import Config
from database import Database
from database import Schemas


class UpdateAgent(BaseModel):
    name: str = None
    description: str = None
    version: int = None
    secret: str


allLimitations = ['linux', 'windows', 'macos']


class AgentCommand(BaseModel):
    command: str
    limitations: list[str] = None


class User(BaseModel):
    username: str
    password: str


class AllowUser(BaseModel):
    username: str
    password: str

    target_user: str


class Connection:
    def __init__(self, websocket: WebSocket, uuid: str):
        self.websocket = websocket
        self.uuid = uuid
        self._rec_buffer = asyncio.Queue()

    async def send_json(self, message: dict):
        await self.websocket.send_json(message)

    async def receive_json(self):
        return await self._rec_buffer.get()


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[Connection] = []

    def get_connection(self, uuid: str):
        for conn in self.active_connections:
            if conn.uuid == uuid:
                return conn

    async def connect(self, websocket: WebSocket, uuid: str):
        await websocket.accept()
        self.active_connections.append(Connection(websocket, uuid))

        await websocket.send_json({"status": "200"})

    def disconnect(self, websocket_or_uuid: WebSocket | str):
        for connection in self.active_connections:
            if isinstance(websocket_or_uuid, WebSocket):
                if connection.websocket == websocket_or_uuid:
                    self.active_connections.remove(connection)
                    return
            else:
                if connection.uuid == websocket_or_uuid:
                    self.active_connections.remove(connection)
                    return

    async def send_personal_message(self, message: dict, websocket_or_uuid: WebSocket | str):
        for connection in self.active_connections:
            if isinstance(websocket_or_uuid, WebSocket):
                if connection.websocket == websocket_or_uuid:
                    await connection.websocket.send_json(message)
                    return
            else:
                if connection.uuid == websocket_or_uuid:
                    await connection.websocket.send_json(message)
                    return

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.websocket.send_json(message)


manager = ConnectionManager()

config: Config = Config()

db: Database = Database(config.dbstring)

app = fastapi.FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.get("/agent/register")
async def register_agent(version: int, name: str = None, description: str = None):
    """
    Register an agent with the server.
    :param name: The name of the agent.
    :param description: A description of the agent.
    :param version: The version of the agent.
    :return: The agent's UUID.
    """

    secret = secrets.token_urlsafe(32)

    secret_hashed = pwd_context.hash(secret)

    agent = Schemas.AgentSchema(
        uuid=str(uuid4()),
        secret=secret_hashed,
        name=name,
        description=description,
        version=version,
        created_at=int(time.time())
    )

    await db.agents.insert_one(agent.to_dict())

    response = agent.to_dict()
    response['raw_secret'] = secret

    return responses.JSONResponse(response, status_code=200)


@app.get("/agent/{uuid}")
async def get_agent(uuid: str):
    """
    Get an agent's information.
    :param uuid: The agent's UUID.
    :return: The agent's information.
    """

    agent = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))

    if agent is None:
        return responses.JSONResponse({"error": "Agent not found."}, status_code=404)

    return responses.JSONResponse(agent.to_dict(), status_code=200)


@app.post("/agent/{uuid}/update")
async def update_agent(uuid: str, update: UpdateAgent):
    """
    Update an agent's information.
    :param uuid: The agent's UUID.
    :param update: The update information.
    :return: The agent's information.
    """

    agent = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))

    if not pwd_context.verify(update.secret, agent.secret):
        return responses.JSONResponse({"error": "Invalid secret."}, status_code=401)

    diff = {"$set": {}}

    if update.name is not None:
        diff["$set"]["name"] = update.name
        agent.name = update.name

    if update.description is not None:
        diff["$set"]["description"] = update.description
        agent.description = update.description

    if update.version is not None:
        diff["$set"]["version"] = update.version
        agent.version = update.version

    await db.agents.update_one(Schemas.AgentSchema(uuid=uuid), diff)

    return responses.JSONResponse(agent.to_dict(), status_code=200)


@app.post("/agent/{uuid}/command")
async def send_command(uuid: str, command: AgentCommand):
    """
    Send a command to an agent.
    :param uuid: The agent's UUID.
    :param command: The command to send.
    :return: The agent's information.
    """

    agent: Schemas.AgentSchema = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))

    if agent is None:
        return responses.JSONResponse({"error": "Agent not found."}, status_code=404)

    if command.limitations is not None:
        for limitation in command.limitations:
            if limitation not in allLimitations:
                return responses.JSONResponse({"error": "Invalid limitation."}, status_code=401)

    await manager.send_personal_message({"command": command.command, "limitations": command.limitations}, uuid)

    return responses.Response("", 200)

    conn = manager.get_connection(uuid)

    try:
        res = await conn.receive_json()
    except fastapi.WebSocketDisconnect as e:
        return responses.JSONResponse({"error": "Agent not connected."}, status_code=401)

    return responses.JSONResponse(res, status_code=200)


@app.websocket("/agent/{uuid}/ws")
async def agent_ws(websocket: fastapi.WebSocket, uuid: str):
    """
    Handle an agent's websocket connection.
    :param websocket: The websocket connection.
    :param uuid: The agent's UUID.

    :return: None
    """

    await manager.connect(websocket, uuid)

    # Authenticate the agent
    data = await websocket.receive_json()
    if data is None:
        await websocket.close(code=400, reason="No data provided.")
        manager.disconnect(websocket)
        return

    if data.get("secret") is None:
        await websocket.close(code=400, reason="No secret provided.")
        manager.disconnect(websocket)
        return

    agent = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))
    if agent is None:
        await websocket.close(code=400, reason="Agent not found.")
        manager.disconnect(websocket)
        return

    if not pwd_context.verify(data.get("secret"), agent.secret):
        await websocket.close(code=401, reason="Invalid secret.")
        await manager.disconnect(websocket)
        return
    
    conn = manager.get_connection(uuid)

    try:
        while True:
            start = time.perf_counter()
            data = await websocket.receive_json()
            end = time.perf_counter()
            print(f"Received data in {end - start} seconds.")
            start = time.perf_counter()
            data = json.loads(data)
            conn._rec_buffer.put(data)
            end = time.perf_counter()
            print(f"Received data in {end - start} seconds.")
    except fastapi.WebSocketDisconnect as e:
        manager.disconnect(websocket)


@app.get("/user/{uuid}")
async def get_user(uuid: str):
    """
    Get a user's information.
    :param uuid: The user's UUID.
    :return: The user's information.
    """

    user = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)

    return responses.JSONResponse(user.to_dict(), status_code=200)


@app.post("/user/register")
async def register_user(user: User):
    """
    Register a user with the server.
    :param username: The user's username.
    :param password: The user's password.
    :return: The user's UUID.
    """

    user = Schemas.UserSchema(
        uuid=str(uuid4()),
        username=user.username,
        password=pwd_context.hash(user.password),
        created_at=int(time.time()),
        is_allowed=False
    )

    await db.users.insert_one(user.to_dict())

    return responses.JSONResponse(user.to_dict(), status_code=200)


@app.post("/user/login")
async def login_user(user: User):
    """
    Login a user.
    :param username: The user's username.
    :param password: The user's password.
    :return: The user's UUID.
    """

    dbuser: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(username=user.username))

    if dbuser is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)

    if not pwd_context.verify(user.password, dbuser.password):
        return responses.JSONResponse({"error": "Invalid password."}, status_code=401)

    if not dbuser.is_allowed:
        return responses.JSONResponse({"error": "User not allowed."}, status_code=401)

    diff = {"$set": {"auth_token": "", "auth_timeout": 0}}

    auth_token = secrets.token_urlsafe(32)
    dbuser.auth_token = auth_token

    auth_token_hashed = pwd_context.hash(auth_token)
    diff["$set"]["auth_token"] = auth_token_hashed

    auth_token_timeout = int(time.time()) + 5260000  # 2 months
    dbuser.auth_timeout = auth_token_timeout
    diff["$set"]["auth_timeout"] = auth_token_timeout

    return responses.JSONResponse(dbuser.to_dict(), status_code=200)


@app.post("/user/{uuid}/allow")
async def authorize_user(uuid: str, allow: AllowUser):
    """
    Allow a user to use the API.
    :param username: The user's username.
    :param password: The user's password.
    :return: The user's UUID.
    """

    user = await db.users.find_one(Schemas.UserSchema(username=allow.username))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)

    if not pwd_context.verify(allow.password, user.password):
        return responses.JSONResponse({"error": "Invalid password."}, status_code=401)

    await db.users.update_one(Schemas.UserSchema(username=allow.target_user), {"$set": {"is_allowed": True}})

    return responses.JSONResponse(user.to_dict(), status_code=200)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
