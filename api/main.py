import fastapi
from fastapi import responses
import uvicorn
from uuid import uuid4
import secrets
from passlib.context import CryptContext
import time
from pydantic import BaseModel

from config import Config
from database import Database
from database import Schemas

class UpdateAgent(BaseModel):
    name: str = None
    description: str = None
    version: int = None
    secret: str

config = Config()

db = Database(config.dbstring)

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


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
