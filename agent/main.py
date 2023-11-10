import websockets
import asyncio
import json

UUID = "91ba9cdb-0607-42bf-b200-8eb0b6a02e2b"

WS_URL = f"ws://127.0.0.1:8000/agent/{UUID}/ws"

async def main():
    async with websockets.connect(WS_URL) as ws:
        # Wait for authentication
        res = await ws.recv()
        res = json.loads(res)
        if res.get("status") != '200':
            raise Exception("Authentication failed")
        
        while True:
            res = await ws.recv()
            print(res)

while True:
    try:
        asyncio.run(main())
    except Exception as e:
        pass
    