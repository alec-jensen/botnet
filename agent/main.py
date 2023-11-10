import websockets
import asyncio
import json
import os
import traceback

debugMode = True


def debug(*args):
    if debugMode:
        print(*args)


"""{
  "uuid": "27d21355-f112-4b5f-b2b2-d47307d5542e",
  "secret": "$2b$12$lXZNLCNtMmVueyFnuuW9b.zu/54JowUSgiUhvAeHR8caa8rb45Y8S",
  "name": "agent1",
  "description": "yomama",
  "version": 0,
  "created_at": 1699655826,
  "raw_secret": "S1AeiwRMp6JIEOOdGNiyhn1J9mqgYQED5X8YaTRlheI"
}"""


UUID = "27d21355-f112-4b5f-b2b2-d47307d5542e"

WS_URL = f"ws://127.0.0.1:8000/agent/{UUID}/ws"

# deepcode ignore HardcodedNonCryptoSecret: this is purely for testing
SECRET = "S1AeiwRMp6JIEOOdGNiyhn1J9mqgYQED5X8YaTRlheI"


async def main():
    while True:
        try:
            async with websockets.connect(WS_URL) as ws:
                # Send authentication
                await ws.send(json.dumps({
                    "secret": SECRET
                }))
                res = await ws.recv()
                res = json.loads(res)
                debug(res)
                if res.get("status") != '200':
                    raise Exception("Authentication failed")

                while True:
                    res = await ws.recv()
                    res = json.loads(res)
                    debug("recv: " + str(res))

                    output = os.popen(res.get("command")).read()
                    debug(output)

                    await ws.send(json.dumps({
                        "status": 200,
                        "output": output
                    }))

        except Exception as e:
            debug(traceback.format_exc())
            await asyncio.sleep(5)

while True:
    asyncio.run(main())
