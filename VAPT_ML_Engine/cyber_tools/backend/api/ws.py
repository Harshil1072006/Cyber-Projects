"""
WebSocket endpoint for real-time CLI output streaming.
The frontend connects here and receives tool output line-by-line.
"""
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.plugins.tools import TOOL_REGISTRY
from backend.engine.runner import stream_command

router = APIRouter()


@router.websocket("/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        tool_id = data.get("tool")
        target = data.get("target")
        options = data.get("options", {})

        plugin = TOOL_REGISTRY.get(tool_id)
        if not plugin:
            await websocket.send_json({"type": "error", "message": f"Tool '{tool_id}' not found"})
            await websocket.close()
            return

        cmd = plugin.build_command(target, options)
        await websocket.send_json({"type": "command", "data": " ".join(cmd)})

        async for line in stream_command(cmd):
            await websocket.send_json({"type": "output", "data": line})

        await websocket.send_json({"type": "done", "message": "Scan complete"})
    except WebSocketDisconnect:
        pass
    except FileNotFoundError as e:
        await websocket.send_json({"type": "error", "message": f"Tool not installed: {str(e)}"})
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
