"""
Secure subprocess runner.
RULE: NEVER use shell=True. NEVER concatenate strings into commands.
All commands must be list[str] from ToolPlugin.build_command().
"""
import asyncio
import subprocess
from typing import AsyncGenerator


async def stream_command(cmd: list[str]) -> AsyncGenerator[str, None]:
    """
    Async generator that runs a command and yields output lines one by one.
    Used for WebSocket streaming of live tool output.
    """
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        # shell=False is the default — NEVER change this
    )
    async for line in process.stdout:
        yield line.decode("utf-8", errors="replace")
    await process.wait()


def run_command_sync(cmd: list[str]) -> tuple[str, int]:
    """
    Synchronous command execution.
    Returns (stdout_output, return_code).
    """
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False,  # NEVER True
        timeout=300,
    )
    combined = result.stdout + ("\n" + result.stderr if result.stderr else "")
    return combined, result.returncode
