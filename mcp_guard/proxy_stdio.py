import asyncio
import sys

TARGET_CMD = ["python3", "/workspaces/mcp_guard_project/mock_mcp_server.py"]
LOG_FILE = "/workspaces/mcp_guard_project/traffic_log.jsonl"

async def main():
    proc = await asyncio.create_subprocess_exec(
        *TARGET_CMD,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=sys.stderr
    )

    async def pipe_hermes_to_server():
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
        while True:
            line = await reader.readline()
            if not line:
                break
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[HERMES -> SERVER] {line.decode('utf-8')}")
            proc.stdin.write(line)
            await proc.stdin.drain()

    async def pipe_server_to_hermes():
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[SERVER -> HERMES] {line.decode('utf-8')}")
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    await asyncio.gather(pipe_hermes_to_server(), pipe_server_to_hermes())

if __name__ == "__main__":
    asyncio.run(main())
