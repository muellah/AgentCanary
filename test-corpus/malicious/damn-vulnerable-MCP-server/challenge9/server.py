"""DVMCP Challenge 9: Remote Access Control - Command Injection
Network tools with unsanitized user input passed to shell commands.
"""
import subprocess
import os
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("DVMCP Challenge 9")


@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """Ping a host to check connectivity.

    VULNERABILITY: host parameter injected directly into shell command.
    Example exploit: ping_host("example.com; cat /etc/passwd")
    """
    command = f"ping -c {count} {host}"
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def traceroute(host: str) -> str:
    """Trace the route to a host.

    VULNERABILITY: No input validation on host parameter.
    """
    command = f"traceroute {host}"
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def port_scan(host: str, port: int) -> str:
    """Check if a port is open on a host.

    VULNERABILITY: host parameter not sanitized before shell interpolation.
    """
    command = f"nc -zv -w 2 {host} {port}"
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def network_diagnostic(target: str, options: str = "") -> str:
    """Run network diagnostic script.

    VULNERABILITY: Both target and options are directly interpolated.
    Example exploit: network_diagnostic("example.com", "; cat /etc/passwd #")
    """
    command = f"./network_diagnostic.sh {target} {options}"
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    os.makedirs("/tmp/dvmcp_challenge9/logs", exist_ok=True)
    uvicorn.run("server:mcp.app", host="localhost", port=8009, log_level="info")
