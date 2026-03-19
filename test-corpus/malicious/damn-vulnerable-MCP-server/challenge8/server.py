"""DVMCP Challenge 8: Malicious Code Execution
Arbitrary code and shell command execution without sandboxing.
"""
import subprocess
import os
import tempfile
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("DVMCP Challenge 8")

SENSITIVE_FILE = "/tmp/dvmcp_challenge8/sensitive/credentials.txt"
SENSITIVE_DATA = """
DATABASE_HOST=prod-db.internal
DATABASE_USER=db_admin
DATABASE_PASSWORD=Pr0d-DB-S3cur3!P@$$w0rd
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
API_GATEWAY_KEY=gw-key-prod-2025-secret
"""


@mcp.tool()
def execute_python_code(code: str) -> str:
    """Execute Python code for data analysis.

    VULNERABILITY: Runs arbitrary Python code without sandboxing.
    An attacker could execute any system command.
    """
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        result = subprocess.run(
            ['python3', temp_path],
            capture_output=True, text=True, timeout=30
        )
        os.unlink(temp_path)
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR: {result.stderr}"
        return output or "Code executed (no output)"
    except Exception as e:
        return f"Execution error: {str(e)}"


@mcp.tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command for system diagnostics.

    VULNERABILITY: Basic filtering easily bypassed.
    Blocks 'rm' and 'dd' but attacker can use '/bin/rm' or encoded commands.
    """
    blocked = ["rm", "dd"]
    for b in blocked:
        if b in command.split():
            return f"Blocked: '{b}' is not allowed."

    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def analyze_log_file(filepath: str) -> str:
    """Read and analyze a log file.

    VULNERABILITY: Accepts any file path without validation.
    Attacker can read /tmp/dvmcp_challenge8/sensitive/credentials.txt
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return f"Log analysis of {filepath}:\n{content}"
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    # Create sensitive file
    os.makedirs(os.path.dirname(SENSITIVE_FILE), exist_ok=True)
    with open(SENSITIVE_FILE, 'w') as f:
        f.write(SENSITIVE_DATA)
    uvicorn.run("server:mcp.app", host="localhost", port=8008, log_level="info")
