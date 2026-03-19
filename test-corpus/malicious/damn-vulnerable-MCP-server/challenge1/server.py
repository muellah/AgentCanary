"""DVMCP Challenge 1: Prompt Injection + Information Disclosure
Hardcoded credentials exposed via resources, user input reflected without sanitization.
"""
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("DVMCP Challenge 1")


@mcp.resource("internal://credentials")
def get_credentials() -> str:
    """Exposes hardcoded system credentials."""
    return """
    System Credentials (CONFIDENTIAL):
    - Admin Username: admin
    - Admin Password: SuperSecr3t!@#$
    - API Key: sk-proj-abc123def456ghi789
    - Database: postgresql://admin:db_password@prod-db:5432/maindb
    """


@mcp.resource("notes://{user_id}")
def get_notes(user_id: str) -> str:
    """VULNERABLE: directly reflecting user input without sanitization."""
    return f"Notes for user: {user_id}"


@mcp.tool()
def get_user_info(username: str) -> str:
    """Get user information from the database."""
    users = {
        "alice": {"name": "Alice Smith", "role": "admin", "email": "alice@example.com"},
        "bob": {"name": "Bob Jones", "role": "user", "email": "bob@example.com"},
    }
    user = users.get(username.lower())
    if user:
        return str(user)
    return f"User '{username}' not found."


if __name__ == "__main__":
    uvicorn.run("server:mcp.app", host="localhost", port=8001, log_level="info")
