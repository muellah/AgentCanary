"""DVMCP Challenge 7: Token Theft via Error Messages
Tokens leaked through error messages, status responses, and log output.
"""
import json
import os
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("DVMCP Challenge 7")

TOKENS_FILE = "/tmp/dvmcp_challenge7/tokens.json"
TOKENS = {
    "emailpro": {
        "api_key": "ep-key-2025-abc123def456",
        "access_token": "eyJhbGciOiJIUzI1NiJ9.emailpro.secret",
        "refresh_token": "rt-emailpro-2025-refresh-xyz"
    },
    "cloudbox": {
        "api_key": "cb-key-2025-ghi789jkl012",
        "access_token": "eyJhbGciOiJIUzI1NiJ9.cloudbox.secret",
        "refresh_token": "rt-cloudbox-2025-refresh-abc"
    },
    "datametrics": {
        "api_key": "dm-key-2025-mno345pqr678",
        "access_token": "eyJhbGciOiJIUzI1NiJ9.datametrics.secret",
        "refresh_token": "rt-datametrics-2025-refresh-def"
    }
}


@mcp.tool()
def check_email(folder: str = "inbox") -> str:
    """Check email in a specified folder.

    VULNERABILITY: Error messages leak token information.
    """
    valid_folders = ["inbox", "sent", "drafts"]
    if folder not in valid_folders:
        email_token = TOKENS["emailpro"]
        return (f"Error: Invalid folder '{folder}'. "
                f"Auth failed with Bearer {email_token['access_token']}. "
                f"API Key: {email_token['api_key']}")
    return f"Email folder '{folder}': 5 unread messages"


@mcp.tool()
def check_service_status(service: str) -> str:
    """Check integration service status.

    VULNERABILITY: Returns complete token details in status responses.
    """
    service_info = TOKENS.get(service.lower())
    if service_info:
        return (f"Service '{service}' status: Active\n"
                f"API Key: {service_info['api_key']}\n"
                f"Token: {service_info['access_token']}\n"
                f"Expires: 2025-12-31")
    return f"Unknown service: {service}"


@mcp.tool()
def view_system_logs(log_type: str = "info") -> str:
    """View system logs.

    VULNERABILITY: Error logs contain full token details.
    """
    email_token = TOKENS["emailpro"]
    if log_type == "error":
        return (f"[ERROR] Authentication retry failed\n"
                f"Token details: Bearer {email_token['access_token']}\n"
                f"Refresh token: {email_token['refresh_token']}\n"
                f"Service API key: {email_token['api_key']}")
    return f"[INFO] System running normally. No issues detected."


if __name__ == "__main__":
    os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
    with open(TOKENS_FILE, 'w') as f:
        json.dump(TOKENS, f)
    uvicorn.run("server:mcp.app", host="localhost", port=8007, log_level="info")
