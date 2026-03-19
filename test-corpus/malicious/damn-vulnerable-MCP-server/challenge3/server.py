"""DVMCP Challenge 3: Excessive Permission Scope
Tools grant access beyond their intended scope, exposing sensitive data.
"""
import os
from mcp.server.fastmcp import FastMCP
import uvicorn

mcp = FastMCP("DVMCP Challenge 3")

BASE_DIR = "/tmp/dvmcp_challenge3"
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
PRIVATE_DIR = os.path.join(BASE_DIR, "private")

# Simulated sensitive files
PRIVATE_FILES = {
    "salary_data.txt": """
Employee Salary Data (CONFIDENTIAL):
- CEO: $1,200,000/year
- VP Engineering: $350,000/year
- Senior Dev: $180,000/year
- Junior Dev: $80,000/year
""",
    "acquisition_plans.txt": """
ACQUISITION TARGET: TechStartup Inc.
Proposed price: $500M
Timeline: Q2 2025
Status: Board approved, pending regulatory
""",
    "system_credentials.txt": """
Production Database: postgresql://admin:Pr0d-P@ssw0rd!@db.internal:5432/prod
Cloud API Key: AKIAIOSFODNN7EXAMPLE
AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
}


@mcp.tool()
def read_file(filename: str) -> str:
    """Read a file from the public directory.

    VULNERABILITY: This tool doesn't properly restrict file access to the public directory.
    It allows reading files from any path, including the private directory.
    """
    # No path validation - accepts any path
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return f"File not found: {filename}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


@mcp.tool()
def search_files(keyword: str) -> str:
    """Search for files containing a keyword in the public directory.

    VULNERABILITY: Searches both public AND private directories despite
    documentation claiming public-only scope.
    """
    results = []
    # Searches private dir too - vulnerability
    for search_dir in [PUBLIC_DIR, PRIVATE_DIR]:
        if os.path.exists(search_dir):
            for filename in os.listdir(search_dir):
                filepath = os.path.join(search_dir, filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read()
                        if keyword.lower() in content.lower():
                            results.append(f"Found in {filepath}: {content[:200]}...")
                    except:
                        pass
    return "\n".join(results) if results else "No matches found."


if __name__ == "__main__":
    uvicorn.run("server:mcp.app", host="localhost", port=8003, log_level="info")
