from authsec_sdk import (
    mcp_tool,
    protected_by_AuthSec,
    run_mcp_server_with_oauth,
)
import os

from dotenv import load_dotenv

load_dotenv()

APP_NAME = "Aman Secure MCP Server"
CLIENT_ID = os.getenv("AUTHSEC_CLIENT_ID", "").strip()


@mcp_tool(
    name="hello",
    description="Greets the authenticated user"
)
@protected_by_AuthSec("hello")
async def hello(arguments: dict) -> list:
    user_info = arguments.get("_user_info", {})
    email = user_info.get("email", "user")

    return [
        {
            "type": "text",
            "text": f"Hello, {email}! Your AuthSec-protected MCP server is working."
        }
    ]


@mcp_tool(
    name="manage_users",
    description="Manages users"
)
@protected_by_AuthSec(
    tool_name="manage_users",
    roles=["admin", "security_admin"],
    resources=["users"],
    scopes=["write"],
    permissions=["users:write"],
    require_all=False,
)
async def manage_users(arguments: dict, session) -> list:
    user_info = arguments.get("_user_info") or {}
    actor = user_info.get("email_id", "unknown")

    return [
        {
            "type": "text",
            "text": f"authorized actor: {actor}",
        }
    ]






    

if __name__ == "__main__":
    import __main__

    if not CLIENT_ID:
        raise SystemExit(
            "AUTHSEC_CLIENT_ID is missing. Set it in .env (see AUTHSEC_CLIENT_ID) "
            "or export it in your shell before running server.py."
        )

    run_mcp_server_with_oauth(
        user_module=__main__,
        client_id=CLIENT_ID,
        app_name=APP_NAME,
        host="127.0.0.1",
        port=3005,
    )