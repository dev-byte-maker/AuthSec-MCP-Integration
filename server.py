from authsec_sdk import (
    mcp_tool,
    protected_by_AuthSec,
    run_mcp_server_with_oauth,
    ServiceAccessSDK,
    CIBAClient
)
import os
import sys

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
    # FIX 1: JWT uses "email_id", fallback to "email" for compatibility
    email = user_info.get("email_id", user_info.get("email", "user"))

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
    # FIX 2: Removed roles=["admin", "security_admin"] since your JWT has no roles assigned.
    # Add roles back once you assign them in your AuthSec dashboard.
    resources=["users"],
    scopes=["write"],
    permissions=["users:write"],
    require_all=False,
)
async def manage_users(arguments: dict, session) -> list:
    user_info = arguments.get("_user_info") or {}
    # FIX 3: Use "email_id" consistent with JWT payload
    actor = user_info.get("email_id", user_info.get("email", "unknown"))

    return [
        {
            "type": "text",
            "text": f"authorized actor: {actor}",
        }
    ]


@mcp_tool(
    name="get_github_token_status",
    description="Tests whether this session can fetch a GitHub service token"
)
@protected_by_AuthSec(
    tool_name="get_github_token_status",
    scopes=["read"],
)
async def get_github_token_status(arguments: dict, session) -> list:
    user_info = arguments.get("_user_info") or {}
    # FIX 4: Use "email_id" consistent with JWT payload
    actor = user_info.get("email_id", user_info.get("email", "unknown"))

    services = ServiceAccessSDK(session)

    # FIX 5: Gracefully handle missing GitHub service token configuration
    try:
        token = await services.get_service_token("github")
        return [
            {
                "type": "text",
                "text": f"Service access works for {actor}. Got GitHub token with length {len(token)}."
            }
        ]
    except Exception as e:
        return [
            {
                "type": "text",
                "text": f"Could not retrieve GitHub token for {actor}. Error: {str(e)}"
            }
        ]

port = int(os.getenv("PORT", 3005))
if __name__ == "__main__":

    import __main__

    # FIX 6: Bind to 0.0.0.0 instead of 127.0.0.1 so the server is
    # accessible externally (e.g. from Claude's MCP connector).
    # Make sure your firewall/cloud allows traffic on port 3005.
    run_mcp_server_with_oauth(
        user_module=__main__,
        client_id=CLIENT_ID,
        app_name=APP_NAME,
        host="0.0.0.0",  # Changed from 127.0.0.1
        port=port,
    )