from authsec_sdk import (
    mcp_tool,
    protected_by_AuthSec,
    run_mcp_server_with_oauth,
)
import os

APP_NAME = "Aman Secure MCP Server"
CLIENT_ID = os.getenv("AUTHSEC_CLIENT_ID")


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


if __name__ == "__main__":
    import __main__
    run_mcp_server_with_oauth(
        user_module=__main__,
        client_id=CLIENT_ID,
        app_name=APP_NAME,
        host="127.0.0.1",
        port=3005,
    )