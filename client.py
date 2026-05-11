import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_SERVER_URL = "http://localhost:3005"

async def call_and_print(session, tool_name, arguments):
    print(f"\nCalling tool: {tool_name}")
    print(f"Arguments: {arguments}")

    result = await session.call_tool(tool_name, arguments)

    if hasattr(result, "content"):
        for item in result.content:
            if getattr(item, "type", None) == "text":
                print(item.text)
            else:
                print(item)
    else:
        print(result)

async def main():
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }

    async with streamablehttp_client(
        MCP_SERVER_URL,
        headers=headers
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("Connected to MCP server successfully.")

            tools_response = await session.list_tools()
            print("\nAvailable Tools:")
            for tool in tools_response.tools:
                print(f"- {tool.name}: {tool.description}")

            #await call_and_print(session, "oauth_status", {})
            await call_and_print(session, "oauth_start", {})
            #await call_and_print(session, "oauth_user_info", {})

if __name__ == "__main__":
    asyncio.run(main())