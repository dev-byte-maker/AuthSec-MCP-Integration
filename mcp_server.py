from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any, Callable

import aiohttp
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from authsec_sdk import (
    Config,
    ManifestTool,
    PolicyMode,
    ValidationMode,
    from_env,
    mount_mcp,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as _JSONResponse

load_dotenv()

_CANONICAL_SCOPES: list[str] = [
    "mcp_server:read",
    "mcp_server:tools:read",
    "mcp_server:tools:write",
    "mcp_server:write",
]


@dataclass
class _ProtectedTool:
    tool_name: str
    scopes: list[str]
    description: str
    input_schema: dict
    handler: Callable[..., Any]


def protected_by_authsec(config: dict[str, Any], handler: Callable[..., Any]) -> _ProtectedTool:
    """
    Declare an AuthSec-protected MCP tool.

    Usage:
        protected_by_authsec(
            {
                "tool_name": "my_tool",
                "scopes": ["mcp_server:read"],
                "description": "Does something useful",
                "input_schema": {"type": "object", "properties": {...}},
            },
            my_async_handler,
        )
    """
    return _ProtectedTool(
        tool_name=config["tool_name"],
        scopes=config.get("scopes", []),
        description=config.get("description", ""),
        input_schema=config.get(
            "input_schema", {"type": "object", "properties": {}, "required": []}
        ),
        handler=handler,
    )


def run_mcp_server_with_oauth(
    tools: list[_ProtectedTool],
    *,
    client_id: str = "",
    app_name: str = "Mcp server",
    host: str = "0.0.0.0",
    port: int = 8080,
    issuer: str = "",
    resource: str = "",
) -> None:
    """
    Bootstrap an AuthSec-protected MCP server.

    Calls mount_mcp which automatically registers:
      GET  /.well-known/oauth-protected-resource/mcp  — RFC 9728 metadata
      POST /mcp                                        — bearer-protected endpoint

    Keyword arguments override their AUTHSEC_* env-var equivalents.
    """
    cfg: Config = from_env()

    if issuer:
        cfg.issuer = issuer
        if not cfg.authorization_server:
            cfg.authorization_server = issuer
    if resource:
        cfg.resource_uri = resource
    if not cfg.resource_name:
        cfg.resource_name = app_name

    resolved_id = (
        client_id.strip()
        or os.getenv("AUTHSEC_RESOURCE_SERVER_ID", "").strip()
        or cfg.resource_server_id.strip()
    )
    if resolved_id:
        if not cfg.resource_server_id:
            cfg.resource_server_id = resolved_id
        if not cfg.introspection_client_id:
            cfg.introspection_client_id = resolved_id

    if cfg.tool_scopes is None:
        cfg.tool_scopes = {t.tool_name: t.scopes for t in tools}
    if not cfg.supported_scopes:
        cfg.supported_scopes = _CANONICAL_SCOPES
    # REMOTE_WITH_LOCAL_FALLBACK: use AuthSec scope matrix when reachable,
    # fall back to tool_scopes dict when not — server never crashes on startup.
    cfg.policy_mode = PolicyMode.REMOTE_WITH_LOCAL_FALLBACK
    if cfg.validation_mode == ValidationMode.UNSET:
        cfg.validation_mode = ValidationMode.JWT_AND_INTROSPECT

    # Publish tool manifest to AuthSec on startup so the admin UI shows
    # all tools and their suggested scopes, and the scope matrix is populated.
    cfg.publish_manifest = True
    cfg.tool_inventory_provider = lambda: [
        ManifestTool(
            name=t.tool_name,
            description=t.description,
            input_schema=t.input_schema,
            suggested_scopes=t.scopes,
        )
        for t in tools
    ]

    tool_index: dict[str, _ProtectedTool] = {t.tool_name: t for t in tools}
    tool_schemas: list[dict] = [
        {
            "name": t.tool_name,
            "description": t.description,
            "inputSchema": t.input_schema,
        }
        for t in tools
    ]

    app = FastAPI(title=app_name)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # MCP `initialize` is a protocol handshake — it carries no user data and
    # must succeed *before* the client can start the OAuth flow.  Every other
    # method (tools/list, tools/call, …) still requires a valid bearer token.
    class _InitializePassthrough(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):  # type: ignore[override]
            if request.method == "POST" and request.url.path == "/mcp":
                body = await request.body()
                try:
                    msg = json.loads(body)
                except Exception:
                    msg = {}
                if msg.get("method") == "initialize":
                    return _JSONResponse({
                        "jsonrpc": "2.0",
                        "id": msg.get("id"),
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": app_name, "version": "1.0.0"},
                        },
                    })
            return await call_next(request)

    app.add_middleware(_InitializePassthrough)

    async def _mcp_handler(request: Request) -> dict:  # type: ignore[return]
        body = await request.body()
        try:
            msg = json.loads(body)
        except json.JSONDecodeError as exc:
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}

        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "tools/list":
            principal = getattr(request.state, "authsec_principal", None)
            granted = set(principal.scopes) if principal else set()
            visible = [
                schema
                for schema, tool in zip(tool_schemas, tools)
                if not tool.scopes or bool(granted & set(tool.scopes))
            ]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": visible}}

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = dict(params.get("arguments") or {})
            tool = tool_index.get(tool_name)
            if tool is None:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            principal = getattr(request.state, "authsec_principal", None)
            if principal:
                arguments["_principal"] = {
                    "subject": principal.subject,
                    "scopes": list(principal.scopes),
                    "claims": principal.claims,
                }

            try:
                content = await tool.handler(arguments)
            except Exception as exc:
                content = [{"type": "text", "text": json.dumps({"error": str(exc)})}]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"content": content}}

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    # _RouteProxy shares the routes list but lacks add_api_route so mount_mcp
    # uses plain Starlette Route (avoids FastAPI annotation-resolution bug).
    # It also lacks on_event, so we register the startup hook manually below.
    class _RouteProxy:
        def __init__(self, real: FastAPI) -> None:
            self.routes = real.routes

    rt = mount_mcp(_RouteProxy(app), "/mcp", _mcp_handler, cfg)

    # Manually register the startup hook that mount_mcp normally wires via
    # on_event.  Without this: scope matrix is never fetched from AuthSec and
    # the tool manifest is never published.
    # Non-fatal: if AuthSec is unreachable at boot the server still starts;
    # scope enforcement falls back to the local tool_scopes map.
    @app.on_event("startup")
    async def _authsec_startup() -> None:
        try:
            await rt.startup()
        except Exception as exc:
            print(f"[AuthSec] startup warning (non-fatal): {exc}")

    print(f"\n{'─'*55}")
    print(f"  {app_name}")
    print(f"{'─'*55}")
    print(f"  MCP endpoint : http://{host}:{port}/mcp")
    print(f"  Metadata     : http://{host}:{port}/.well-known/oauth-protected-resource/mcp")
    print(f"  Issuer       : {cfg.issuer}")
    print(f"  Resource URI : {cfg.resource_uri}")
    print(f"  Policy mode  : {cfg.policy_mode}")
    print(f"  Tools        : {[t.tool_name for t in tools]}")
    print(f"{'─'*55}\n")

    async def _serve() -> None:
        uv_cfg = uvicorn.Config(app, host=host, port=port, log_level="info")
        await uvicorn.Server(uv_cfg).serve()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        print("Server stopped.")



async def _get_weather(arguments: dict) -> list:
    city: str = (arguments.get("city") or "London").strip()

    async with aiohttp.ClientSession() as session:
        geo_url = (
            "https://geocoding-api.open-meteo.com/v1/search"
            f"?name={aiohttp.helpers.quote(city)}&count=1&language=en&format=json"
        )
        async with session.get(geo_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            geo = await r.json()

        results = geo.get("results")
        if not results:
            return [{"type": "text", "text": f"Location not found: {city}"}]

        loc = results[0]
        lat, lon = loc["latitude"], loc["longitude"]
        location_name = f"{loc['name']}, {loc.get('country', '')}"

        wx_url = (
            "https://api.open-meteo.com/v1/forecast"
            f"?latitude={lat}&longitude={lon}"
            "&current=temperature_2m,apparent_temperature,wind_speed_10m,"
            "relative_humidity_2m,weather_code,precipitation"
            "&temperature_unit=celsius&wind_speed_unit=kmh"
        )
        async with session.get(wx_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            wx = await r.json()

    cur = wx.get("current", {})
    wmo_desc = {
        0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
        45: "Foggy", 48: "Depositing rime fog",
        51: "Light drizzle", 53: "Moderate drizzle", 55: "Dense drizzle",
        61: "Slight rain", 63: "Moderate rain", 65: "Heavy rain",
        71: "Slight snow", 73: "Moderate snow", 75: "Heavy snow",
        80: "Slight showers", 81: "Moderate showers", 82: "Violent showers",
        95: "Thunderstorm", 96: "Thunderstorm with hail", 99: "Heavy thunderstorm",
    }
    condition = wmo_desc.get(cur.get("weather_code", -1), "Unknown")

    text = (
        f"Weather in {location_name}\n"
        f"Condition:    {condition}\n"
        f"Temperature:  {cur.get('temperature_2m', 'N/A')}°C "
        f"(feels like {cur.get('apparent_temperature', 'N/A')}°C)\n"
        f"Humidity:     {cur.get('relative_humidity_2m', 'N/A')}%\n"
        f"Wind speed:   {cur.get('wind_speed_10m', 'N/A')} km/h\n"
        f"Precipitation:{cur.get('precipitation', 0)} mm"
    )
    return [{"type": "text", "text": text}]



async def _search_wikipedia(arguments: dict) -> list:
    query: str = (arguments.get("query") or "").strip()
    if not query:
        return [{"type": "text", "text": "query is required"}]

    async with aiohttp.ClientSession() as session:
        summary_url = (
            "https://en.wikipedia.org/api/rest_v1/page/summary/"
            + aiohttp.helpers.quote(query.replace(" ", "_"))
        )
        async with session.get(
            summary_url,
            headers={"User-Agent": "AuthSecMCPServer/1.0"},
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            if r.status == 200:
                data = await r.json()
                title = data.get("title", "")
                extract = data.get("extract", "")[:600]
                page_url = data.get("content_urls", {}).get("desktop", {}).get("page", "")
                return [
                    {
                        "type": "text",
                        "text": f"{title}\n\n{extract}\n\nSource: {page_url}",
                    }
                ]

        # Fall back to full-text search
        search_url = (
            "https://en.wikipedia.org/w/api.php"
            f"?action=query&list=search&srsearch={aiohttp.helpers.quote(query)}"
            "&format=json&srlimit=5"
        )
        async with session.get(
            search_url,
            headers={"User-Agent": "AuthSecMCPServer/1.0"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            data = await r.json()

    hits = data.get("query", {}).get("search", [])
    if not hits:
        return [{"type": "text", "text": f"No Wikipedia results for: {query}"}]

    lines = [f"Wikipedia search results for '{query}':"]
    for h in hits:
        snippet = (
            h.get("snippet", "")
            .replace('<span class="searchmatch">', "")
            .replace("</span>", "")
        )
        lines.append(f"• {h['title']} — {snippet[:120]}")
    return [{"type": "text", "text": "\n".join(lines)}]



async def _get_crypto_price(arguments: dict) -> list:
    coin_id: str = (arguments.get("coin_id") or "bitcoin").strip().lower()

    async with aiohttp.ClientSession() as session:
        url = (
            "https://api.coingecko.com/api/v3/simple/price"
            f"?ids={aiohttp.helpers.quote(coin_id)}"
            "&vs_currencies=usd,eur,gbp"
            "&include_24hr_change=true"
            "&include_market_cap=true"
            "&include_24hr_vol=true"
        )
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            data = await r.json()

    if not data or coin_id not in data:
        return [
            {
                "type": "text",
                "text": (
                    f"Coin '{coin_id}' not found. "
                    "Common IDs: bitcoin, ethereum, solana, ripple, cardano, dogecoin."
                ),
            }
        ]

    c = data[coin_id]
    usd = c.get("usd", 0)
    eur = c.get("eur", 0)
    gbp = c.get("gbp", 0)
    change = c.get("usd_24h_change") or 0
    market_cap = c.get("usd_market_cap") or 0
    vol_24h = c.get("usd_24h_vol") or 0
    arrow = "▲" if change >= 0 else "▼"

    text = (
        f"{coin_id.capitalize()} (live price)\n"
        f"USD:        ${usd:,.4f}\n"
        f"EUR:        €{eur:,.4f}\n"
        f"GBP:        £{gbp:,.4f}\n"
        f"24h Change: {arrow} {change:+.2f}%\n"
        f"Market Cap: ${market_cap:,.0f}\n"
        f"24h Volume: ${vol_24h:,.0f}"
    )
    return [{"type": "text", "text": text}]



async def _list_github_repos(arguments: dict) -> list:
    username: str = (arguments.get("username") or "").strip()
    if not username:
        return [{"type": "text", "text": "username is required"}]

    sort = arguments.get("sort", "updated")          # updated | pushed | full_name
    per_page = min(int(arguments.get("per_page", 10)), 30)

    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AuthSecMCPServer/1.0",
    }
    pat = os.getenv("UPSTREAM_API_TOKEN", "").strip()
    if pat:
        headers["Authorization"] = f"Bearer {pat}"

    url = (
        f"https://api.github.com/users/{aiohttp.helpers.quote(username)}/repos"
        f"?sort={sort}&per_page={per_page}&type=public"
    )

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 404:
                return [{"type": "text", "text": f"GitHub user '{username}' not found."}]
            if r.status == 403:
                return [{"type": "text", "text": "GitHub API rate limit hit. Try again later."}]
            if r.status != 200:
                return [{"type": "text", "text": f"GitHub API error {r.status}."}]
            repos = await r.json()

    if not repos:
        return [{"type": "text", "text": f"No public repositories found for {username}."}]

    lines = [f"Public repositories for {username} (sorted by {sort}):"]
    for repo in repos:
        stars = repo.get("stargazers_count", 0)
        forks = repo.get("forks_count", 0)
        lang = repo.get("language") or "—"
        desc = (repo.get("description") or "No description")[:70]
        archived = " [archived]" if repo.get("archived") else ""
        lines.append(
            f"  {repo['name']}{archived}\n"
            f"    ⭐ {stars}  🍴 {forks}  [{lang}]\n"
            f"    {desc}"
        )
    return [{"type": "text", "text": "\n".join(lines)}]


async def _create_github_issue(arguments: dict) -> list:
    owner: str = (arguments.get("owner") or "").strip()
    repo: str = (arguments.get("repo") or "").strip()
    title: str = (arguments.get("title") or "").strip()
    body: str = (arguments.get("body") or "").strip()
    labels: list[str] = arguments.get("labels") or []

    missing = [f for f, v in [("owner", owner), ("repo", repo), ("title", title)] if not v]
    if missing:
        return [{"type": "text", "text": f"Missing required fields: {', '.join(missing)}"}]

    pat = os.getenv("UPSTREAM_API_TOKEN", "").strip()
    if not pat:
        return [
            {
                "type": "text",
                "text": (
                    "GitHub integration is not configured on this server. "
                    "Set UPSTREAM_API_TOKEN to a GitHub personal access token "
                    "with the 'repo' scope."
                ),
            }
        ]

    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AuthSecMCPServer/1.0",
    }
    payload: dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels

    url = (
        f"https://api.github.com/repos/"
        f"{aiohttp.helpers.quote(owner)}/{aiohttp.helpers.quote(repo)}/issues"
    )

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            data = await r.json()
            if r.status == 201:
                return [
                    {
                        "type": "text",
                        "text": (
                            f"Issue #{data['number']} created successfully.\n"
                            f"Title:  {data['title']}\n"
                            f"State:  {data['state']}\n"
                            f"URL:    {data['html_url']}"
                        ),
                    }
                ]
            error_msg = data.get("message", f"HTTP {r.status}")
            return [{"type": "text", "text": f"Failed to create issue: {error_msg}"}]



tools = [
    protected_by_authsec(
        {
            "tool_name": "get_weather",
            "scopes": ["mcp_server:read"],
            "description": (
                "Get the current weather for any city. "
                "Returns temperature, humidity, wind speed, and conditions."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name, e.g. 'London' or 'New York'",
                    }
                },
                "required": ["city"],
            },
        },
        _get_weather,
    ),
    protected_by_authsec(
        {
            "tool_name": "search_wikipedia",
            "scopes": ["mcp_server:read"],
            "description": (
                "Search Wikipedia and return the summary of the best-matching article."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term or article title",
                    }
                },
                "required": ["query"],
            },
        },
        _search_wikipedia,
    ),
    protected_by_authsec(
        {
            "tool_name": "get_crypto_price",
            "scopes": ["mcp_server:tools:read"],
            "description": (
                "Get the live price, 24-hour change, and market cap of a cryptocurrency. "
                "Use the CoinGecko coin ID (e.g. bitcoin, ethereum, solana)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "coin_id": {
                        "type": "string",
                        "description": (
                            "CoinGecko coin ID (bitcoin, ethereum, solana, ripple, "
                            "cardano, dogecoin, …)"
                        ),
                    }
                },
                "required": ["coin_id"],
            },
        },
        _get_crypto_price,
    ),
    protected_by_authsec(
        {
            "tool_name": "list_github_repos",
            "scopes": ["mcp_server:tools:read"],
            "description": (
                "List public GitHub repositories for a user, sorted by most recently updated."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "GitHub username or organisation name",
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Number of repos to return (max 30, default 10)",
                    },
                },
                "required": ["username"],
            },
        },
        _list_github_repos,
    ),
    protected_by_authsec(
        {
            "tool_name": "create_github_issue",
            "scopes": ["mcp_server:write"],
            "description": (
                "Create a GitHub issue in a repository. "
                "Requires UPSTREAM_API_TOKEN (GitHub PAT) on the server. "
                "The AuthSec token controls access; the PAT is never exposed to the caller."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "Repository owner (user or organisation)",
                    },
                    "repo": {
                        "type": "string",
                        "description": "Repository name",
                    },
                    "title": {
                        "type": "string",
                        "description": "Issue title",
                    },
                    "body": {
                        "type": "string",
                        "description": "Issue body (Markdown supported)",
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Labels to apply (must already exist on the repo)",
                    },
                },
                "required": ["owner", "repo", "title"],
            },
        },
        _create_github_issue,
    ),
]



if __name__ == "__main__":
    run_mcp_server_with_oauth(
        tools=tools,
        client_id=os.getenv("AUTHSEC_CLIENT_ID", ""),
        app_name="Mcp server",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8080)),
        issuer=os.getenv("AUTHSEC_ISSUER", "https://dev.api.authsec.dev"),
        resource=os.getenv(
            "AUTHSEC_RESOURCE_URI",
            "https://authsec-mcp-integration-production.up.railway.app/mcp",
        ),
    )
