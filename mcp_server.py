from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
import os
import aiohttp
from dotenv import load_dotenv
from authsec_sdk import from_env, mount_mcp, ManifestTool

load_dotenv()

mcp = FastMCP("Mcp server")


@mcp.tool()
async def get_weather(city: str) -> str:
    """Get the current weather for any city."""
    async with aiohttp.ClientSession() as session:
        geo_url = (
            "https://geocoding-api.open-meteo.com/v1/search"
            f"?name={aiohttp.helpers.quote(city)}&count=1&language=en&format=json"
        )
        async with session.get(geo_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            geo = await r.json()

        results = geo.get("results")
        if not results:
            return f"Location not found: {city}"

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

    return (
        f"Weather in {location_name}\n"
        f"Condition:    {condition}\n"
        f"Temperature:  {cur.get('temperature_2m', 'N/A')}°C "
        f"(feels like {cur.get('apparent_temperature', 'N/A')}°C)\n"
        f"Humidity:     {cur.get('relative_humidity_2m', 'N/A')}%\n"
        f"Wind speed:   {cur.get('wind_speed_10m', 'N/A')} km/h\n"
        f"Precipitation:{cur.get('precipitation', 0)} mm"
    )


@mcp.tool()
async def search_wikipedia(query: str) -> str:
    """Search Wikipedia and return the summary of the best-matching article."""
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
                return f"{title}\n\n{extract}\n\nSource: {page_url}"

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
        return f"No Wikipedia results for: {query}"

    lines = [f"Wikipedia search results for '{query}':"]
    for h in hits:
        snippet = (
            h.get("snippet", "")
            .replace('<span class="searchmatch">', "")
            .replace("</span>", "")
        )
        lines.append(f"• {h['title']} — {snippet[:120]}")
    return "\n".join(lines)


@mcp.tool()
async def get_crypto_price(coin_id: str) -> str:
    """Get the live price, 24-hour change, and market cap of a cryptocurrency."""
    coin_id = coin_id.strip().lower()

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
        return (
            f"Coin '{coin_id}' not found. "
            "Common IDs: bitcoin, ethereum, solana, ripple, cardano, dogecoin."
        )

    c = data[coin_id]
    usd = c.get("usd", 0)
    eur = c.get("eur", 0)
    gbp = c.get("gbp", 0)
    change = c.get("usd_24h_change") or 0
    market_cap = c.get("usd_market_cap") or 0
    vol_24h = c.get("usd_24h_vol") or 0
    arrow = "▲" if change >= 0 else "▼"

    return (
        f"{coin_id.capitalize()} (live price)\n"
        f"USD:        ${usd:,.4f}\n"
        f"EUR:        €{eur:,.4f}\n"
        f"GBP:        £{gbp:,.4f}\n"
        f"24h Change: {arrow} {change:+.2f}%\n"
        f"Market Cap: ${market_cap:,.0f}\n"
        f"24h Volume: ${vol_24h:,.0f}"
    )


@mcp.tool()
async def list_github_repos(username: str, per_page: int = 10) -> str:
    """List public GitHub repositories for a user, sorted by most recently updated."""
    per_page = min(per_page, 30)

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
        f"?sort=updated&per_page={per_page}&type=public"
    )

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 404:
                return f"GitHub user '{username}' not found."
            if r.status == 403:
                return "GitHub API rate limit hit. Try again later."
            if r.status != 200:
                return f"GitHub API error {r.status}."
            repos = await r.json()

    if not repos:
        return f"No public repositories found for {username}."

    lines = [f"Public repositories for {username} (sorted by updated):"]
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
    return "\n".join(lines)


@mcp.tool()
async def create_github_issue(
    owner: str,
    repo: str,
    title: str,
    body: str = "",
    labels: list[str] | None = None,
) -> str:
    """Create a GitHub issue in a repository."""
    pat = os.getenv("UPSTREAM_API_TOKEN", "").strip()
    if not pat:
        return (
            "GitHub integration is not configured on this server. "
            "Set UPSTREAM_API_TOKEN to a GitHub personal access token with the 'repo' scope."
        )

    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AuthSecMCPServer/1.0",
    }
    payload: dict = {"title": title, "body": body}
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
                return (
                    f"Issue #{data['number']} created successfully.\n"
                    f"Title:  {data['title']}\n"
                    f"State:  {data['state']}\n"
                    f"URL:    {data['html_url']}"
                )
            error_msg = data.get("message", f"HTTP {r.status}")
            return f"Failed to create issue: {error_msg}"


def my_tools() -> list[ManifestTool]:
    return [
        ManifestTool(
            name="get_weather",
            description=(
                "Get the current weather for any city. "
                "Returns temperature, humidity, wind speed, and conditions."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "City name, e.g. 'London' or 'New York'"},
                },
                "required": ["city"],
            },
            suggested_scopes=["mcp_server:read"],
        ),
        ManifestTool(
            name="search_wikipedia",
            description="Search Wikipedia and return the summary of the best-matching article.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term or article title"},
                },
                "required": ["query"],
            },
            suggested_scopes=["mcp_server:read"],
        ),
        ManifestTool(
            name="get_crypto_price",
            description=(
                "Get the live price, 24-hour change, and market cap of a cryptocurrency. "
                "Use the CoinGecko coin ID (e.g. bitcoin, ethereum, solana)."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "coin_id": {
                        "type": "string",
                        "description": "CoinGecko coin ID (bitcoin, ethereum, solana, ripple, cardano, dogecoin, …)",
                    },
                },
                "required": ["coin_id"],
            },
            suggested_scopes=["mcp_server:tools:read"],
        ),
        ManifestTool(
            name="list_github_repos",
            description="List public GitHub repositories for a user, sorted by most recently updated.",
            input_schema={
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "GitHub username or organisation name"},
                    "per_page": {"type": "integer", "description": "Number of repos to return (max 30, default 10)"},
                },
                "required": ["username"],
            },
            suggested_scopes=["mcp_server:tools:read"],
        ),
        ManifestTool(
            name="create_github_issue",
            description=(
                "Create a GitHub issue in a repository. "
                "Requires UPSTREAM_API_TOKEN (GitHub PAT) on the server."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "Repository owner (user or organisation)"},
                    "repo": {"type": "string", "description": "Repository name"},
                    "title": {"type": "string", "description": "Issue title"},
                    "body": {"type": "string", "description": "Issue body (Markdown supported)"},
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Labels to apply (must already exist on the repo)",
                    },
                },
                "required": ["owner", "repo", "title"],
            },
            suggested_scopes=["mcp_server:write"],
        ),
    ]


cfg = from_env()
cfg.tool_inventory_provider = my_tools
cfg.publish_manifest = True

app = FastAPI()

mcp_app = mcp.streamable_http_app()

mount_mcp(app, "/mcp", mcp_app, cfg)

