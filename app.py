from typing import Any, Dict, List
import os
import base64
import logging
import sys
import re
import httpx
from datetime import datetime

from mcp.server.fastmcp import FastMCP, Context


# ----------------------
# Minimal Logging Setup
# ----------------------
def setup_logging():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.handlers = []
    logger.addHandler(handler)
    logger.propagate = False
    return logger

logger = setup_logging()


# ----------------------
# Basic JIRA API Config
# ----------------------
class JiraConfig:
    def __init__(self):
        self.domain = os.getenv("JIRA_DOMAIN") or "example"
        self.email = os.getenv("JIRA_EMAIL") or "your_email@example.com"
        self.api_token = os.getenv("JIRA_API_TOKEN") or "your_api_token"
        self.base_url = f"https://{self.domain}.atlassian.net/rest/api/3"


class HTTPError(Exception):
    """Custom HTTP error."""
    def __init__(self, message: str, status_code: int = None):
        self.status_code = status_code
        super().__init__(message)


# ----------------------
# Minimal JIRA API Class
# ----------------------
class JiraAPI:
    def __init__(self, config: JiraConfig):
        self.config = config
        auth_str = f"{config.email}:{config.api_token}".encode()
        self.auth = base64.b64encode(auth_str).decode()
        self.headers = {
            "Authorization": f"Basic {self.auth}",
            "Accept": "application/json"
        }

    async def make_request(self, method: str, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.request(method, url, params=params, headers=self.headers, timeout=30.0)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                # Attempt to parse error message
                message = f"HTTP {exc.response.status_code}"
                try:
                    j = exc.response.json()
                    if "errorMessages" in j:
                        message += ": " + j["errorMessages"][0]
                except:
                    pass
                raise HTTPError(message, exc.response.status_code)
            except httpx.TimeoutException:
                raise HTTPError("Request timed out.", None)
            except Exception as exc:
                raise HTTPError(f"Unexpected error: {str(exc)}", None)

    async def search(self, jql: str, max_results: int = 50, start_at: int = 0) -> Dict[str, Any]:
        params = {"jql": jql, "maxResults": max_results, "startAt": start_at}
        return await self.make_request("GET", "search", params)

    async def get_issue_with_comments(self, issue_key: str) -> Dict[str, Any]:
        issue_data = await self.make_request("GET", f"issue/{issue_key}") or {}
        comments_data = await self.make_request("GET", f"issue/{issue_key}/comment") or {}
        issue_data["comments"] = comments_data.get("comments", [])
        return issue_data


# ----------------------
# Utility Functions
# ----------------------
def format_date(date_str: str) -> str:
    if not date_str:
        return "Unknown"
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return date_str

def find_pr_links(text: str) -> List[str]:
    if not text:
        return []
    patterns = [
        r'https?://[^\s]+?/(?:pull|pull-requests)/\d+',
        r'https?://github\.com/[^/]+/[^/]+/pull/\d+',
        r'https?://bitbucket\.org/[^/]+/[^/]+/pull-requests/\d+',
        r'https?://gitlab\.com/[^/]+/[^/]+/-/merge_requests/\d+'
    ]
    links = []
    for pat in patterns:
        links.extend(re.findall(pat, text))
    return list(set(links))


# ------------------------------------------------------------
# Initialize MCP & Create Tools with Extra 'project_name' Context
# ------------------------------------------------------------
mcp = FastMCP("jira")

@mcp.tool()
async def execute_jql(
    query: str,
    ctx: Context,
    project_name: str = "LAN"
) -> Dict[str, Any]:
    """
    Execute a JQL query within a specific project context.

    Args:
      query (str): A JQL snippet like 'summary ~ NFR ORDER BY created DESC'
      project_name (str): The Jira project key (defaults to "LAN")

    Returns:
      dict: JSON serializable dict with 'message' and 'issues'
    """
    logger.info(f"Executing JQL with project={project_name} query={query}")
    try:
        config = JiraConfig()
        jira = JiraAPI(config)

        # Prepend "project = <project_name> AND ..." to the user query
        # if user query is nonempty. If user query is empty, we just do "project = <project_name>"
        if query.strip():
            full_jql = f'project = "{project_name}" AND {query}'
        else:
            full_jql = f'project = "{project_name}"'

        # Get total
        first_page = await jira.search(full_jql, max_results=1)
        total = first_page.get("total", 0)
        if total == 0:
            return {"message": "No issues found", "issues": []}

        # Paginate
        all_issues = []
        page_size = 50
        for start_idx in range(0, total, page_size):
            page_data = await jira.search(full_jql, max_results=page_size, start_at=start_idx)
            issues_page = page_data.get("issues", [])
            all_issues.extend(issues_page)
            await ctx.report_progress(len(all_issues), total)

        return {
            "message": f"Found {len(all_issues)} issues for project={project_name}",
            "issues": all_issues
        }
    except HTTPError as exc:
        return {"error": "HTTPError", "status_code": exc.status_code, "message": str(exc)}
    except Exception as exc:
        return {"error": "UnexpectedError", "message": str(exc)}


@mcp.tool()
async def get_ticket_details(
    ticket_key: str,
    ctx: Context,
    project_name: str = "LAN"
) -> Dict[str, Any]:
    """
    Get detailed info about a single ticket, with context for the project name.

    Args:
      ticket_key (str): The full ticket key, e.g., "LAN-123"
      project_name (str): Defaults to "LAN". Optional extra context in docstrings.

    Returns:
      dict: JSON with the ticket fields, comments, and PR links
    """
    logger.info(f"Fetching details for ticket={ticket_key} in project={project_name}")
    try:
        config = JiraConfig()
        jira = JiraAPI(config)
        raw_issue = await jira.get_issue_with_comments(ticket_key)

        # Flatten out fields
        fields = raw_issue.get("fields", {})
        summary = fields.get("summary", "No summary")
        status = fields.get("status", {}).get("name", "Unknown")
        description = fields.get("description", "")
        created = format_date(fields.get("created"))
        updated = format_date(fields.get("updated"))
        pr_links = find_pr_links(description)

        # Comments
        comments_json = []
        for c in raw_issue.get("comments", []):
            author = c.get("author", {}).get("displayName", "Unknown")
            body = c.get("body", "")
            comment_prs = find_pr_links(body)
            comments_json.append({
                "created": format_date(c.get("created")),
                "author": author,
                "body": body,
                "pull_request_links": comment_prs
            })

        return {
            "ticket_key": ticket_key,
            "project_name": project_name,
            "summary": summary,
            "status": status,
            "description": description,
            "description_pr_links": pr_links,
            "created": created,
            "updated": updated,
            "comments": comments_json,
            "url": f"https://{config.domain}.atlassian.net/browse/{ticket_key}"
        }
    except HTTPError as exc:
        return {"error": "HTTPError", "status_code": exc.status_code, "message": str(exc)}
    except Exception as exc:
        return {"error": "UnexpectedError", "message": str(exc)}


if __name__ == "__main__":
    mcp.run()