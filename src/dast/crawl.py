from html.parser import HTMLParser
from urllib.parse import urljoin


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


class HTMLPlanner:
    def propose(self, observation) -> list[str]:
        if "text/html" not in observation.headers.get("content-type", "").lower():
            return []
        parser = Links()
        parser.feed(observation.body)
        # Ignore base tags so content cannot change origin interpretation.
        return [urljoin(observation.url, link) for link in parser.links]


def api_seeds(document: dict, target: str) -> list[str]:
    """Local OpenAPI JSON, GET operations only. Never follow servers/$ref."""
    if not isinstance(document, dict) or not str(document.get("openapi", "")).startswith("3."):
        raise ValueError("Expected an OpenAPI 3 JSON object")
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")
    result = []
    for route, operations in paths.items():
        if (isinstance(route, str) and route.startswith("/") and
                not route.startswith("//") and "{" not in route and
                isinstance(operations, dict) and "get" in operations):
            result.append(urljoin(target, route))
    return result
