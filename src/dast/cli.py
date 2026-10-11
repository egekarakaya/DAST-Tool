import argparse
import json
import os
from pathlib import Path
from urllib.parse import urljoin
from .crawl import api_seeds
from .engine import scan
from .models import Role
from .policy import Policy
from .report import write_report


def load_roles(filename):
    if not filename:
        return [Role()]
    data = json.loads(Path(filename).read_text(encoding="utf-8"))
    entries = data.get("roles") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("Auth config needs a non-empty roles array")
    roles = []
    for entry in entries:
        name = entry["name"]
        if not isinstance(name, str) or not name or any(r.name == name for r in roles):
            raise ValueError("Role names must be unique non-empty strings")
        paths = tuple(entry.get("paths", ["/"]))
        if not paths or any(not isinstance(p, str) or not p.startswith("/") for p in paths):
            raise ValueError("Role paths must be absolute path prefixes")
        headers = {}
        for header, env in entry.get("headers_env", {}).items():
            value = os.environ.get(env)
            if not value:
                raise ValueError("Required authentication environment variable is missing")
            headers[header] = value
        roles.append(Role(name, headers, paths))
    return roles


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded passive web/API assessment")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("scan")
    run.add_argument("target")
    run.add_argument("--profile", choices=["production", "standard"], default="production")
    run.add_argument("--protocol", choices=["auto", "1.0", "1.1", "2"], default="auto")
    run.add_argument("--rps", type=float, default=1)
    run.add_argument("--max-requests", type=int, default=50)
    run.add_argument("--max-depth", type=int, default=3)
    run.add_argument("--max-seconds", type=float, default=120)
    run.add_argument("--max-body", type=int, default=262144)
    run.add_argument("--timeout", type=float, default=10)
    run.add_argument("--ca-file", help="Trusted PEM CA bundle; certificate verification stays enabled")
    run.add_argument("--auth-config")
    run.add_argument("--openapi", help="Local OpenAPI 3 JSON file")
    run.add_argument("--seed", action="append", default=[])
    run.add_argument("--no-crawl", action="store_true", help="Manual mode: assess only seeds and redirects")
    run.add_argument("--output", default="reports")
    run.add_argument("--fail-on", choices=["none", "info", "low", "medium", "high"], default="none")
    args = parser.parse_args(argv)
    try:
        policy = Policy(args.target, args.profile, args.rps, args.max_requests,
                        args.max_depth, args.max_body, args.timeout, args.max_seconds)
        roles = load_roles(args.auth_config)
        seeds = [args.target] + [urljoin(args.target, s) for s in args.seed]
        if args.openapi:
            document = json.loads(Path(args.openapi).read_text(encoding="utf-8"))
            seeds.extend(api_seeds(document, args.target))
        report = scan(policy, roles, seeds, not args.no_crawl, args.protocol, ca_file=args.ca_file)
        write_report(report, args.output)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Config/library error strings can include tokens; keep terminal output generic.
        parser.exit(2, f"Configuration/report error ({type(exc).__name__}); check inputs.\n")
    print(f"Requests: {report['requests']}; findings: {len(report['findings'])}; stop: {report['stop_reason']}")
    if report["errors"] or report["stop_reason"] in {
            "server-health-circuit-breaker", "error-circuit-breaker", "no-in-scope-seeds",
            "request-budget", "duration-budget"}:
        return 2
    ranks = {"info": 0, "low": 1, "medium": 2, "high": 3}
    if args.fail_on != "none" and any(
            ranks[f["severity"]] >= ranks[args.fail_on] for f in report["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
