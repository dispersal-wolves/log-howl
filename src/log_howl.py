"""Watch local logs and emit restrained, configurable alerts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]


class Suppressor:
    def __init__(self, window: float):
        self.window = window
        self.seen: dict[str, float] = {}

    def permits(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        previous = self.seen.get(key)
        if previous is not None and now - previous < self.window:
            return False
        self.seen[key] = now
        return True


def load_config(path: Path) -> tuple[list[Path], list[Rule], str | None, float]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    files = [Path(item) for item in raw.get("files", [])]
    if not files:
        raise ValueError("config must contain at least one log file")
    rules = []
    for item in raw.get("rules", []):
        rules.append(Rule(item["name"], item.get("severity", "notice"), re.compile(item["pattern"], re.IGNORECASE)))
    if not rules:
        raise ValueError("config must contain at least one rule")
    return files, rules, raw.get("webhook"), float(raw.get("suppress_seconds", 60))


def redact_line(line: str) -> str:
    line = re.sub(r"(?i)(password|token|secret|authorization)\s*[=:]\s*\S+", r"\1=[REDACTED]", line)
    return line[:2048]


def match_line(path: Path, line: str, rules: list[Rule]) -> list[dict[str, str]]:
    events = []
    for rule in rules:
        if rule.pattern.search(line):
            events.append({
                "schema": "dispersal-wolves/log-howl-event/v1",
                "time": datetime.now(timezone.utc).isoformat(),
                "rule": rule.name,
                "severity": rule.severity,
                "source": path.name,
                "message": redact_line(line.strip()),
            })
    return events


def deliver(event: dict[str, str], webhook: str | None, allow_http: bool) -> None:
    print(json.dumps(event), flush=True)
    if not webhook:
        return
    if not webhook.startswith("https://") and not (allow_http and webhook.startswith("http://")):
        raise ValueError("webhook must use HTTPS unless --allow-http is set")
    request = urllib.request.Request(webhook, data=json.dumps(event).encode(), headers={"Content-Type": "application/json", "User-Agent": "dispersal-log-howl/0.1"}, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status >= 400:
            raise RuntimeError(f"webhook returned HTTP {response.status}")


def scan_file(path: Path, rules: list[Rule], suppressor: Suppressor, webhook: str | None, allow_http: bool) -> int:
    emitted = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            for event in match_line(path, line, rules):
                key = f"{event['rule']}:{event['message']}"
                if suppressor.permits(key):
                    deliver(event, webhook, allow_http)
                    emitted += 1
    return emitted


def command_scan(args: argparse.Namespace) -> int:
    try:
        files, rules, webhook, window = load_config(args.config)
        suppressor = Suppressor(window)
        count = sum(scan_file(path, rules, suppressor, webhook, args.allow_http) for path in files)
        print(json.dumps({"summary": {"alerts": count}}))
        return 1 if args.strict and count else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Log Howl: {exc}", file=sys.stderr)
        return 2


def command_watch(args: argparse.Namespace) -> int:
    try:
        files, rules, webhook, window = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Log Howl: {exc}", file=sys.stderr)
        return 2
    suppressor = Suppressor(window)
    positions = {path: path.stat().st_size if path.exists() else 0 for path in files}
    print(f"Watching {len(files)} log file(s); press Ctrl+C to stop.")
    try:
        while True:
            for path in files:
                if not path.exists():
                    positions[path] = 0
                    continue
                size = path.stat().st_size
                if size < positions[path]:  # rotation or truncation
                    positions[path] = 0
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(positions[path])
                    for line in handle:
                        for event in match_line(path, line, rules):
                            if suppressor.permits(f"{event['rule']}:{event['message']}"):
                                try:
                                    deliver(event, webhook, args.allow_http)
                                except Exception as exc:
                                    print(f"Delivery failed: {exc}", file=sys.stderr)
                    positions[path] = handle.tell()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func in (("scan", command_scan), ("watch", command_watch)):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--allow-http", action="store_true")
        if name == "scan":
            command.add_argument("--strict", action="store_true")
        else:
            command.add_argument("--interval", type=float, default=1.0)
        command.set_defaults(func=func)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
