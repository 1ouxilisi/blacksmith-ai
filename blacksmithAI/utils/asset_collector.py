"""
Asset Collector - Batch target collection from FOFA/Quake/Shodan.
Supports querying asset search engines, probing liveness, and scoring targets.
"""
import os
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import requests


@dataclass
class Target:
    """A single target asset."""
    url: str
    ip: str = ""
    port: int = 0
    domain: str = ""
    title: str = ""
    server: str = ""
    tech_stack: List[str] = field(default_factory=list)
    source: str = ""  # fofa, quake, shodan
    score: float = 0.0
    alive: bool = False
    status_code: int = 0
    response_time_ms: int = 0
    notes: str = ""
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())


class FOFACollector:
    """FOFA asset search engine collector."""

    BASE_URL = "https://fofa.info/api/v1/search/all"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("FOFA_API_KEY", "")
        self.email = os.getenv("FOFA_EMAIL", "")

    def search(self, query: str, size: int = 100, fields: str = "host,ip,port,title,server,domain") -> List[Target]:
        """Search FOFA and return targets."""
        if not self.api_key:
            print("[FOFA] API key not configured, skipping")
            return []

        params = {
            "email": self.email,
            "key": self.api_key,
            "qbase64": query,
            "size": size,
            "fields": fields,
        }

        try:
            resp = requests.get(self.BASE_URL, params=params, timeout=30)
            data = resp.json()
            if data.get("error"):
                print(f"[FOFA] Error: {data.get('errmsg')}")
                return []

            targets = []
            for item in data.get("results", []):
                target = Target(
                    url=item[0] if len(item) > 0 else "",
                    ip=item[1] if len(item) > 1 else "",
                    port=int(item[2]) if len(item) > 2 and item[2] else 0,
                    title=item[3] if len(item) > 3 else "",
                    server=item[4] if len(item) > 4 else "",
                    domain=item[5] if len(item) > 5 else "",
                    source="fofa",
                )
                targets.append(target)
            return targets

        except Exception as e:
            print(f"[FOFA] Request failed: {e}")
            return []


class QuakeCollector:
    """360 Quake asset search engine collector."""

    BASE_URL = "https://quake.360.net/api/v3/search/quake_service"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("QUAKE_API_KEY", "")

    def search(self, query: str, size: int = 100) -> List[Target]:
        """Search Quake and return targets."""
        if not self.api_key:
            print("[Quake] API key not configured, skipping")
            return []

        headers = {"X-QuakeToken": self.api_key}
        payload = {
            "query": query,
            "size": size,
        }

        try:
            resp = requests.post(self.BASE_URL, json=payload, headers=headers, timeout=30)
            data = resp.json()
            if data.get("code") != 0:
                print(f"[Quake] Error: {data.get('message')}")
                return []

            targets = []
            for item in data.get("data", []):
                service = item.get("service", {})
                target = Target(
                    url=item.get("hostname", "") or f"{item.get('ip','')}:{item.get('port','')}",
                    ip=item.get("ip", ""),
                    port=item.get("port", 0),
                    title=service.get("http", {}).get("title", ""),
                    server=service.get("http", {}).get("server", ""),
                    source="quake",
                )
                targets.append(target)
            return targets

        except Exception as e:
            print(f"[Quake] Request failed: {e}")
            return []


class ShodanCollector:
    """Shodan asset search engine collector."""

    BASE_URL = "https://api.shodan.io/shodan/host/search"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY", "")

    def search(self, query: str, size: int = 100) -> List[Target]:
        """Search Shodan and return targets."""
        if not self.api_key:
            print("[Shodan] API key not configured, skipping")
            return []

        params = {
            "key": self.api_key,
            "query": query,
            "limit": size,
        }

        try:
            resp = requests.get(self.BASE_URL, params=params, timeout=30)
            data = resp.json()
            if "error" in data:
                print(f"[Shodan] Error: {data['error']}")
                return []

            targets = []
            for item in data.get("matches", []):
                target = Target(
                    url=f"{item.get('ip_str','')}:{item.get('port','')}",
                    ip=item.get("ip_str", ""),
                    port=item.get("port", 0),
                    title=item.get("http", {}).get("title", "") if isinstance(item.get("http"), dict) else "",
                    server=item.get("http", {}).get("server", "") if isinstance(item.get("http"), dict) else "",
                    source="shodan",
                )
                targets.append(target)
            return targets

        except Exception as e:
            print(f"[Shodan] Request failed: {e}")
            return []


class TargetScorer:
    """Score and prioritize targets based on vulnerability likelihood."""

    HIGH_VALUE_KEYWORDS = [
        "admin", "login", "manage", "system", "api", "test", "dev",
        "backup", "old", "demo", " staging", "internal", "vpn",
        "jenkins", "gitlab", "git", "jira", "confluence", "zabbix",
        "nacos", "druid", "swagger", "graphql",
    ]

    HIGH_RISK_SERVERS = [
        "apache", "nginx", "iis", "tomcat", "weblogic",
        "jboss", "websphere", "spring",
    ]

    @classmethod
    def score_target(cls, target: Target) -> float:
        """Calculate a vulnerability potential score (0-100)."""
        score = 0.0
        text = f"{target.title} {target.server} {target.url}".lower()

        # High value keywords
        for kw in cls.HIGH_VALUE_KEYWORDS:
            if kw in text:
                score += 10

        # High risk server software
        for srv in cls.HIGH_RISK_SERVERS:
            if srv in target.server.lower():
                score += 15

        # Non-standard ports (more likely to have misconfigs)
        if target.port not in [80, 443, 8080, 8443]:
            score += 5

        # Alive and responding
        if target.alive and target.status_code == 200:
            score += 20
        elif target.alive and target.status_code in [301, 302, 401, 403]:
            score += 10

        # HTTPS (modern stack, more surface)
        if "https" in target.url:
            score += 5

        return min(score, 100.0)


class AssetCollector:
    """Main asset collection orchestrator."""

    def __init__(self):
        self.collectors = {
            "fofa": FOFACollector(),
            "quake": QuakeCollector(),
            "shodan": ShodanCollector(),
        }
        self.targets: List[Target] = []

    def collect(self, source: str, query: str, size: int = 100) -> List[Target]:
        """Collect targets from a specific source."""
        collector = self.collectors.get(source)
        if not collector:
            print(f"Unknown source: {source}")
            return []

        print(f"[AssetCollector] Searching {source}: {query[:50]}...")
        targets = collector.search(query, size=size)
        print(f"[AssetCollector] Found {len(targets)} targets from {source}")

        # Score targets
        for t in targets:
            t.score = TargetScorer.score_target(t)

        # Deduplicate by URL
        seen = set()
        unique = []
        for t in targets:
            if t.url not in seen:
                seen.add(t.url)
                unique.append(t)

        self.targets.extend(unique)
        return unique

    def probe_alive(self, target: Target, timeout: int = 10) -> bool:
        """Check if target is alive."""
        try:
            start = time.time()
            resp = requests.get(
                target.url if target.url.startswith("http") else f"http://{target.url}",
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            target.alive = True
            target.status_code = resp.status_code
            target.response_time_ms = int((time.time() - start) * 1000)
            if not target.title:
                target.title = resp.text[:200] if resp.text else ""
            return True
        except Exception:
            target.alive = False
            return False

    def probe_all_alive(self) -> int:
        """Probe liveness for all collected targets."""
        alive_count = 0
        for t in self.targets:
            if self.probe_alive(t):
                alive_count += 1
        print(f"[AssetCollector] {alive_count}/{len(self.targets)} targets alive")
        return alive_count

    def get_top_targets(self, n: int = 10) -> List[Target]:
        """Get top N highest-scoring alive targets."""
        alive = [t for t in self.targets if t.alive]
        return sorted(alive, key=lambda x: x.score, reverse=True)[:n]

    def export_targets(self, output_path: str):
        """Export targets to JSON."""
        data = [
            {
                "url": t.url,
                "ip": t.ip,
                "port": t.port,
                "domain": t.domain,
                "title": t.title,
                "server": t.server,
                "source": t.source,
                "score": t.score,
                "alive": t.alive,
                "status_code": t.status_code,
            }
            for t in self.targets
        ]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# Global instance
asset_collector = AssetCollector()
