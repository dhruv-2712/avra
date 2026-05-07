#!/usr/bin/env python3
"""
NVD CVE Ingestion Script
────────────────────────
Fetches HIGH and CRITICAL CVEs from the NVD REST API 2.0 and indexes
them in ChromaDB for RAG-based finding enrichment.

Usage:
    # From repo root (ChromaDB must be running):
    python scripts/ingest_nvd.py

    # With NVD API key for higher rate limits (recommended):
    NVD_API_KEY=your_key python scripts/ingest_nvd.py

    # Limit to last N years (default: 3):
    python scripts/ingest_nvd.py --years 2

Environment:
    CHROMA_HOST   ChromaDB host  (default: localhost)
    CHROMA_PORT   ChromaDB port  (default: 8001)
    NVD_API_KEY   NVD API key    (optional — raises rate limit 5x)
"""
import argparse
import os
import sys
import time
from datetime import datetime, timedelta

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from core.rag import get_collection  # noqa: E402

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
SEVERITIES = ["HIGH", "CRITICAL"]
# NVD rate limits: 5 req/30s without key, 50 req/30s with key
RATE_DELAY_NO_KEY = 6.5   # seconds between requests
RATE_DELAY_WITH_KEY = 0.7
CHROMA_BATCH = 200        # upsert batch size


def _nvd_headers() -> dict:
    key = os.getenv("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _rate_delay() -> float:
    return RATE_DELAY_WITH_KEY if os.getenv("NVD_API_KEY") else RATE_DELAY_NO_KEY


def fetch_cves(severity: str, start_date: str, end_date: str) -> list[dict]:
    """Paginate through NVD API and return raw CVE dicts for one severity tier."""
    cves = []
    start_index = 0
    headers = _nvd_headers()
    delay = _rate_delay()

    with httpx.Client(timeout=30) as client:
        while True:
            params = {
                "cvssV3Severity": severity,
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            }
            try:
                resp = client.get(NVD_API_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                console.print(f"[red]NVD API error at startIndex={start_index}: {exc}[/red]")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            cves.extend(vulnerabilities)
            total = data.get("totalResults", 0)

            if start_index + PAGE_SIZE >= total:
                break
            start_index += PAGE_SIZE
            time.sleep(delay)

    return cves


def _parse_cve(vuln: dict) -> dict | None:
    """Extract fields we care about from a raw NVD vulnerability dict."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # English description
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    if not desc:
        return None

    # CVSS v3.1 → v3.0 fallback
    cvss_score, cvss_severity = None, None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metrics = cve.get("metrics", {}).get(key, [])
        if metrics:
            d = metrics[0].get("cvssData", {})
            cvss_score = d.get("baseScore")
            cvss_severity = d.get("baseSeverity")
            break

    # CWE IDs
    cwe_ids = []
    for w in cve.get("weaknesses", []):
        for wd in w.get("description", []):
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    published = cve.get("published", "")[:10]  # YYYY-MM-DD

    return {
        "id": cve_id,
        "document": f"{cve_id}: {desc}",
        "metadata": {
            "cvss_score": cvss_score or 0.0,
            "cvss_severity": cvss_severity or "",
            "cwe_ids": ",".join(cwe_ids),
            "published": published,
            "description": desc[:1000],  # cap for metadata storage
        },
    }


def upsert_to_chroma(collection, records: list[dict], progress, task) -> int:
    """Batch-upsert parsed CVE records into ChromaDB. Returns count upserted."""
    upserted = 0
    for i in range(0, len(records), CHROMA_BATCH):
        batch = records[i: i + CHROMA_BATCH]
        collection.upsert(
            ids=[r["id"] for r in batch],
            documents=[r["document"] for r in batch],
            metadatas=[r["metadata"] for r in batch],
        )
        upserted += len(batch)
        progress.advance(task, len(batch))
    return upserted


def main():
    parser = argparse.ArgumentParser(description="Ingest NVD CVEs into ChromaDB")
    parser.add_argument("--years", type=int, default=3, help="How many years back to fetch (default: 3)")
    args = parser.parse_args()

    end_dt = datetime.utcnow()
    start_dt = end_dt - timedelta(days=365 * args.years)
    start_date = start_dt.strftime("%Y-%m-%dT00:00:00.000")
    end_date = end_dt.strftime("%Y-%m-%dT23:59:59.999")

    using_key = bool(os.getenv("NVD_API_KEY"))
    console.print(f"\n[bold cyan]AVRA — NVD CVE Ingestion[/bold cyan]")
    console.print(f"Range  : {start_date[:10]} → {end_date[:10]}")
    console.print(f"API key: {'yes (higher rate limit)' if using_key else 'no (5 req/30s)'}\n")

    # Connect to ChromaDB
    try:
        collection = get_collection()
        existing = collection.count()
        console.print(f"[green]ChromaDB connected[/green] — {existing} existing CVEs in collection\n")
    except Exception as e:
        console.print(f"[red]Cannot connect to ChromaDB: {e}[/red]")
        console.print("Make sure ChromaDB is running: docker compose up chromadb")
        sys.exit(1)

    all_records: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        for severity in SEVERITIES:
            task = progress.add_task(f"Fetching {severity} CVEs from NVD...", total=None)
            raw = fetch_cves(severity, start_date, end_date)
            progress.update(task, completed=1, total=1)
            console.print(f"  {severity}: {len(raw)} raw records fetched")

            parsed = [r for v in raw if (r := _parse_cve(v))]
            all_records.extend(parsed)

        if not all_records:
            console.print("[yellow]No CVEs fetched — check your network or NVD API status.[/yellow]")
            sys.exit(0)

        console.print(f"\n[bold]Total parsed:[/bold] {len(all_records)} CVEs — upserting to ChromaDB...\n")
        upsert_task = progress.add_task("Upserting to ChromaDB...", total=len(all_records))
        count = upsert_to_chroma(collection, all_records, progress, upsert_task)

    final_count = collection.count()
    console.print(f"\n[bold green]Done![/bold green] Upserted {count} CVEs. "
                  f"Collection total: {final_count}")


if __name__ == "__main__":
    main()
