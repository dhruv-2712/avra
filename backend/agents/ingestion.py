"""
Ingestion Agent
───────────────
Clones the target repo, detects language/framework,
maps file structure, identifies entry points + attack surface.
"""
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

import git
import httpx

from models.scan import ScanState, AgentStep, ScanStatus
from core.config import MAX_REPO_MB

# Language detection by extension
LANG_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript",
    ".tsx": "TypeScript",
    ".sol": "Solidity",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".c": "C",
    ".cpp": "C++",
}

# Framework signals
FRAMEWORK_SIGNALS = {
    "requirements.txt": ["Python"],
    "package.json": ["Node.js"],
    "go.mod": ["Go"],
    "Cargo.toml": ["Rust"],
    "pom.xml": ["Java/Maven"],
    "foundry.toml": ["Solidity/Foundry"],
    "hardhat.config.js": ["Solidity/Hardhat"],
    "hardhat.config.ts": ["Solidity/Hardhat"],
    "truffle-config.js": ["Solidity/Truffle"],
}

# High-value entry point patterns
ENTRY_POINT_PATTERNS = [
    "main.py", "app.py", "server.py", "wsgi.py", "asgi.py",
    "index.js", "index.ts", "server.js", "app.js",
    "main.go", "cmd/", "handler", "router", "route",
    "controller", "view", "endpoint", "api/",
]

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "coverage", ".pytest_cache",
}


def _check_repo_size(repo_url: str, max_mb: int = MAX_REPO_MB) -> None:
    """Raise ValueError if a GitHub repo exceeds max_mb. No-ops for non-GitHub URLs."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url)
    if not m:
        return
    owner, repo = m.group(1), m.group(2)
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(api_url, headers={"User-Agent": "avra-scanner"})
            resp.raise_for_status()
            data = resp.json()
        size_kb = data.get("size", 0)
        if size_kb > max_mb * 1024:
            raise ValueError(
                f"Repository is {size_kb // 1024} MB — exceeds the {max_mb} MB limit"
            )
    except ValueError:
        raise
    except Exception:
        pass  # network / rate-limit error — proceed without blocking


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=data,
    )


def clone_repository(repo_url: str, scan_id: str) -> str:
    """Clone repo to a temp directory. Returns local path."""
    clone_dir = os.path.join(tempfile.gettempdir(), f"avra_{scan_id}")
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"  # never open /dev/tty in Docker
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "credential.helper"
    env["GIT_CONFIG_VALUE_0"] = ""

    git.Repo.clone_from(
        repo_url,
        clone_dir,
        depth=1,
        single_branch=True,
        env=env,
    )
    return clone_dir


def detect_language(local_path: str, max_files: int = 2000) -> tuple[str, list[str]]:
    """Detect primary language and frameworks from file extensions and config files."""
    ext_counts: Counter = Counter()
    frameworks: list[str] = []
    root = Path(local_path)
    scanned = 0

    for file in root.rglob("*"):
        if not file.is_file():
            continue
        parts = set(file.parts)
        if parts.intersection(SKIP_DIRS):
            continue

        ext = file.suffix.lower()
        if ext in LANG_MAP:
            ext_counts[LANG_MAP[ext]] += 1

        if file.name in FRAMEWORK_SIGNALS:
            frameworks.extend(FRAMEWORK_SIGNALS[file.name])

        scanned += 1
        if scanned >= max_files:
            break

    if not ext_counts:
        return "Unknown", list(set(frameworks))

    # Prefer TypeScript over JavaScript when TS files are ≥30% of the JS+TS pool
    ts = ext_counts.get("TypeScript", 0)
    js = ext_counts.get("JavaScript", 0)
    if ts > 0 and js > 0 and ts / (ts + js) >= 0.3:
        ext_counts["TypeScript"] += js  # boost so it wins most_common

    primary_lang = ext_counts.most_common(1)[0][0]
    return primary_lang, list(set(frameworks))


def map_file_tree(local_path: str, max_files: int = 500) -> list[str]:
    """Build a relative file tree, skipping noise directories."""
    root = Path(local_path)
    files = []

    for file in root.rglob("*"):
        if file.is_file():
            parts = set(file.relative_to(root).parts)
            if not parts.intersection(SKIP_DIRS):
                files.append(str(file.relative_to(root)))
                if len(files) >= max_files:
                    break

    return sorted(files)


def identify_entry_points(file_tree: list[str]) -> list[str]:
    """Find likely attack surface entry points from the file tree."""
    entry_points = []
    for path in file_tree:
        path_lower = path.lower()
        for pattern in ENTRY_POINT_PATTERNS:
            if pattern in path_lower:
                entry_points.append(path)
                break
    return entry_points[:50]  # cap to most relevant


def ingestion_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: Ingestion Agent
    Input:  state with repo_url + scan_id
    Output: state with local_path, language, frameworks, file_tree, entry_points
    """
    agent_name = "Ingestion Agent"

    try:
        # Step 1: Size check (fast-fail before cloning)
        state.steps.append(_step(agent_name, "running", "Checking repository size..."))
        _check_repo_size(state.repo_url)

        # Step 2: Clone
        state.steps.append(_step(agent_name, "running", f"Cloning {state.repo_url}..."))
        local_path = clone_repository(state.repo_url, state.scan_id)
        state.local_path = local_path

        # Step 2: Language detection
        state.steps.append(_step(agent_name, "running", "Detecting language and frameworks..."))
        language, frameworks = detect_language(local_path)
        state.language = language
        state.frameworks = frameworks

        # Step 3: File tree
        state.steps.append(_step(agent_name, "running", "Mapping file structure..."))
        file_tree = map_file_tree(local_path)
        state.file_tree = file_tree

        # Step 4: Entry points
        entry_points = identify_entry_points(file_tree)
        state.entry_points = entry_points

        state.steps.append(_step(
            agent_name, "complete",
            f"Ingestion complete — {language} project, {len(file_tree)} files, "
            f"{len(entry_points)} entry points identified",
            data={
                "language": language,
                "frameworks": frameworks,
                "file_count": len(file_tree),
                "entry_points": entry_points[:10],
            }
        ))

    except Exception as e:
        state.error = str(e)
        state.status = ScanStatus.FAILED
        state.steps.append(_step(agent_name, "error", f"Ingestion failed: {e}"))

    return state
