import os

SEMGREP_TIMEOUT = int(os.getenv("SEMGREP_TIMEOUT", "60"))
BANDIT_TIMEOUT = int(os.getenv("BANDIT_TIMEOUT", "90"))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "600"))
MAX_REPO_MB = int(os.getenv("MAX_REPO_MB", "150"))
SEMGREP_MAX_MEMORY = int(os.getenv("SEMGREP_MAX_MEMORY", "512"))
SSE_GRACE_SECONDS = int(os.getenv("SSE_GRACE_SECONDS", "60"))
