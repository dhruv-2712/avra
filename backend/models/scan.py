from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from enum import Enum
import uuid
from datetime import datetime


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CVEMatch(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cwe_ids: List[str] = []
    published: Optional[str] = None
    similarity: float  # cosine similarity 0-1 (higher = more similar)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    tool: str  # semgrep | bandit
    cwe: Optional[str] = None
    confidence: Optional[float] = None
    is_false_positive: bool = False
    llm_reasoning: Optional[str] = None
    attack_vector: Optional[str] = None
    file_context: Optional[str] = None
    is_reachable: Optional[bool] = None
    owasp_category: Optional[str] = None
    cve_matches: List[CVEMatch] = []


class Report(BaseModel):
    scan_id: str
    repo_url: str
    language: Optional[str]
    frameworks: List[str] = []
    executive_summary: str
    total_findings: int
    by_severity: Dict[str, int] = {}
    top_findings: List[Finding] = []
    generated_at: str


class AgentStep(BaseModel):
    agent: str
    status: str  # running | complete | error
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    data: Optional[Any] = None


class ScanState(BaseModel):
    """LangGraph state object passed between all agents."""
    scan_id: str
    repo_url: str
    local_path: Optional[str] = None
    language: Optional[str] = None
    frameworks: List[str] = []
    file_tree: List[str] = []
    entry_points: List[str] = []
    raw_findings: List[Finding] = []
    triaged_findings: List[Finding] = []
    findings_with_context: List[Finding] = []
    report: Optional[Report] = None
    report_markdown: Optional[str] = None
    steps: List[AgentStep] = []
    error: Optional[str] = None
    status: ScanStatus = ScanStatus.PENDING


class ScanRequest(BaseModel):
    repo_url: str


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    repo_url: str
    created_at: str


class ScanResult(BaseModel):
    scan_id: str
    status: ScanStatus
    repo_url: str
    language: Optional[str]
    findings: List[Finding] = []
    steps: List[AgentStep] = []
    report: Optional[Report] = None
    error: Optional[str] = None
