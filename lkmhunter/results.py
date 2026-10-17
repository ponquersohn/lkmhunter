from dataclasses import asdict, dataclass, field
from enum import Enum


class ScanStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


@dataclass
class Finding:
    kind: str
    summary: str
    evidence: dict = field(default_factory=dict)
    suspicious: bool = True


@dataclass
class ScanResult:
    technique: str
    status: ScanStatus = ScanStatus.COMPLETE
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)

    @property
    def exit_code(self):
        if self.status != ScanStatus.COMPLETE:
            return 2
        return int(any(f.suspicious for f in self.findings))

    def to_dict(self):
        return asdict(self)
