from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # High | Medium | Low | Info
    owasp: str  # key into owasp.OWASP_TOP10 (2021 numbering)
    cwe: str
    description: str
    recommendation: str
    evidence: str = ""
    urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class FindingStore:
    """Collects findings and merges identical ones seen on several URLs."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], Finding] = {}

    def add(self, finding: Finding, url: str) -> None:
        key = (finding.id, finding.evidence)
        existing = self._items.get(key)
        if existing is None:
            finding.urls = [url]
            self._items[key] = finding
        elif url not in existing.urls:
            existing.urls.append(url)

    def all(self) -> list[Finding]:
        return list(self._items.values())
