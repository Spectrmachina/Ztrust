"""Built-in scanners."""

from ztrust.scanners.base import ScanContext, Scanner
from ztrust.scanners.cicd import WorkflowScanner
from ztrust.scanners.integrity import IntegrityScanner
from ztrust.scanners.secrets import SecretsScanner
from ztrust.scanners.typosquat import TyposquatScanner
from ztrust.scanners.vulns import OSVScanner


def default_scanners() -> list[Scanner]:
    return [SecretsScanner(), TyposquatScanner(), IntegrityScanner(), WorkflowScanner(), OSVScanner()]


SCANNER_NAMES = [s.name for s in default_scanners()]

__all__ = [
    "SCANNER_NAMES",
    "IntegrityScanner",
    "OSVScanner",
    "ScanContext",
    "Scanner",
    "SecretsScanner",
    "TyposquatScanner",
    "WorkflowScanner",
    "default_scanners",
]
