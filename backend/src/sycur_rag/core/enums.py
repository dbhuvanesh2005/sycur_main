from enum import Enum


class ReviewStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_APPLICABLE = "N/A"


class PolicyAction(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    ALLOW = "ALLOW"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class KnowledgeLayer(str, Enum):
    REQUIREMENTS = "requirements"
    TESTING = "testing"
    RISK_TAXONOMY = "risk_taxonomy"
    REMEDIATION = "remediation"
    API_SECURITY = "api_security"
    WEAKNESS_TAXONOMY = "weakness_taxonomy"
    STACK_GUIDANCE = "stack_guidance"