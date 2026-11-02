from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
EVIDENCE_DIR = DATASET / "evidence"
OUTPUT_FILE = ROOT / "output.csv"

OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]

# Operation order is part of the challenge contract.
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

# The resource category determines the treatment. These mappings are
# conservative defaults; deletion_rules.csv is loaded and used below.
CATEGORY_HINTS = {
    "USER_PROFILE": ("DELETE", "account_service"),
    "SECONDARY_IDENTIFIER": ("DELETE", "identity_service"),
    "SEARCH_INDEX_ENTRY": ("DELETE", "search_service"),
    "CACHE_ENTRY": ("DELETE", "cache_service"),
    "SUPPORT_MESSAGE": ("REDACT", "support_platform"),
    "SUPPORT_ATTACHMENT": ("DELETE", "support_platform"),
    "ANALYTICS_PROFILE": ("ANONYMIZE", "analytics_platform"),
    "PRODUCT_TELEMETRY": ("ANONYMIZE", "analytics_platform"),
    "USER_EXPORT": ("DELETE", "export_service"),
    "MARKETING_PROFILE": ("DELETE", "marketing_service"),
    "EMAIL_DELIVERY_LOG": ("REDACT", "notification_service"),
    "SECURITY_AUDIT_LOG": ("RETAIN", "security_service"),
    "LEGAL_HOLD_RECORD": ("RETAIN", "legal_service"),
    "BACKUP_ARCHIVE": ("RETAIN", "backup_service"),
    "ACCOUNT_TOMBSTONE": ("REDACT", "account_service"),
}

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")

RESOURCE_RE = re.compile(
    r"\b(?:account|search|support|export|analytics|telemetry|backup|"
    r"audit_record|data_flow|cache|marketing|delivery_log|attachment|"
    r"tombstone|profile|user_export|legal_hold)[_-]"
    r"\d+[A-Za-z0-9_-]*\b",
    re.IGNORECASE,
)

USER_ID_RE = re.compile(r"\buser[_-]\d+\b", re.IGNORECASE)


def log(message: str) -> None:
    print(f"[deletion-audit] {message}", flush=True)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    value = str(value).strip()
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def norm(value: Any) -> str:
    return str(value or "").strip().casefold()


def digits(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def flatten_values(obj: Any) -> list[str]:
    result: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            result.append(str(key))
            result.extend(flatten_values(value))
    elif isinstance(obj, list):
        for value in obj:
            result.extend(flatten_values(value))
    elif obj is not None:
        result.append(str(obj))
    return result


def flatten_text(obj: Any) -> str:
    return " ".join(flatten_values(obj))



def contains_identifier(
    text: str,
    identifiers: set[str],
    phone_digits: set[str],
) -> bool:
    normalized_text = norm(text)

    for identifier in identifiers:
        candidate = norm(identifier).strip()
        if len(candidate) < 4:
            continue

        # Require identifier boundaries. For example, user_43 must not
        # match user_430, user_431, or user_437.
        pattern = (
            r"(?<![a-z0-9])"
            + re.escape(candidate)
            + r"(?![a-z0-9])"
        )
        if re.search(pattern, normalized_text, flags=re.IGNORECASE):
            return True

    # Keep phone matching separate from ordinary identifiers.
    # Only match sufficiently long digit sequences with boundaries,
    # rather than searching the concatenation of every digit in the text.
    for phone in phone_digits:
        candidate_digits = digits(phone)
        if len(candidate_digits) < 8:
            continue

        pattern = (
            r"(?<!\d)"
            + re.escape(candidate_digits)
            + r"(?!\d)"
        )
        text_digits_with_boundaries = str(text)
        if re.search(pattern, text_digits_with_boundaries):
            return True

    return False



def parse_json_records(obj: Any) -> list[dict[str, Any]]:
    """Return nested objects that look like individual data records."""
    records: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            keys = {norm(k) for k in value.keys()}
            if (
                "resource_id" in keys
                or "record_id" in keys
                or "customer_reference" in keys
                or "subject_reference" in keys
            ):
                records.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(obj)
    return records


def infer_system(record: dict[str, Any], path: str = "") -> str:
    for key in (
        "system_id", "data_store", "origin_system", "source_system",
        "service", "system", "target_system",
    ):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            value = value.strip().casefold()
            mapping = {
                "account": "account_service",
                "account_service": "account_service",
                "identity": "identity_service",
                "search": "search_service",
                "search_service": "search_service",
                "support": "support_platform",
                "support_platform": "support_platform",
                "analytics": "analytics_platform",
                "analytics_platform": "analytics_platform",
                "backup": "backup_service",
                "backup_service": "backup_service",
                "security": "security_service",
                "security_service": "security_service",
                "integration": "integration_service",
                "export": "export_service",
                "export_service": "export_service",
                "marketing": "marketing_service",
                "cache": "cache_service",
                "notification": "notification_service",
                "legal": "legal_service",
            }
            if value in mapping:
                return mapping[value]
            if value.endswith("_service") or value.endswith("_platform"):
                return value

    category = infer_category(record, path)
    if category in CATEGORY_HINTS:
        return CATEGORY_HINTS[category][1]

    combined = (path + " " + flatten_text(record)).casefold()
    for term, system in (
        ("account", "account_service"),
        ("search", "search_service"),
        ("support", "support_platform"),
        ("analytics", "analytics_platform"),
        ("telemetry", "analytics_platform"),
        ("backup", "backup_service"),
        ("audit_record", "security_service"),
        ("security", "security_service"),
        ("data_flow", "integration_service"),
        ("integration", "integration_service"),
        ("export", "export_service"),
        ("marketing", "marketing_service"),
        ("cache", "cache_service"),
        ("delivery", "notification_service"),
        ("legal", "legal_service"),
    ):
        if term in combined:
            return system
    return "unknown_service"


def infer_category(record: dict[str, Any], path: str = "") -> str:
    fields = " ".join(
        str(record.get(k, "")) for k in (
            "data_category", "category", "collection_name", "collection",
            "record_type", "resource_type", "table",
        )
    )
    combined = (fields + " " + path + " " + str(record.get("resource_id", ""))).casefold()

    aliases = [
        ("ACCOUNT_TOMBSTONE", ("tombstone",)),
        ("SECURITY_AUDIT_LOG", ("security_audit", "audit_record", "audit_log")),
        ("LEGAL_HOLD_RECORD", ("legal_hold",)),
        ("BACKUP_ARCHIVE", ("backup_archive", "backup_", "archive")),
        ("SUPPORT_ATTACHMENT", ("support_attachment", "attachment")),
        ("SUPPORT_MESSAGE", ("support_message", "support_conversation", "support_ticket")),
        ("SEARCH_INDEX_ENTRY", ("search_index", "search_document", "search_")),
        ("CACHE_ENTRY", ("cache_entry", "cache_")),
        ("ANALYTICS_PROFILE", ("analytics_profile", "customer_analytics", "analytics_")),
        ("PRODUCT_TELEMETRY", ("product_telemetry", "telemetry")),
        ("USER_EXPORT", ("user_export", "export_")),
        ("MARKETING_PROFILE", ("marketing_profile", "marketing_")),
        ("EMAIL_DELIVERY_LOG", ("email_delivery", "delivery_log", "notification_log")),
        ("SECONDARY_IDENTIFIER", ("secondary_identifier", "identity_record")),
        ("USER_PROFILE", ("customer_profiles", "user_profile", "account_")),
    ]
    for category, hints in aliases:
        if any(hint in combined for hint in hints):
            return category
    return ""


def record_state(record: dict[str, Any], raw_text: str = "") -> str:
    """Infer observed record state from explicit record fields and context."""
    fields = {norm(k): norm(v) for k, v in record.items() if not isinstance(v, (dict, list))}
    combined = (flatten_text(record) + " " + raw_text).casefold()

    # Explicit per-record state fields take precedence over general prose.
    for key in (
        "record_state", "account_status", "status", "state", "result",
        "operation_result", "deletion_state", "restore_state", "pii_state",
    ):
        value = fields.get(key, "")
        if value in {"not_found", "not found", "absent", "deleted", "missing", "404"}:
            return "ABSENT"
        if value in {"redacted", "redact"}:
            return "REDACTED"
        if value in {"anonymized", "anonymised"}:
            return "ANONYMIZED"
        if value in {"blocked", "restore_blocked"}:
            return "BLOCKED"
        if value in {"disabled", "inactive", "stopped"}:
            return "DISABLED"
        if value in {"active", "enabled", "running"}:
            return "ACTIVE"
        if value in {"found", "present", "identifiable", "success", "successfully_deleted"}:
            if value == "successfully_deleted":
                return "ABSENT"
            return "PRESENT"

    # Do not interpret a generic SUCCESS activity as proof of deletion.
    if re.search(r"\b(not_found|not found|no rows|rows=0|http_status=404)\b", combined):
        return "ABSENT"
    if re.search(r"\b(redacted|pii_removed|identifiers_removed)\b", combined):
        return "REDACTED"
    if re.search(r"\b(anonymized|anonymised|deidentified|de-identified)\b", combined):
        return "ANONYMIZED"
    if re.search(r"\b(restore_blocked|blocked_restore|restore_access_blocked)\b", combined):
        return "BLOCKED"
    if re.search(r"\b(disabled|inactive|paused|stopped)\b", combined):
        return "DISABLED"
    if re.search(r"\b(active|enabled|running)\b", combined):
        return "ACTIVE"
    if re.search(r"\b(identifiable|found|present|result=hit|rows=[1-9]\d*)\b", combined):
        return "PRESENT"
    return "UNKNOWN"


def record_resource(record: dict[str, Any], text: str = "") -> str:
    for key in ("resource_id", "record_id", "id", "resource", "record_key"):
        value = record.get(key)
        if isinstance(value, (str, int)) and RESOURCE_RE.search(str(value)):
            return str(value)
    match = RESOURCE_RE.search(flatten_text(record) + " " + text)
    return match.group(0) if match else ""


def record_user_ids(record: dict[str, Any], text: str = "") -> set[str]:
    found = set()
    for match in USER_ID_RE.findall(flatten_text(record) + " " + text):
        found.add(norm(match))
    return found


def infer_flow_kind(resource_id: str, category: str, state: str) -> str:
    combined = f"{resource_id} {category}".casefold()
    if "backup" in combined or "restore" in combined or "archive" in combined:
        return "RESTORE"
    if "flow" in combined or "sync" in combined or "import" in combined:
        return "FLOW"
    return ""


def load_evidence_manifest() -> list[dict[str, str]]:
    path = DATASET / "evidence_files.csv"
    rows = read_csv(path)
    result = []
    for row in rows:
        rel = row.get("file_path", "").replace("\\", "/")
        result.append({
            **row,
            "_full_path": str((DATASET / rel).resolve()),
        })
    return result


def load_evidence_records() -> list[dict[str, Any]]:
    """
    Read all participant-visible evidence into record-like observations.
    JSON and SQL are parsed structurally. Logs/text are processed line-wise.
    PDF and image OCR are optional and are not required for this script to run.
    """
    observations: list[dict[str, Any]] = []
    manifest = load_evidence_manifest()

    for item in manifest:
        path = Path(item["_full_path"])
        file_id = item.get("file_id", "")
        captured_at = parse_time(item.get("captured_at"))
        if not path.exists():
            continue

        suffix = path.suffix.casefold()
        try:
            if suffix == ".json":
                raw = path.read_text(encoding="utf-8", errors="replace")
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                for record in parse_json_records(obj):
                    observations.append({
                        "file_id": file_id,
                        "captured_at": captured_at,
                        "path": str(path),
                        "record": record,
                        "raw": flatten_text(record),
                        "resource_id": record_resource(record),
                        "system_id": infer_system(record, str(path)),
                        "category": infer_category(record, str(path)),
                        "state": record_state(record),
                        "user_ids": record_user_ids(record),
                        "kind": "record",
                    })

            elif suffix == ".sql":
                conn = sqlite3.connect(":memory:")
                try:
                    conn.executescript(path.read_text(encoding="utf-8", errors="replace"))
                    tables = [
                        row[0] for row in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        )
                    ]
                    for table in tables:
                        # Table names originate from the SQL snapshot, not user input.
                        quoted = '"' + table.replace('"', '""') + '"'
                        try:
                            cursor = conn.execute(f"SELECT * FROM {quoted}")
                            columns = [c[0] for c in cursor.description or []]
                            for values in cursor.fetchall():
                                record = dict(zip(columns, values))
                                # Parse JSON-encoded payload columns.
                                for key, value in list(record.items()):
                                    if isinstance(value, str) and value[:1] in ("{", "["):
                                        try:
                                            record[key] = json.loads(value)
                                        except json.JSONDecodeError:
                                            pass
                                observations.append({
                                    "file_id": file_id,
                                    "captured_at": captured_at,
                                    "path": str(path),
                                    "record": record,
                                    "raw": flatten_text(record),
                                    "resource_id": record_resource(record),
                                    "system_id": infer_system(record, str(path)),
                                    "category": infer_category(record, str(path) + " " + table),
                                    "state": record_state(record),
                                    "user_ids": record_user_ids(record),
                                    "kind": "record",
                                })
                        except sqlite3.DatabaseError:
                            continue
                except sqlite3.DatabaseError:
                    # Fallback to scanning SQL text if a snapshot cannot be executed.
                    raw = path.read_text(encoding="utf-8", errors="replace")
                    observations.extend(parse_text_observations(raw, file_id, captured_at, str(path)))
                finally:
                    conn.close()

            elif suffix in {".log", ".txt", ".csv"}:
                raw = path.read_text(encoding="utf-8", errors="replace")
                observations.extend(parse_text_observations(raw, file_id, captured_at, str(path)))

            elif suffix == ".pdf":
                # Optional PDF text extraction. If pypdf is installed, use it.
                try:
                    from pypdf import PdfReader  # type: ignore
                    reader = PdfReader(str(path))
                    raw = "\n".join(page.extract_text() or "" for page in reader.pages)
                    observations.extend(parse_text_observations(raw, file_id, captured_at, str(path)))
                except Exception:
                    pass

            elif suffix in {".png", ".jpg", ".jpeg"}:
                # Optional OCR. Install pytesseract + Pillow + local Tesseract to enable.
                try:
                    from PIL import Image  # type: ignore
                    import pytesseract  # type: ignore
                    raw = pytesseract.image_to_string(Image.open(path))
                    observations.extend(parse_text_observations(raw, file_id, captured_at, str(path)))
                except Exception:
                    pass

        except (OSError, UnicodeError, sqlite3.DatabaseError) as exc:
            log(f"Skipping unreadable evidence {file_id}: {exc}")

    return observations



def parse_text_observations(
    raw: str,
    file_id: str,
    captured_at: datetime | None,
    path: str,
) -> list[dict[str, Any]]:
    observations = []

    resource_key_re = re.compile(
        r"\b(?:resource_id|record_id|resource|record_key|resource_key)"
        r"\s*[=:]\s*[\"']?([A-Za-z][A-Za-z0-9_-]*)",
        re.IGNORECASE,
    )
    service_re = re.compile(
        r"\b(?:service|system|data_store|source_system|origin_system)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9_-]+)",
        re.IGNORECASE,
    )

    resource_systems = {
        "account": "account_service",
        "search": "search_service",
        "support": "support_platform",
        "export": "export_service",
        "analytics": "analytics_platform",
        "telemetry": "analytics_platform",
        "backup": "backup_service",
        "audit_record": "security_service",
        "data_flow": "integration_service",
        "cache": "cache_service",
        "marketing": "marketing_service",
        "delivery_log": "notification_service",
        "attachment": "support_platform",
        "tombstone": "account_service",
        "profile": "account_service",
        "user_export": "export_service",
        "legal_hold": "legal_service",
    }

    resource_categories = {
        "account": "USER_PROFILE",
        "search": "SEARCH_INDEX_ENTRY",
        "support": "SUPPORT_MESSAGE",
        "export": "USER_EXPORT",
        "analytics": "ANALYTICS_PROFILE",
        "telemetry": "PRODUCT_TELEMETRY",
        "backup": "BACKUP_ARCHIVE",
        "audit_record": "SECURITY_AUDIT_LOG",
        "data_flow": "DATA_FLOW",
        "cache": "CACHE_ENTRY",
        "marketing": "MARKETING_PROFILE",
        "delivery_log": "EMAIL_DELIVERY_LOG",
        "attachment": "SUPPORT_ATTACHMENT",
        "tombstone": "ACCOUNT_TOMBSTONE",
        "profile": "USER_PROFILE",
        "user_export": "USER_EXPORT",
        "legal_hold": "LEGAL_HOLD_RECORD",
    }

    def prefix_of(resource_id: str) -> str:
        match = re.match(
            r"^(" + "|".join(
                sorted(resource_systems, key=len, reverse=True)
            ) + r")[_-]",
            resource_id,
            re.IGNORECASE,
        )
        return match.group(1).casefold() if match else ""

    def normalize_service(value: str) -> str:
        value = value.strip().casefold()
        mapping = {
            "account": "account_service",
            "identity": "identity_service",
            "search": "search_service",
            "support": "support_platform",
            "analytics": "analytics_platform",
            "backup": "backup_service",
            "security": "security_service",
            "integration": "integration_service",
            "export": "export_service",
            "marketing": "marketing_service",
            "cache": "cache_service",
            "notification": "notification_service",
            "legal": "legal_service",
        }
        return mapping.get(value, value)

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # Prefer an explicitly labeled resource field.
        explicit_resource = resource_key_re.search(line)
        resource_id = ""

        if explicit_resource:
            candidate = explicit_resource.group(1).rstrip(",;")
            if RESOURCE_RE.fullmatch(candidate):
                resource_id = candidate

        # Fall back only to a token matching the resource-ID pattern.
        if not resource_id:
            resource_match = RESOURCE_RE.search(line)
            if resource_match:
                resource_id = resource_match.group(0)

        if not resource_id:
            continue

        prefix = prefix_of(resource_id)

        # Infer from the resource first, not from arbitrary words in the line.
        category = resource_categories.get(prefix, "")
        system_id = resource_systems.get(prefix, "unknown_service")

        # Explicit service metadata takes precedence for system attribution.
        service_match = service_re.search(line)
        if service_match:
            explicit_system = normalize_service(service_match.group(1))
            if (
                explicit_system.endswith("_service")
                or explicit_system.endswith("_platform")
            ):
                system_id = explicit_system

        state = record_state({}, line)

        observations.append({
            "file_id": file_id,
            "captured_at": captured_at,
            "path": path,
            "record": {},
            "raw": line,
            "resource_id": resource_id,
            "system_id": system_id,
            "category": category,
            "state": state,
            "user_ids": record_user_ids({}, line),
            "kind": "line",
        })

    return observations



def load_identity_index() -> tuple[dict[str, dict[str, set[str]]], dict[str, set[str]]]:
    """
    Build user_id -> identifiers, and identifier -> user_ids, including
    historical email/name/phone/hash values from user_audit_log.csv.
    """
    identities: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"emails": set(), "phones": set(), "names": set(), "hashes": set()}
    )
    reverse: dict[str, set[str]] = defaultdict(set)

    for row in read_csv(DATASET / "user_identities.csv"):
        user_id = norm(row.get("user_id"))
        if not user_id:
            continue
        for field, bucket in (
            ("email", "emails"), ("phone", "phones"),
            ("name", "names"), ("email_hash", "hashes"),
        ):
            value = norm(row.get(field))
            if value:
                identities[user_id][bucket].add(value)
                reverse[value].add(user_id)

    audit_rows = read_csv(DATASET / "user_audit_log.csv")
    for row in audit_rows:
        user_id = norm(row.get("user_id"))
        field = norm(row.get("field_name"))
        if not user_id:
            continue
        for value_field in ("old_value", "new_value"):
            value = norm(row.get(value_field))
            if not value:
                continue
            if field == "email":
                identities[user_id]["emails"].add(value)
                reverse[value].add(user_id)
            elif field in {"phone", "telephone", "mobile"}:
                identities[user_id]["phones"].add(value)
                reverse[value].add(user_id)
            elif field in {"name", "full_name"}:
                identities[user_id]["names"].add(value)
                reverse[value].add(user_id)
            elif field in {"email_hash", "email_sha256"}:
                identities[user_id]["hashes"].add(value)
                reverse[value].add(user_id)

    # Include the user ID itself in the identifier set.
    for user_id in identities:
        reverse[user_id].add(user_id)

    return identities, reverse


def resolve_subject(
    request_email: str,
    identities: dict[str, dict[str, set[str]]],
    reverse: dict[str, set[str]],
) -> tuple[set[str], set[str], set[str], set[str]]:
    email = norm(request_email)
    user_ids = set(reverse.get(email, set()))
    identifiers = {email} if email else set()
    phones: set[str] = set()
    hashes: set[str] = set()

    for user_id in list(user_ids):
        identifiers.add(user_id)
        item = identities.get(user_id, {})
        identifiers.update(item.get("emails", set()))
        identifiers.update(item.get("names", set()))
        identifiers.update(item.get("hashes", set()))
        phones.update(item.get("phones", set()))
        hashes.update(item.get("hashes", set()))

    # If no mapping exists, the supplied email is still a valid identifier.
    if not user_ids and email:
        identifiers.add(email)

    return user_ids, identifiers, phones, hashes



def request_authorizes_deletion(request_text: str) -> bool:
    text = norm(request_text)

    # Requests that must not be interpreted as deletion authorization.
    non_delete_patterns = [
        r"\b(access|export|download|copy)\b.{0,45}\b(my data|personal data|information|records)\b",
        r"\b(correct|correction|rectify|update|change)\b.{0,45}\b(email|name|phone|address|data|record)\b",
        r"\b(opt[\s-]?out|unsubscribe|stop marketing|marketing opt out)\b",
        r"\bdelete\s+my\s+marketing\s+emails?\b",
        r"\bno longer want promotional emails\b",
        r"\bconsulta de acceso\b",
        r"\bsolicitud de acceso\b",
        r"\brectificar\b|\bcorregir\b",
    ]
    if any(re.search(p, text, re.I) for p in non_delete_patterns):
        return False

    # Explicit negation or withdrawal takes precedence.
    negative_patterns = [
        r"\bdo not delete\b",
        r"\bdon't delete\b",
        r"\bnot asking for deletion\b",
        r"\bno deletion request\b",
        r"\bwithdraw(?:ing)? (?:my )?deletion request\b",
        r"\bkeep my account\b",
        r"\bretain my account\b",
    ]
    if any(re.search(p, text, re.I) for p in negative_patterns):
        return False

    # Direct deletion, erasure, and account/profile closure.
    deletion_patterns = [
        r"\bdelete(?:d|ing|ion)?\b",
        r"\berase(?:d|s|ing|r)?\b",
        r"\berasure\b",
        r"\bremove(?:d|s|ing)?\b.{0,60}\b(?:my|the)\s+(?:data|account|profile|personal details)\b",
        r"\b(?:my|the)\s+(?:data|account|profile)\b.{0,60}\b(?:delete|erase|remove|close|purge)\w*\b",
        r"\b(?:close|closed|closing)\b.{0,100}\b(?:account|profile)\b",
        r"\b(?:account|profile)\b.{0,100}\b(?:close|closed|delete|deleted|remove|removed|erase|erased)\b",
        r"\bwould like it closed\b",
        r"\bpermanent(?:ly)?\s+(?:delete|erase|remove)\b",
        r"\bpermanent account\b",
        r"\bright to be forgotten\b",
        r"\bwipe my data\b",
        r"\bpurge my\b",
        r"\bdestroy my data\b",

        # French
        r"\bsuppression\b",
        r"\bsupprimer\b",
        r"\beffacer\b",

        # German
        r"\blöschen\b",
        r"\blöschung\b",
        r"\bentfernen\b",
        r"\bkonto schließen\b",

        # Spanish and Portuguese
        r"\beliminar\b",
        r"\beliminación\b",
        r"\bborrar\b",
        r"\bsupresión\b",
        r"\bexcluir\b",
        r"\bcancelar minha conta\b",

        # Italian and Dutch
        r"\bcancellare\b",
        r"\bcancellazione\b",
        r"\brimuovere i miei dati\b",
        r"\bverwijderen\b",
        r"\bgegevens wissen\b",

        # Polish and other scripts
        r"\busuń moje dane\b",
        r"\busunięcie\b",
        r"удалить",
        r"удаление",
        r"削除",
        r"删除",
        r"刪除",
        r"永久删除",
        r"계정 삭제",
    ]
    if any(re.search(p, text, re.I) for p in deletion_patterns):
        return True

    # Requests to audit or verify a deletion that has already occurred.
    audit_patterns = [
        r"\bverify\b.{0,100}\b(?:profile|account|data)\b.{0,80}\b(?:gone|deleted|removed|erased)\b",
        r"\bconfirm(?:ation)?\b.{0,100}\b(?:account|profile|data)\b.{0,80}\b(?:removed|deleted|erased|gone)\b",
        r"\baudit\b.{0,100}\bdeletion\b",
        r"\baccount\b.{0,100}\bfully removed\b",
    ]
    if any(re.search(p, text, re.I) for p in audit_patterns):
        return True

    return False



def load_rules() -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in read_csv(DATASET / "deletion_rules.csv"):
        category = norm(row.get("data_category")).upper()
        result[category].append({
            "condition": row.get("condition", ""),
            "required_action": row.get("required_action", "DELETE").upper(),
            "rule_id": row.get("rule_id", ""),
        })
    return result


def policy_action(category: str, record: dict[str, Any], rules: dict[str, list[dict[str, str]]]) -> str:
    category = category.upper()
    text = flatten_text(record).casefold()

    # Conditions requiring a specific policy decision.
    if category == "SECURITY_AUDIT_LOG":
        return "RETAIN"
    if category == "LEGAL_HOLD_RECORD":
        if re.search(r"\b(active|true|held|in force)\b", text):
            return "RETAIN"
        return "DELETE"
    if category == "BACKUP_ARCHIVE":
        return "RETAIN"  # preserve the archive, block unsafe restore access
    if category == "ACCOUNT_TOMBSTONE":
        return "REDACT"
    if category == "SUPPORT_MESSAGE":
        return "REDACT"

    entries = rules.get(category, [])
    if entries:
        for entry in entries:
            condition = norm(entry["condition"])
            if not condition or condition == "always":
                return entry["required_action"]
        return entries[0]["required_action"]

    if category in CATEGORY_HINTS:
        return CATEGORY_HINTS[category][0]
    return "DELETE"


def operation_for_finding(action: str, state: str) -> tuple[str, str]:
    if action == "REDACT":
        return "REPORT_EXPOSED_PII", "PRESENT"
    if action == "ANONYMIZE":
        return "REPORT_EXPOSED_PII", "PRESENT"
    if action == "FLOW":
        return "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
    if action == "RESTORE":
        return "REPORT_RESTORE_RISK", "ACTIVE"
    return "REPORT_REMAINING_RECORD", "PRESENT"


def remediation_for_action(action: str) -> tuple[str, str, str]:
    if action == "REDACT":
        return "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"
    if action == "ANONYMIZE":
        return "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"
    if action == "RETAIN":
        return "VERIFY_RECORD_PRESENT", "PRESENT", "VERIFY_RECORD_PRESENT"
    return "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT"


def step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id or "unknown_service",
        "resource_id": resource_id or "unknown_resource",
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id or "",
    }


def step_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        PHASE_ORDER.get(item["phase"], 99),
        OP_ORDER.get(item["operation"], 99),
        item["system_id"],
        item["resource_id"],
    )


def normalize_observation_state(observation: dict[str, Any]) -> str:
    state = str(observation.get("state", "UNKNOWN")).upper()
    raw = norm(observation.get("raw", ""))
    category = str(observation.get("category", "")).upper()

    if state != "UNKNOWN":
        return state

    # Category-specific hints when evidence does not carry a clean status field.
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return "PRESENT"
    if category == "BACKUP_ARCHIVE" and re.search(r"\b(active|enabled|restorable)\b", raw):
        return "ACTIVE"
    if re.search(r"\b(result=hit|identifiable|found|present|matched_value=)\b", raw):
        return "PRESENT"
    return "UNKNOWN"


def observation_matches_subject(
    observation: dict[str, Any],
    identifiers: set[str],
    phone_digits: set[str],
    user_ids: set[str],
) -> bool:
    raw = str(observation.get("raw", ""))
    if contains_identifier(raw, identifiers, phone_digits):
        return True
    obs_users = observation.get("user_ids", set())
    if obs_users.intersection(user_ids):
        return True
    record = observation.get("record", {})
    if isinstance(record, dict):
        return bool(record_user_ids(record).intersection(user_ids))
    return False


def observation_is_in_scope(
    observation: dict[str, Any],
    audit_at: datetime | None,
) -> bool:
    captured_at = observation.get("captured_at")
    if audit_at and captured_at and captured_at > audit_at:
        return False
    return True


def make_candidate(
    observation: dict[str, Any],
    action: str,
    state: str,
) -> dict[str, Any] | None:
    resource_id = observation.get("resource_id", "")
    system_id = observation.get("system_id", "")
    category = observation.get("category", "")
    if not resource_id:
        return None

    flow_kind = infer_flow_kind(resource_id, category, state)
    if flow_kind:
        operation, finding_state = operation_for_finding(flow_kind, state)
        return {
            "resource_id": resource_id,
            "system_id": system_id or "integration_service",
            "category": category,
            "action": flow_kind,
            "state": finding_state,
            "finding_operation": operation,
            "evidence_id": observation.get("file_id", ""),
            "source_state": state,
            "record": observation.get("record", {}),
        }

    if state in {"ABSENT", "NOT_FOUND", "DELETED", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}:
        return {
            "resource_id": resource_id,
            "system_id": system_id,
            "category": category,
            "action": action,
            "state": state,
            "finding_operation": "",
            "evidence_id": observation.get("file_id", ""),
            "source_state": state,
            "record": observation.get("record", {}),
        }

    operation, finding_state = operation_for_finding(action, state)
    return {
        "resource_id": resource_id,
        "system_id": system_id,
        "category": category,
        "action": action,
        "state": finding_state if state in {"PRESENT", "ACTIVE"} else state,
        "finding_operation": operation if state in {"PRESENT", "ACTIVE"} else "",
        "evidence_id": observation.get("file_id", ""),
        "source_state": state,
        "record": observation.get("record", {}),
    }


def best_observation_by_resource(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Collapse duplicate references to the same resource. Prefer the latest
    evidence capture; break ties deterministically. Evidence may disagree, so
    later observations supersede earlier snapshots for that resource.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        grouped[(candidate["system_id"], candidate["resource_id"])].append(candidate)

    result = []
    for key, items in grouped.items():
        # Input observations are already restricted to <= audit_at. The file
        # capture time is attached separately by caller if needed; evidence_id
        # is a stable tie-breaker here.
        items.sort(key=lambda x: (x.get("_captured_at") or "", x.get("evidence_id", "")))
        result.append(items[-1])
    return result


def infer_account_verification(
    email: str,
    user_ids: set[str],
    observations: list[dict[str, Any]],
    audit_at: datetime | None,
) -> list[dict[str, Any]]:
    """
    Read explicit account-service NOT_FOUND checks for the subject.
    This gives a resource-specific verification when the account profile is
    absent and avoids inventing a random account ID.
    """
    results = []
    for obs in observations:
        if not observation_is_in_scope(obs, audit_at):
            continue
        if obs.get("system_id") != "account_service":
            continue
        raw = str(obs.get("raw", ""))
        if not re.search(r"\b(not_found|not found|rows=0|http_status=404)\b", raw, re.I):
            continue
        if email and email.casefold() not in raw.casefold():
            continue
        resource = obs.get("resource_id", "")
        if resource:
            results.append({
                "resource_id": resource,
                "system_id": "account_service",
                "category": "USER_PROFILE",
                "action": "DELETE",
                "state": "ABSENT",
                "finding_operation": "",
                "evidence_id": obs.get("file_id", ""),
                "source_state": "ABSENT",
                "record": {},
            })
    return results


def process_request(
    request: dict[str, str],
    identities: dict[str, dict[str, set[str]]],
    reverse: dict[str, set[str]],
    observations: list[dict[str, Any]],
    rules: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    case_id = request.get("case_id", "")
    email = norm(request.get("email", ""))
    audit_at = parse_time(request.get("audit_at"))
    request_text = request.get("request_text", "")

    if not request_authorizes_deletion(request_text):
        return {
            "case_id": case_id,
            "deletion_status": "NOT_APPLICABLE",
            "steps_json": "[]",
        }

    user_ids, identifiers, phones, hashes = resolve_subject(email, identities, reverse)
    phone_digits = {digits(p) for p in phones if digits(p)}
    identifiers.update(hashes)
    identifiers.update(norm(v) for v in phones if v)
    identifiers.update(user_ids)

    candidates: list[dict[str, Any]] = []
    for obs in observations:
        if not observation_is_in_scope(obs, audit_at):
            continue
        if not observation_matches_subject(obs, identifiers, phone_digits, user_ids):
            continue

        record = obs.get("record", {})
        category = str(obs.get("category", "")).upper()
        state = normalize_observation_state(obs)

        if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
            action = policy_action(category, record if isinstance(record, dict) else {}, rules)
        else:
            action = policy_action(category, record if isinstance(record, dict) else {}, rules)

        candidate = make_candidate(obs, action, state)
        if candidate:
            captured = obs.get("captured_at")
            candidate["_captured_at"] = captured.isoformat() if captured else ""
            candidates.append(candidate)

    candidates.extend(infer_account_verification(email, user_ids, observations, audit_at))
    candidates = best_observation_by_resource(candidates)

    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []

    # A resource is a violation if the latest observed state fails policy.
    # Explicit absence/redaction/anonymization/disabled/blocked observations
    # are considered compliant only for the corresponding required treatment.
    for candidate in candidates:
        resource = candidate["resource_id"]
        system = candidate["system_id"] or "unknown_service"
        category = candidate["category"]
        action = candidate["action"]
        state = candidate["state"]
        evidence_id = candidate.get("evidence_id", "")

        if action == "FLOW":
            if state == "ACTIVE":
                findings.append(step(
                    "FINDING", system, resource,
                    "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id
                ))
                remediations.append(step(
                    "REMEDIATION", system, resource,
                    "DISABLE_DATA_FLOW", "DISABLED", ""
                ))
                verifications.append(step(
                    "VERIFICATION", system, resource,
                    "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""
                ))
            elif state == "DISABLED":
                verifications.append(step(
                    "VERIFICATION", system, resource,
                    "VERIFY_DATA_FLOW_DISABLED", "DISABLED", evidence_id
                ))
            continue

        if action == "RESTORE":
            if state in {"ACTIVE", "PRESENT", "UNKNOWN"}:
                findings.append(step(
                    "FINDING", system, resource,
                    "REPORT_RESTORE_RISK", "ACTIVE", evidence_id
                ))
                remediations.append(step(
                    "REMEDIATION", system, resource,
                    "BLOCK_RESTORE", "BLOCKED", ""
                ))
                verifications.append(step(
                    "VERIFICATION", system, resource,
                    "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""
                ))
            elif state == "BLOCKED":
                verifications.append(step(
                    "VERIFICATION", system, resource,
                    "VERIFY_RESTORE_BLOCKED", "BLOCKED", evidence_id
                ))
            continue

        if action == "RETAIN":
            if state in {"PRESENT", "UNKNOWN"}:
                verifications.append(step(
                    "VERIFICATION", system, resource,
                    "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id
                ))
            # A retained record is not a deletion violation.
            continue

        expected = {
            "DELETE": "ABSENT",
            "REDACT": "REDACTED",
            "ANONYMIZE": "ANONYMIZED",
        }.get(action, "ABSENT")

        compliant = state == expected
        if action == "DELETE" and state in {"ABSENT", "NOT_FOUND", "DELETED"}:
            compliant = True
        if action == "REDACT" and state == "REDACTED":
            compliant = True
        if action == "ANONYMIZE" and state == "ANONYMIZED":
            compliant = True

        if compliant:
            verify_operation = {
                "ABSENT": "VERIFY_RECORD_ABSENT",
                "REDACTED": "VERIFY_RECORD_REDACTED",
                "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED",
            }[expected]
            verifications.append(step(
                "VERIFICATION", system, resource,
                verify_operation, expected, evidence_id
            ))
            continue

        # Only explicit evidence that a record remains or exposes PII should
        # produce a finding. Unknown states are not enough to invent a leak.
        if state in {"PRESENT", "ACTIVE"}:
            finding_op = (
                "REPORT_REMAINING_RECORD" if action == "DELETE"
                else "REPORT_EXPOSED_PII"
            )
            findings.append(step(
                "FINDING", system, resource,
                finding_op, "PRESENT", evidence_id
            ))
            remediation_op, remediation_state, verify_op = remediation_for_action(action)
            remediations.append(step(
                "REMEDIATION", system, resource,
                remediation_op, remediation_state, ""
            ))
            verifications.append(step(
                "VERIFICATION", system, resource,
                verify_op, remediation_state, ""
            ))

    # Add checks for known retained security audit records that are linked by
    # stable user reference. Do not remove these records when policy says retain.
    for candidate in candidates:
        if candidate["category"] == "SECURITY_AUDIT_LOG" and candidate["state"] in {"PRESENT", "UNKNOWN"}:
            verifications.append(step(
                "VERIFICATION",
                candidate["system_id"],
                candidate["resource_id"],
                "VERIFY_RECORD_PRESENT",
                "PRESENT",
                candidate.get("evidence_id", ""),
            ))

    # If no violation is found, only evidence-backed verification steps may
    # support COMPLETE. If no relevant evidence exists, do not infer success
    # solely from reported_status.
    unique_findings = deduplicate_steps(findings)
    unique_remediations = deduplicate_steps(remediations)
    unique_verifications = deduplicate_steps(verifications)

    if unique_findings:
        status = "INCOMPLETE"
        # Future remediation and verification evidence IDs must be blank.
        for item in unique_remediations + unique_verifications:
            item["evidence_id"] = ""
        # Add an account absence check to the future verification plan when
        # the account resource is explicitly known from evidence.
        account_candidates = [
            c for c in candidates
            if c["system_id"] == "account_service"
            and c["category"] in {"USER_PROFILE", "ACCOUNT_TOMBSTONE"}
        ]
        for c in account_candidates:
            if not any(
                v["system_id"] == "account_service"
                and v["resource_id"] == c["resource_id"]
                and v["operation"] == "VERIFY_RECORD_ABSENT"
                for v in unique_verifications
            ):
                unique_verifications.append(step(
                    "VERIFICATION", "account_service", c["resource_id"],
                    "VERIFY_RECORD_ABSENT", "ABSENT", ""
                ))
    else:
        status = "COMPLETE"
        # For COMPLETE, keep only verifications backed by evidence.
        unique_verifications = [
            v for v in unique_verifications
            if v["evidence_id"]
        ]
        # If there is no positive evidence for any verification, the case is
        # uncertain; conservatively classify as incomplete without inventing
        # findings or unsupported remediation steps.
        if not unique_verifications:
            status = "INCOMPLETE"
            unique_verifications = []

    if status == "COMPLETE":
        output_steps = unique_verifications
    else:
        output_steps = unique_findings + unique_remediations + unique_verifications

    output_steps.sort(key=step_sort_key)
    for index, item in enumerate(output_steps, start=1):
        item["step_no"] = index

    # For a complete case, evidence IDs must cite actual evidence. For an
    # incomplete case, findings cite evidence; proposed work has blank IDs.
    if status == "COMPLETE":
        output_steps = [s for s in output_steps if s["evidence_id"]]

    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps_json": json.dumps(output_steps, ensure_ascii=False, separators=(",", ":")),
    }


def deduplicate_steps(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        key = (
            item.get("phase"),
            item.get("system_id"),
            item.get("resource_id"),
            item.get("operation"),
            item.get("state"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def validate_output(rows: list[dict[str, Any]], requests: list[dict[str, str]]) -> None:
    expected_ids = sorted(row["case_id"] for row in requests)
    actual_ids = [row["case_id"] for row in rows]

    if len(rows) != len(requests):
        raise ValueError(f"Expected {len(requests)} rows; produced {len(rows)}.")
    if actual_ids != expected_ids:
        raise ValueError("Output case IDs are missing, duplicated, or not sorted.")
    for row in rows:
        if row["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError(f"Invalid status for {row['case_id']}")
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid steps_json for {row['case_id']}: {exc}") from exc
        if not isinstance(steps, list):
            raise ValueError(f"steps_json must be a JSON array: {row['case_id']}")
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE must have []: {row['case_id']}")
        for index, item in enumerate(steps, start=1):
            required = {
                "step_no", "phase", "system_id", "resource_id",
                "operation", "state", "evidence_id",
            }
            if set(item.keys()) != required:
                raise ValueError(
                    f"Wrong step fields for {row['case_id']} step {index}: {set(item.keys())}"
                )
            if item["step_no"] != index:
                raise ValueError(f"Non-consecutive step_no for {row['case_id']}")
            if item["phase"] not in PHASE_ORDER:
                raise ValueError(f"Invalid phase for {row['case_id']}")
            if item["operation"] not in OP_ORDER:
                raise ValueError(f"Invalid operation for {row['case_id']}")


def write_usage_report(total_requests: int, evidence_count: int) -> None:
    path = ROOT / "code" / "evaluation" / "usage_report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = f"""# Token Usage and Cost Report

## Final full-dataset run

- Date: {datetime.now(timezone.utc).isoformat()}
- Requests processed: {total_requests}
- Evidence files listed in manifest: {evidence_count}
- Model provider: None (deterministic local Python implementation)
- Model name: None
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total model cost: USD 0.00
- Estimated model cost per request: USD 0.00

## Method

This run uses local CSV parsing, evidence parsing, identifier matching, policy rules,
and deterministic output generation. No remote model API is called. Token counts and
model cost are therefore zero; local CPU/runtime cost is not represented as model cost.

## Limitations

PDF extraction and image OCR are attempted only when optional dependencies are installed.
A clean run without those dependencies still processes CSV, JSON, SQL, logs, and text.
"""
    path.write_text(content, encoding="utf-8")


def main() -> int:
    log(f"Repository root: {ROOT}")
    requests = read_csv(DATASET / "deletion_requests.csv")
    if not requests:
        raise ValueError("deletion_requests.csv is empty.")

    identities, reverse = load_identity_index()
    rules = load_rules()

    log("Loading evidence files...")
    observations = load_evidence_records()
    log(f"Loaded {len(observations)} evidence observations.")

    output_rows = []
    for index, request in enumerate(requests, start=1):
        output_rows.append(
            process_request(request, identities, reverse, observations, rules)
        )
        if index % 50 == 0:
            log(f"Processed {index}/{len(requests)} requests.")

    output_rows.sort(key=lambda row: row["case_id"])
    validate_output(output_rows, requests)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(output_rows)

    counts: dict[str, int] = defaultdict(int)
    for row in output_rows:
        counts[row["deletion_status"]] += 1

    manifest = load_evidence_manifest()
    write_usage_report(len(requests), len(manifest))

    log(f"Output written: {OUTPUT_FILE}")
    log(f"Rows: {len(output_rows)}")
    log(
        "Statuses: "
        + ", ".join(f"{status}={counts.get(status, 0)}" for status in (
            "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"
        ))
    )
    log("Structural validation passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise