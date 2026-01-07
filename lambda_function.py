import boto3
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote_plus, unquote_plus

# AWS clients
s3 = boto3.client("s3")
sns = boto3.client("sns")

# Environment variables (set in Lambda Configuration)
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

# MVP: only scan simple text files
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json", ".log"}
MAX_BYTES = 1024 * 1024  # 1 MB


# Patterns we want to detect (name -> regex)
PATTERNS = {
    "AWS Access Key ID": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "Private Key": r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----",
    "Password": r"(?i)\bpassword\b\s*[:=]",
    "Credit Card Number": r"\b(?:\d[ -]*?){13,16}\b",
}

COMPILED_PATTERNS = {name: re.compile(rx) for name, rx in PATTERNS.items()}


def file_extension(key: str) -> str:
    """Return lower-case extension like '.txt' or '' if no extension."""
    key = key.lower()
    dot = key.rfind(".")
    return key[dot:] if dot != -1 else ""


def s3_tagging_string(tags: dict) -> str:
    """Convert dict to S3 Tagging string: key=value&key2=value2 (URL-encoded)."""
    return "&".join(f"{quote_plus(str(k))}={quote_plus(str(v))}" for k, v in tags.items())


def scan_for_secrets(text: str) -> list[str]:
    """Return a list of pattern names that match the content."""
    hits = []
    for name, rx in COMPILED_PATTERNS.items():
        if rx.search(text):
            hits.append(name)
    return hits


def send_alert(subject: str, message: str) -> None:
    """Send SNS alert if SNS_TOPIC_ARN is set."""
    if not SNS_TOPIC_ARN:
        print("⚠️ SNS_TOPIC_ARN not set, skipping alert.")
        return

    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    print("📩 SNS alert published.")


def lambda_handler(event, context):
    print("=== LeakBlockerScanner ===")
    print("Event received:", json.dumps(event))

    if not QUARANTINE_BUCKET:
        raise RuntimeError("Missing environment variable: QUARANTINE_BUCKET")

    # Extract bucket + key from the S3 event
    try:
        record = event["Records"][0]
        src_bucket = record["s3"]["bucket"]["name"]

        # S3 keys may be URL-encoded in events
        src_key = unquote_plus(record["s3"]["object"]["key"])
    except Exception:
        raise RuntimeError("Expected S3 ObjectCreated event format: Records[0].s3.bucket/object")

    print(f"Source bucket: {src_bucket}")
    print(f"Source key: {src_key}")

    # Safety: don't process events from the quarantine bucket (prevents loops)
    if src_bucket == QUARANTINE_BUCKET:
        print("Skipping: object is already in the quarantine bucket.")
        return {"statusCode": 200, "body": "Skipped quarantine bucket"}

    # Only scan allowed text extensions (MVP)
    ext = file_extension(src_key)
    if ext not in ALLOWED_EXTENSIONS:
        print(f"Skipping file (unsupported extension): {ext}")
        return {"statusCode": 200, "body": f"Skipped unsupported extension {ext}"}

    # Check size 
    meta = s3.head_object(Bucket=src_bucket, Key=src_key)
    size = meta.get("ContentLength", 0)

    if size > MAX_BYTES:
        print(f"Skipping file (too large): {size} bytes")
        return {"statusCode": 200, "body": "Skipped large file"}

    # Download the object and decode as text
    obj = s3.get_object(Bucket=src_bucket, Key=src_key)
    raw_bytes = obj["Body"].read()
    text = raw_bytes.decode("utf-8", errors="replace")

    # Scan content
    hits = scan_for_secrets(text)

    if not hits:
        print("✅ Scan result: clean (no sensitive patterns found).")
        return {"statusCode": 200, "body": "Clean"}

    # Quarantine: copy to quarantine bucket, tag it, then delete original
    reason = ", ".join(hits)
    print(f"🚨 Scan result: sensitive data found -> {reason}")

    tags = {
        "LeakBlocker": "Quarantined",
        "Reason": reason[:200],  
    }

    s3.copy_object(
        Bucket=QUARANTINE_BUCKET,
        Key=src_key,
        CopySource={"Bucket": src_bucket, "Key": src_key},
        TaggingDirective="REPLACE",
        Tagging=s3_tagging_string(tags),
    )

    s3.delete_object(Bucket=src_bucket, Key=src_key)
    print("🧹 Original file deleted from the public bucket.")

    # Notify admins via SNS
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = "LeakBlocker Alert: Sensitive Data Detected"
    message = (
        "LeakBlocker Alert 🚨\n\n"
        f"Time: {when}\n"
        f"Public Bucket: {src_bucket}\n"
        f"File: {src_key}\n"
        f"Detected: {reason}\n\n"
        f"Action: copied to '{QUARANTINE_BUCKET}' and deleted from '{src_bucket}'.\n"
    )

    send_alert(subject, message)

    return {"statusCode": 200, "body": "Quarantined and alerted"}
