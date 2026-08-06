import os
import boto3
from botocore.exceptions import ClientError
from botocore.client import Config
from observability import get_logger

log = get_logger(__name__)

MINIO_URL = os.environ.get("MINIO_URL", "http://minio:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
EVIDENCE_BUCKET = "sentinel-evidence"

def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=MINIO_URL,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1"
    )

def setup_bucket():
    """Ensure the evidence bucket exists on startup. Idempotent — safe to call multiple times."""
    s3 = get_s3_client()
    try:
        s3.head_bucket(Bucket=EVIDENCE_BUCKET)
        log.info(f"[Evidence] Bucket '{EVIDENCE_BUCKET}' already exists.")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("404", "NoSuchBucket"):
            log.info(f"[Evidence] Bucket '{EVIDENCE_BUCKET}' not found. Creating...")
            try:
                s3.create_bucket(Bucket=EVIDENCE_BUCKET)
                import json
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["s3:GetObject"],
                            "Resource": [f"arn:aws:s3:::{EVIDENCE_BUCKET}/*"]
                        }
                    ]
                }
                s3.put_bucket_policy(Bucket=EVIDENCE_BUCKET, Policy=json.dumps(policy))
                log.info(f"[Evidence] Bucket '{EVIDENCE_BUCKET}' created and policy applied.")
            except ClientError as create_err:
                create_code = create_err.response["Error"]["Code"]
                if create_code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                    # Race condition or restart — bucket exists, we're fine
                    log.info(f"[Evidence] Bucket '{EVIDENCE_BUCKET}' already owned. Skipping creation.")
                else:
                    log.error(f"[Evidence] Failed to create bucket: {create_err}")
        else:
            log.error(f"[Evidence] Unexpected error checking bucket: {e}")

def upload_evidence(scan_id: int, filename: str, content: str) -> str:
    """
    Uploads raw text content to MinIO and returns a URL.
    """
    s3 = get_s3_client()
    object_name = f"scan_{scan_id}/{filename}"
    try:
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=object_name,
            Body=content.encode("utf-8"),
            ContentType="text/plain"
        )
        # Using localhost for the URL so it's accessible from the host machine browser
        url = f"http://localhost:9000/{EVIDENCE_BUCKET}/{object_name}"
        return url
    except ClientError as e:
        log.error(f"Failed to upload evidence for scan {scan_id}: {e}")
        return ""
