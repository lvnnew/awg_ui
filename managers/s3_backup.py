"""
S3-compatible off-site backup for panel state (data.json + SECRET_KEY pair).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

BACKUP_MANIFEST_VERSION = 1
_STAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z/$')


def default_backup_settings() -> dict:
    return {
        'enabled': False,
        'endpoint_url': '',
        'region': 'us-east-1',
        'bucket': '',
        'prefix': 'awg-panel/backups/',
        'access_key_id': '',
        'secret_access_key': '',
        'force_path_style': True,
        'interval_hours': 12,
        'retention_count': 30,
        'last_run_at': None,
        'last_status': 'never',
        'last_error': '',
        'last_backup_key': '',
    }


def normalize_prefix(prefix: str) -> str:
    prefix = (prefix or 'awg-panel/backups/').strip()
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    return prefix


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def create_s3_client(cfg: dict):
    import boto3
    from botocore.config import Config

    endpoint = (cfg.get('endpoint_url') or '').strip() or None
    style = 'path' if cfg.get('force_path_style', True) else 'auto'
    config = Config(signature_version='s3v4', s3={'addressing_style': style})

    return boto3.client(
        's3',
        endpoint_url=endpoint,
        region_name=(cfg.get('region') or 'us-east-1').strip() or 'us-east-1',
        aws_access_key_id=(cfg.get('access_key_id') or '').strip(),
        aws_secret_access_key=(cfg.get('secret_access_key') or '').strip(),
        config=config,
    )


def validate_backup_config(cfg: dict) -> str | None:
    if not (cfg.get('bucket') or '').strip():
        return 'Bucket name is required'
    if not (cfg.get('access_key_id') or '').strip():
        return 'Access key ID is required'
    if not (cfg.get('secret_access_key') or '').strip():
        return 'Secret access key is required'
    retention = int(cfg.get('retention_count') or 30)
    if retention < 1:
        return 'Retention count must be at least 1'
    interval = int(cfg.get('interval_hours') or 12)
    if interval < 1:
        return 'Interval must be at least 1 hour'
    return None


def test_connection(cfg: dict) -> tuple[bool, str]:
    err = validate_backup_config(cfg)
    if err:
        return False, err
    try:
        client = create_s3_client(cfg)
        bucket = cfg['bucket'].strip()
        client.head_bucket(Bucket=bucket)
        probe_key = normalize_prefix(cfg.get('prefix')) + '.panel-backup-probe'
        client.put_object(Bucket=bucket, Key=probe_key, Body=b'ok', ContentType='text/plain')
        client.delete_object(Bucket=bucket, Key=probe_key)
        return True, 'Connection OK'
    except Exception as e:
        logger.warning('S3 backup test failed: %s', e)
        return False, str(e)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')


def _build_manifest(*, data_bytes: bytes, secret_key: str, panel_version: str, data_parsed: dict) -> dict:
    return {
        'version': BACKUP_MANIFEST_VERSION,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'panel_version': panel_version,
        'data_sha256': sha256_bytes(data_bytes),
        'secret_key_sha256': sha256_text(secret_key),
        'servers_count': len(data_parsed.get('servers') or []),
        'users_count': len(data_parsed.get('users') or []),
        'user_connections_count': len(data_parsed.get('user_connections') or []),
        'restore_note': 'Restore data.json together with secret.key using the same SECRET_KEY value.',
    }


def run_backup(*, data_path: str, secret_key: str, cfg: dict, panel_version: str) -> dict[str, Any]:
    """Upload data.json + secret.key + manifest.json to S3. Returns result metadata."""
    err = validate_backup_config(cfg)
    if err:
        raise ValueError(err)
    if not secret_key:
        raise ValueError('SECRET_KEY environment variable is not set')
    if not os.path.exists(data_path):
        raise FileNotFoundError(f'Data file not found: {data_path}')

    with open(data_path, 'rb') as f:
        data_bytes = f.read()

    try:
        data_parsed = json.loads(data_bytes.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise ValueError(f'Invalid data.json: {e}') from e

    bucket = cfg['bucket'].strip()
    prefix = normalize_prefix(cfg.get('prefix'))
    stamp = _utc_stamp()
    base_key = f'{prefix}{stamp}/'

    manifest = _build_manifest(
        data_bytes=data_bytes,
        secret_key=secret_key,
        panel_version=panel_version,
        data_parsed=data_parsed,
    )
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode('utf-8')
    secret_bytes = secret_key.encode('utf-8')

    client = create_s3_client(cfg)
    client.put_object(
        Bucket=bucket, Key=base_key + 'data.json',
        Body=data_bytes, ContentType='application/json',
    )
    client.put_object(
        Bucket=bucket, Key=base_key + 'secret.key',
        Body=secret_bytes, ContentType='text/plain',
    )
    client.put_object(
        Bucket=bucket, Key=base_key + 'manifest.json',
        Body=manifest_bytes, ContentType='application/json',
    )

    retention = int(cfg.get('retention_count') or 30)
    deleted = prune_old_backups(client, bucket, prefix, retention)

    return {
        'backup_key': base_key,
        'bucket': bucket,
        'manifest': manifest,
        'pruned_folders': deleted,
    }


def _folder_stamp(prefix: str) -> str | None:
    # prefix like awg-panel/backups/2026-06-08T07-30-00Z/
    tail = prefix.rstrip('/').split('/')[-1]
    if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$', tail):
        return tail
    return None


def prune_old_backups(client, bucket: str, prefix: str, keep: int) -> int:
    """Delete oldest backup folders beyond *keep*. Returns number of folders removed."""
    prefix = normalize_prefix(prefix)
    folders: list[str] = []
    paginator = client.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter='/'):
        for cp in page.get('CommonPrefixes') or []:
            p = cp.get('Prefix') or ''
            if _folder_stamp(p):
                folders.append(p)

    folders.sort(reverse=True)  # newest first (lexicographic ISO UTC)
    to_delete = folders[keep:]
    deleted = 0
    for folder in to_delete:
        keys: list[dict] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=folder):
            for obj in page.get('Contents') or []:
                keys.append({'Key': obj['Key']})
        if keys:
            for i in range(0, len(keys), 1000):
                client.delete_objects(Bucket=bucket, Delete={'Objects': keys[i:i + 1000]})
        deleted += 1
    return deleted


def list_recent_backups(cfg: dict, limit: int = 10) -> list[dict]:
    err = validate_backup_config(cfg)
    if err:
        return []
    client = create_s3_client(cfg)
    bucket = cfg['bucket'].strip()
    prefix = normalize_prefix(cfg.get('prefix'))
    folders: list[str] = []
    paginator = client.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter='/'):
        for cp in page.get('CommonPrefixes') or []:
            p = cp.get('Prefix') or ''
            stamp = _folder_stamp(p)
            if stamp:
                folders.append(stamp)
    folders.sort(reverse=True)
    return [{'stamp': s, 'prefix': f'{prefix}{s}/'} for s in folders[:limit]]
