"""Fernet encryption for LTM text and embedding blobs at rest."""

from __future__ import annotations

import logging
import pickle
from pathlib import Path

import numpy as np
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_KEY_FILE_NAME = ".ltm_key"
_fernet: Fernet | None = None
_key_path: Path | None = None


def _project_root() -> Path:
    # backend/app/security/encryptor.py -> backend/
    return Path(__file__).resolve().parent.parent.parent


def key_path() -> Path:
    global _key_path
    if _key_path is None:
        _key_path = _project_root() / _KEY_FILE_NAME
    return _key_path


def encryption_enabled() -> bool:
    import os

    return bool(os.environ.get("LTM_ENCRYPTION_KEY")) or key_path().is_file()


def _load_or_create_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet

    # 1. Prefer an explicit env var — required on Vercel, where the filesystem
    #    is read-only outside /tmp and /tmp does not persist between invocations.
    import os

    env_key = os.environ.get("LTM_ENCRYPTION_KEY")
    if env_key:
        _fernet = Fernet(env_key.strip().encode("ascii"))
        return _fernet

    # 2. Fall back to a key file on disk (local / non-serverless deployments).
    kp = key_path()
    if kp.is_file():
        key = kp.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        try:
            kp.write_bytes(key)
            logger.info("Generated new LTM encryption key at %s", kp)
            gitignore = _project_root().parent / ".gitignore"
            if gitignore.is_file():
                content = gitignore.read_text(encoding="utf-8")
                if ".ltm_key" not in content:
                    gitignore.write_text(content.rstrip() + "\n.ltm_key\n", encoding="utf-8")
        except OSError:
            # Read-only filesystem (e.g. serverless) — use an ephemeral
            # in-memory key for this process instead of crashing.
            logger.warning(
                "Could not persist LTM key to disk; using an ephemeral key. "
                "Set LTM_ENCRYPTION_KEY env var for stable encryption across restarts."
            )
    _fernet = Fernet(key)
    return _fernet


def encrypt_text(plain_text: str) -> str:
    f = _load_or_create_fernet()
    return f.encrypt((plain_text or "").encode("utf-8")).decode("ascii")


def decrypt_text(cipher_text: str) -> str:
    if not cipher_text:
        return ""
    try:
        f = _load_or_create_fernet()
        return f.decrypt(cipher_text.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as e:
        logger.warning("LTM text decryption failed: %s", e)
        return "[DECRYPTION_FAILED]"


def encrypt_embedding(embedding: np.ndarray) -> bytes:
    f = _load_or_create_fernet()
    raw = pickle.dumps(np.asarray(embedding, dtype=np.float32), protocol=4)
    return f.encrypt(raw)


def decrypt_embedding(blob: bytes) -> np.ndarray:
    if not blob:
        return np.zeros(384, dtype=np.float32)
    try:
        f = _load_or_create_fernet()
        raw = f.decrypt(blob)
        return pickle.loads(raw)
    except Exception as e:
        logger.warning("LTM embedding decryption failed: %s", e)
        return np.zeros(384, dtype=np.float32)


def is_encrypted_payload(text: str) -> bool:
    """Heuristic: Fernet tokens start with gAAAAA."""
    return bool(text) and text.startswith("gAAAA")
