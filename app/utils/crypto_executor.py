"""
ProcessPoolExecutor-based cryptographic signing utility.

This module offloads CPU-bound RSA-PSS signing to separate processes,
freeing the main event loop from blocking on cryptographic operations.

The standalone signing function is pickle-able and runs in a worker process.
"""

import base64
import copy
import os
import sys
import logging
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger("crypto-executor")

# Global executor instance (lazy-initialized per process)
_executor = None


def _load_private_key(key_data: bytes, password: bytes = None):
    """Load RSA private key from PEM bytes. Runs in executor process."""
    return serialization.load_pem_private_key(key_data, password=password)


def _sign_canonical_bytes(canonical_bytes: bytes, key_data: bytes, password: bytes = None) -> str:
    """
    Sign canonical bytes using RSA-2048-PSS-SHA256.
    
    This is a pure function that can be executed in a separate process.
    It receives key material as bytes (pickle-able) and returns base64-encoded signature.
    
    Args:
        canonical_bytes: Deterministic byte representation of the log data
        key_data: PEM-encoded private key bytes
        password: Optional passphrase for the private key
        
    Returns:
        Base64-encoded RSA-PSS signature
        
    Raises:
        ValueError: If key loading or signing fails
    """
    try:
        private_key = _load_private_key(key_data, password)
        
        signature = private_key.sign(
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        logger.error(f"Signing failed: {e}")
        raise ValueError(f"Cryptographic signing failed: {e}") from e


def get_crypto_executor(max_workers: int = 2) -> ProcessPoolExecutor:
    """
    Get or create the global ProcessPoolExecutor for crypto operations.
    
    Args:
        max_workers: Number of worker processes (default 2; tune based on CPU cores)
        
    Returns:
        ProcessPoolExecutor instance
    """
    global _executor
    if _executor is None:
        _executor = ProcessPoolExecutor(max_workers=max_workers)
        logger.info(f"Initialized ProcessPoolExecutor with {max_workers} worker processes for cryptographic operations")
    return _executor


def shutdown_crypto_executor():
    """Gracefully shut down the crypto executor. Call during application shutdown."""
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=True)
        _executor = None
        logger.info("Crypto executor shut down gracefully")
