"""Azure blob legal-hold helpers shared by archival and hold reconciliation."""

from __future__ import annotations

from datetime import datetime, timezone


def _as_utc(value):
    if not isinstance(value, datetime):
        return None
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def blob_legal_hold_status(properties) -> dict:
    return {
        "has_legal_hold": bool(getattr(properties, "has_legal_hold", False)),
        "version_id": getattr(properties, "version_id", None),
        "last_modified": _as_utc(getattr(properties, "last_modified", None)),
    }


async def ensure_blob_legal_hold(blob_client) -> dict:
    """Apply and verify a legal hold, preserving whether it pre-existed WarSOC."""
    before = blob_legal_hold_status(await blob_client.get_blob_properties())
    if not before["has_legal_hold"]:
        await blob_client.set_legal_hold(True)
    after = blob_legal_hold_status(await blob_client.get_blob_properties())
    if not after["has_legal_hold"]:
        raise RuntimeError("Azure blob legal hold could not be verified")
    return {
        "verified": True,
        "preexisting": before["has_legal_hold"],
        "version_id": after["version_id"] or before["version_id"],
        "verified_at": datetime.now(timezone.utc),
    }


async def release_managed_blob_legal_hold(blob_client, *, preexisting: bool) -> dict:
    """Clear only holds that WarSOC originally applied, then verify the result."""
    if preexisting:
        return {
            "released": False,
            "preserved_preexisting": True,
            "verified_at": datetime.now(timezone.utc),
        }
    await blob_client.set_legal_hold(False)
    after = blob_legal_hold_status(await blob_client.get_blob_properties())
    if after["has_legal_hold"]:
        raise RuntimeError("Azure blob legal hold release could not be verified")
    return {
        "released": True,
        "preserved_preexisting": False,
        "verified_at": datetime.now(timezone.utc),
    }


def archive_blob_client(container, name: str, version_id: str | None = None):
    kwargs = {"version_id": version_id} if version_id else {}
    return container.get_blob_client(name, **kwargs)


async def protect_archive_for_hold(
    db,
    blob_service,
    hold: dict,
    archive: dict,
    *,
    container_client=None,
) -> None:
    """Apply a hold to both archive objects and persist a retry-safe binding."""
    hold_id = str(hold["hold_id"])
    archive_key = str(archive["archive_key"])
    binding_query = {
        "tenant_id": str(hold["tenant_id"]),
        "hold_id": hold_id,
        "archive_key": archive_key,
    }
    binding = await db.evidence_archive_hold_bindings.find_one(binding_query)
    container = container_client or blob_service.get_container_client(str(archive["container_name"]))
    json_blob = archive_blob_client(
        container,
        str(archive["blob_name"]),
        archive.get("blob_version_id"),
    )
    hash_blob = archive_blob_client(
        container,
        str(archive["hash_blob_name"]),
        archive.get("hash_blob_version_id"),
    )
    if not binding:
        managed_binding = await db.evidence_archive_hold_bindings.find_one(
            {
                "tenant_id": str(hold["tenant_id"]),
                "archive_key": archive_key,
                "status": {"$in": ["APPLYING", "PROTECTED"]},
            }
        )
        if managed_binding:
            json_before = {
                "has_legal_hold": bool(managed_binding.get("json_hold_preexisting")),
                "version_id": managed_binding.get("blob_version_id"),
            }
            hash_before = {
                "has_legal_hold": bool(managed_binding.get("hash_hold_preexisting")),
                "version_id": managed_binding.get("hash_blob_version_id"),
            }
        else:
            json_before = blob_legal_hold_status(await json_blob.get_blob_properties())
            hash_before = blob_legal_hold_status(await hash_blob.get_blob_properties())
        now = datetime.now(timezone.utc)
        await db.evidence_archive_hold_bindings.update_one(
            binding_query,
            {
                "$setOnInsert": {
                    **binding_query,
                    "collection": archive.get("collection"),
                    "container_name": archive.get("container_name"),
                    "blob_name": archive.get("blob_name"),
                    "hash_blob_name": archive.get("hash_blob_name"),
                    "blob_version_id": archive.get("blob_version_id") or json_before["version_id"],
                    "hash_blob_version_id": archive.get("hash_blob_version_id") or hash_before["version_id"],
                    "json_hold_preexisting": json_before["has_legal_hold"],
                    "hash_hold_preexisting": hash_before["has_legal_hold"],
                    "status": "APPLYING",
                    "created_at": now,
                    "updated_at": now,
                }
            },
            upsert=True,
        )

    json_status = await ensure_blob_legal_hold(json_blob)
    hash_status = await ensure_blob_legal_hold(hash_blob)
    now = datetime.now(timezone.utc)
    await db.evidence_archive_hold_bindings.update_one(
        binding_query,
        {
            "$set": {
                "status": "PROTECTED",
                "json_verified_at": json_status["verified_at"],
                "hash_verified_at": hash_status["verified_at"],
                "updated_at": now,
            },
            "$unset": {"last_error": ""},
        },
    )
    await db.storage_archives.update_one(
        {"_id": archive["_id"], "tenant_id": hold["tenant_id"]},
        {
            "$addToSet": {"active_hold_ids": hold_id},
            "$set": {"legal_hold_reconciled_at": now},
        },
    )
