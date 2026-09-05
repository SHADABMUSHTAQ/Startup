"""Windows Server collection policy runtime. Never changes OS audit/firewall policy."""

import copy
import ctypes
import hashlib
import json
import os
import platform
import sys
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.utils.collection_profiles import (
    GENERAL_AUDIT_REQUIREMENTS,
    MAX_PROFILE_BYTES,
    PROFILE_ERROR_CODES,
    assignment_context,
    canonical_profile_json,
    general_server_compatible,
    sanitize_host_facts,
    validate_assignment,
)


def _registry_value(path, name, default=None):
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return default


def read_host_facts():
    facts = {}
    if sys.platform != "win32":
        return sanitize_host_facts(facts)
    try:
        facts["product_type"] = sys.getwindowsversion().product_type
        nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        facts["build"] = int(_registry_value(nt, "CurrentBuildNumber", "0"))
        facts["edition_id"] = _registry_value(nt, "EditionID", "")
        facts["installation_type"] = _registry_value(nt, "InstallationType", "")
        facts["architecture"] = platform.machine()
        machine_guid = _registry_value(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid", "")
        if machine_guid:
            facts["machine_fingerprint"] = hashlib.sha256(
                ("warsoc-host-v1|" + str(machine_guid)).encode("utf-8")
            ).hexdigest()
        netapi = ctypes.WinDLL("netapi32", use_last_error=True)
        name = ctypes.c_void_p()
        join_status = ctypes.c_int()
        netapi.NetGetJoinInformation.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
        netapi.NetGetJoinInformation.restype = ctypes.c_uint32
        netapi.NetApiBufferFree.argtypes = [ctypes.c_void_p]
        netapi.NetApiBufferFree.restype = ctypes.c_uint32
        if netapi.NetGetJoinInformation(None, ctypes.byref(name), ctypes.byref(join_status)) == 0:
            try:
                facts["domain_joined"] = join_status.value == 3 if join_status.value else None
            finally:
                netapi.NetApiBufferFree(name)
    except (OSError, ValueError, AttributeError):
        # Incomplete facts cannot qualify a server or authorize response.
        pass
    return sanitize_host_facts(facts)


class _Guid(ctypes.Structure):
    _fields_ = [("data1", ctypes.c_uint32), ("data2", ctypes.c_uint16),
                ("data3", ctypes.c_uint16), ("data4", ctypes.c_ubyte * 8)]


class _AuditPolicy(ctypes.Structure):
    _fields_ = [("subcategory", _Guid), ("flags", ctypes.c_uint32), ("category", _Guid)]


class _Luid(ctypes.Structure):
    _fields_ = [("low_part", ctypes.c_uint32), ("high_part", ctypes.c_int32)]


class _LuidAndAttributes(ctypes.Structure):
    _fields_ = [("luid", _Luid), ("attributes", ctypes.c_uint32)]


class _TokenPrivileges(ctypes.Structure):
    _fields_ = [("privilege_count", ctypes.c_uint32), ("privileges", _LuidAndAttributes * 1)]


@contextmanager
def _security_privilege():
    """Enable SeSecurityPrivilege only while reading effective audit policy."""
    token_adjust_privileges = 0x0020
    token_query = 0x0008
    privilege_enabled = 0x0002
    error_not_all_assigned = 1300
    token = ctypes.c_void_p()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    advapi.OpenProcessToken.restype = ctypes.c_int
    advapi.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_Luid)]
    advapi.LookupPrivilegeValueW.restype = ctypes.c_int
    advapi.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(_TokenPrivileges), ctypes.c_uint32,
        ctypes.POINTER(_TokenPrivileges), ctypes.POINTER(ctypes.c_uint32),
    ]
    advapi.AdjustTokenPrivileges.restype = ctypes.c_int
    if not advapi.OpenProcessToken(
        kernel.GetCurrentProcess(), token_adjust_privileges | token_query, ctypes.byref(token),
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    previous = _TokenPrivileges()
    previous_size = ctypes.c_uint32()
    try:
        luid = _Luid()
        if not advapi.LookupPrivilegeValueW(None, "SeSecurityPrivilege", ctypes.byref(luid)):
            raise OSError(ctypes.get_last_error(), "LookupPrivilegeValue failed")
        desired = _TokenPrivileges(1, (_LuidAndAttributes(luid, privilege_enabled),))
        ctypes.set_last_error(0)
        if not advapi.AdjustTokenPrivileges(
            token, False, ctypes.byref(desired), ctypes.sizeof(previous),
            ctypes.byref(previous), ctypes.byref(previous_size),
        ):
            raise OSError(ctypes.get_last_error(), "AdjustTokenPrivileges failed")
        error = ctypes.get_last_error()
        if error == error_not_all_assigned:
            raise OSError(error, "SeSecurityPrivilege is unavailable")
        yield
    finally:
        if previous_size.value:
            advapi.AdjustTokenPrivileges(token, False, ctypes.byref(previous), 0, None, None)
        kernel.CloseHandle(token)


def query_audit_policy():
    """GUID/native API readback avoids localized auditpol text parsing."""
    if sys.platform != "win32":
        raise OSError("Windows audit policy is unavailable")
    guids = (_Guid * len(GENERAL_AUDIT_REQUIREMENTS))(*[
        _Guid.from_buffer_copy(uuid.UUID(key).bytes_le) for key in GENERAL_AUDIT_REQUIREMENTS
    ])
    result = ctypes.POINTER(_AuditPolicy)()
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.AuditQuerySystemPolicy.argtypes = [ctypes.POINTER(_Guid), ctypes.c_uint32, ctypes.POINTER(ctypes.POINTER(_AuditPolicy))]
    api.AuditQuerySystemPolicy.restype = ctypes.c_ubyte
    api.AuditFree.argtypes = [ctypes.c_void_p]
    api.AuditFree.restype = None
    with _security_privilege():
        if not api.AuditQuerySystemPolicy(guids, len(guids), ctypes.byref(result)):
            raise OSError(ctypes.get_last_error(), "Audit policy query failed")
        try:
            return {
                str(uuid.UUID(bytes_le=bytes(result[i].subcategory))): int(result[i].flags)
                for i in range(len(guids))
            }
        finally:
            api.AuditFree(result)


def read_audit_health(facts, *, query=None, command_line_reader=None):
    result = {
        "state": "AUDIT_UNKNOWN", "observed_at": datetime.now(timezone.utc).isoformat(),
        # Domain membership does not prove which GPO owns a particular setting.
        "policy_owner": "LOCAL" if facts.get("domain_joined") is False else "UNKNOWN",
        "missing": [],
    }
    try:
        effective = (query or query_audit_policy)()
        missing = [key for key, required in GENERAL_AUDIT_REQUIREMENTS.items()
                   if effective.get(key, 0) & required != required]
        enabled = (command_line_reader or (lambda: _registry_value(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled", 0,
        )))()
        if enabled != 1:
            missing.append("process_command_line")
        result.update(state="AUDIT_DRIFTED" if missing else "AUDIT_OK", missing=missing)
    except (OSError, ValueError, TypeError, AttributeError):
        result["state"] = "AUDIT_UNKNOWN"
    return result


def _atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".profile-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(canonical_profile_json(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ServerMonitoringRuntime:
    def __init__(self, state_directory, *, facts=None):
        self.path = Path(state_directory) / "server-collection-profile.json"
        self.previous_path = Path(state_directory) / "server-collection-profile.previous.json"
        self.lock = threading.RLock()
        self.facts = sanitize_host_facts(facts if facts is not None else read_host_facts())
        self.identity_fingerprint = self.facts["machine_fingerprint"]
        self.assignment = None
        self.error_code = None
        self.server_seen = self.facts["product_type"] in (2, 3)
        if self.path.exists():
            try:
                if self.path.stat().st_size > MAX_PROFILE_BYTES + 1024:
                    raise ValueError("PROFILE_STATE_INVALID")
                saved = json.loads(self.path.read_text(encoding="utf-8"))
                assignment = validate_assignment(saved["assignment"])
                saved_fingerprint = str(saved.get("machine_fingerprint") or "")
                if (
                    saved_fingerprint
                    and self.facts["machine_fingerprint"]
                    and saved_fingerprint != self.facts["machine_fingerprint"]
                ):
                    raise ValueError("HOST_IDENTITY_CHANGED")
                self.identity_fingerprint = saved_fingerprint or self.identity_fingerprint
                self.assignment = assignment
                self.server_seen = True
            except ValueError as exc:
                code = str(exc)
                self.error_code = code if code in PROFILE_ERROR_CODES else "PROFILE_STATE_INVALID"
                self.server_seen = True
            except (OSError, KeyError, TypeError):
                self.error_code = "PROFILE_STATE_INVALID"
                self.server_seen = True

    def refresh_facts(self, facts=None):
        with self.lock:
            updated = sanitize_host_facts(facts if facts is not None else read_host_facts())
            if (
                self.identity_fingerprint
                and updated["machine_fingerprint"]
                and updated["machine_fingerprint"] != self.identity_fingerprint
            ):
                self.error_code = "HOST_IDENTITY_CHANGED"
            elif not self.identity_fingerprint and updated["machine_fingerprint"]:
                self.identity_fingerprint = updated["machine_fingerprint"]
            self.facts = updated
            self.server_seen = self.server_seen or updated["product_type"] in (2, 3)

    def is_server_boundary(self):
        with self.lock:
            return self.server_seen or self.facts["product_type"] != 1

    def allows_response(self):
        return not self.is_server_boundary()

    def snapshot(self, agent_id):
        with self.lock:
            if not self.is_server_boundary():
                return None
            if not self.assignment or self.assignment["agent_id"] != agent_id:
                return None
            if not general_server_compatible(self.facts) or self.error_code in {"HOST_IDENTITY_CHANGED", "PROFILE_STATE_INVALID"}:
                return None
            return copy.deepcopy(self.assignment)

    def apply(self, assignment, *, agent_id):
        with self.lock:
            try:
                candidate = validate_assignment(assignment, agent_id=agent_id)
                if not general_server_compatible(self.facts):
                    raise ValueError("HOST_UNSUPPORTED")
                if self.error_code in {"HOST_IDENTITY_CHANGED", "PROFILE_STATE_INVALID"}:
                    raise ValueError(self.error_code)
                current = self.assignment
                if current:
                    if (current["agent_id"], current["tenant_id"]) != (candidate["agent_id"], candidate["tenant_id"]):
                        raise ValueError("PROFILE_BINDING")
                    if candidate["revision"] < current["revision"]:
                        raise ValueError("PROFILE_REPLAY")
                    if candidate["revision"] == current["revision"]:
                        if candidate != current:
                            raise ValueError("PROFILE_CONFLICT")
                        self.error_code = None
                        return True
                    _atomic_write(self.previous_path, {"assignment": current, "machine_fingerprint": self.facts["machine_fingerprint"]})
                # Runtime profile application changes no OS policy: one atomic
                # state replacement is the commit point before collection/ACK.
                _atomic_write(self.path, {"assignment": candidate, "machine_fingerprint": self.facts["machine_fingerprint"]})
                self.assignment = candidate
                self.identity_fingerprint = self.facts["machine_fingerprint"]
                self.server_seen = True
                self.error_code = None
                return True
            except (ValueError, TypeError, OSError) as exc:
                code = str(exc)
                self.error_code = code if code in PROFILE_ERROR_CODES else "PROFILE_STORAGE"
                return False

    def report(self, agent_id, *, audit=None):
        with self.lock:
            current = self.snapshot(agent_id)
            state = "PENDING"
            if not general_server_compatible(self.facts):
                state = "UNSUPPORTED"
            if current:
                state = "APPLIED" if current["profile"]["enabled"] else "PAUSED"
            if self.error_code:
                state = "PROFILE_APPLY_FAILED"
            return {
                "state": state,
                "applied_revision": current["revision"] if current else 0,
                "applied_profile_id": current["profile"]["profile_id"] if current else None,
                "applied_profile_version": current["profile"]["profile_version"] if current else None,
                "applied_profile_hash": current["profile_hash"] if current else "",
                "error_code": self.error_code,
                "audit": audit or {"state": "AUDIT_UNKNOWN"},
            }

    def collection_context(self, agent_id):
        current = self.snapshot(agent_id)
        return assignment_context(current) if current else None
