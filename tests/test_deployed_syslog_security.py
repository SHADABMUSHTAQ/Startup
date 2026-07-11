import asyncio

import pytest

import syslog_receiver


def test_syslog_source_allowlist_accepts_ip_and_cidr():
    networks = syslog_receiver.parse_allowed_source_networks("203.0.113.8,198.51.100.0/24")
    assert syslog_receiver.source_is_allowed("203.0.113.8", networks)
    assert syslog_receiver.source_is_allowed("198.51.100.42", networks)
    assert not syslog_receiver.source_is_allowed("192.0.2.1", networks)


def test_syslog_source_allowlist_rejects_invalid_entries():
    with pytest.raises(RuntimeError, match="Invalid SYSLOG_ALLOWED_SOURCES"):
        syslog_receiver.parse_allowed_source_networks("not-an-ip")


@pytest.mark.asyncio
async def test_deployed_udp_receiver_drops_non_allowlisted_source(monkeypatch):
    queue = asyncio.Queue()
    protocol = syslog_receiver.SyslogUDPProtocol(queue)
    monkeypatch.setattr(syslog_receiver, "APP_ENV", "production")
    monkeypatch.setattr(syslog_receiver, "ALLOWED_SOURCE_NETWORKS", ())

    protocol.datagram_received(b"<13>test", ("203.0.113.50", 5140))

    assert queue.empty()
    assert protocol._unauthorized == 1
