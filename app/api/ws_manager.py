import asyncio
import datetime
import logging
from typing import Dict, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # ✅ CTO FIX 1: O(1) Memory Set instead of O(n) List
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, tenant_id: str):
        """Accepts a new WebSocket connection and assigns it to a Tenant Room."""
        await websocket.accept()
        if tenant_id not in self.active_connections:
            self.active_connections[tenant_id] = set()
            
        self.active_connections[tenant_id].add(websocket)
        logger.info(f"✅ Dashboard Connected to Room [{tenant_id}]. Active: {len(self.active_connections[tenant_id])}")

    def disconnect(self, websocket: WebSocket, tenant_id: str):
        """Removes a WebSocket connection from its Tenant Room instantly."""
        if tenant_id in self.active_connections:
            # discard() is safer than remove() as it doesn't throw KeyErrors
            self.active_connections[tenant_id].discard(websocket)
            if not self.active_connections[tenant_id]:
                del self.active_connections[tenant_id]
        logger.info(f"🔌 Dashboard Disconnected from [{tenant_id}].")

    async def _send_with_timeout(self, websocket: WebSocket, tenant_id: str, message: dict):
        """Internal wrapper to enforce strict timeouts on individual sockets."""
        try:
            # ✅ CTO FIX 2: Strict 2-second timeout to kill zombie connections instantly
            await asyncio.wait_for(websocket.send_json(message), timeout=2.0)
        except Exception as e:
            logger.warning(f"⚠️ Pruning dead dashboard connection for [{tenant_id}]: {str(e)}")
            self.disconnect(websocket, tenant_id)

    async def broadcast_to_tenant(self, tenant_id: str, message: dict):
        """Sends a payload ONLY to dashboards connected to this specific tenant concurrently."""
        if tenant_id in self.active_connections:
            # Copy the set to a list to avoid "Set changed size during iteration" errors
            connections = list(self.active_connections[tenant_id])
            
            # ✅ CTO FIX 3: Parallel Broadcasting
            # A slow client will NEVER block other clients from receiving the alert.
            tasks = [self._send_with_timeout(ws, tenant_id, message) for ws in connections]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    # ==========================================
    # SECURE: SPECIALIZED AI & THREAT METHODS
    # ==========================================

    async def send_threat_alert(self, tenant_id: str, ip: str, severity: str, message: str, mitre_id: str = "T1000", engine: str = "Stateless"):
        payload = {
            "severity": severity.upper(),
            "title": message,
            "source_ip": ip,
            "mitre": mitre_id,
            "engine_source": engine,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        await self.broadcast_to_tenant(tenant_id, payload)

    async def send_mitigation_status(self, tenant_id: str, ip: str, status: str):
        msg_type = "MITIGATION_SUCCESS" if status == "BLOCKED" else "MITIGATION_REVOKED"
        payload = {
            "type": msg_type,
            "ip": ip,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        await self.broadcast_to_tenant(tenant_id, payload)

# Global instance
manager = ConnectionManager()