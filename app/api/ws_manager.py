from fastapi import WebSocket
from typing import Dict, List
import json
import datetime

class ConnectionManager:
    def __init__(self):
        # Tracking active dashboard connections by Tenant Room
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, tenant_id: str):
        """Accepts a new WebSocket connection and assigns it to a Tenant Room."""
        await websocket.accept()
        if tenant_id not in self.active_connections:
            self.active_connections[tenant_id] = []
        self.active_connections[tenant_id].append(websocket)
        print(f"✅ Dashboard Connected to Room [{tenant_id}]. Active: {len(self.active_connections[tenant_id])}")

    def disconnect(self, websocket: WebSocket, tenant_id: str):
        """Removes a WebSocket connection from its Tenant Room."""
        if tenant_id in self.active_connections and websocket in self.active_connections[tenant_id]:
            self.active_connections[tenant_id].remove(websocket)
            if not self.active_connections[tenant_id]:
                del self.active_connections[tenant_id]
            print(f"🔌 Dashboard Disconnected from [{tenant_id}].")

    async def broadcast_to_tenant(self, tenant_id: str, message: dict):
        """Sends a payload ONLY to dashboards connected to this specific tenant."""
        if tenant_id in self.active_connections:
            for connection in self.active_connections[tenant_id][:]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"⚠️ Failed to send to a stale connection: {e}")
                    self.disconnect(connection, tenant_id)

    # ==========================================
    # ✅ SECURE: SPECIALIZED AI & THREAT METHODS
    # ==========================================

    async def send_threat_alert(self, tenant_id: str, ip: str, severity: str, message: str, mitre_id: str = "T1000", engine: str = "Stateless"):
        payload = {
            "severity": severity.upper(),
            "title": message,
            "source_ip": ip,
            "mitre": mitre_id,
            "engine_source": engine,
            "timestamp": datetime.datetime.now().isoformat()
        }
        await self.broadcast_to_tenant(tenant_id, payload)
        print(f"🚀 Alert Sent to [{tenant_id}]: [{severity}] {message} from {ip}")

    async def send_mitigation_status(self, tenant_id: str, ip: str, status: str):
        msg_type = "MITIGATION_SUCCESS" if status == "BLOCKED" else "MITIGATION_REVOKED"
        payload = {
            "type": msg_type,
            "ip": ip,
            "timestamp": datetime.datetime.now().isoformat()
        }
        await self.broadcast_to_tenant(tenant_id, payload)
        print(f"🛡️ Mitigation Update for [{tenant_id}]: {ip} -> {status}")

# Global instance
manager = ConnectionManager()