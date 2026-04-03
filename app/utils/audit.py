import functools
import json
import logging
from datetime import datetime, timezone
from fastapi import Request, HTTPException
from app.database import db_manager

logger = logging.getLogger("Management-Audit")

def audit_log(action_name: str):
    """
    🔬 MASTER BUILD: Internal Management Audit Decorator.
    Intercepts administrative actions and records them for compliance (PECA/SOC2).
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # 1. Extract the Request object from the decorated function's kwargs
            request: Request = kwargs.get("request")
            if not request:
                # Attempt to find it in args if not in kwargs
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            
            # 2. Extract current user if available (Depends on get_current_user being used)
            current_user = kwargs.get("current_user")
            operator = current_user.get("username", "System/Anonymous") if current_user else "System/Anonymous"
            tenant_id = current_user.get("tenant_id", "System") if current_user else "System"

            # 3. Execute the actual functional logic
            try:
                response = await func(*args, **kwargs)
                status = "SUCCESS"
            except Exception as e:
                status = f"FAILED: {str(e)}"
                raise e
            finally:
                # 4. Asynchronously record the audit trail (Fire and Forget for high performance)
                try:
                    audit_entry = {
                        "timestamp": datetime.now(timezone.utc),
                        "operator": operator,
                        "tenant_id": tenant_id,
                        "action": action_name,
                        "endpoint": str(request.url) if request else "Unknown",
                        "method": request.method if request else "Unknown",
                        "status": status
                    }
                    
                    # Store in the dedicated management_audit collection
                    if db_manager.db is not None:
                        # We use insert_one directly to ensure immutability
                        # TTL for management audit is typically long (90-365 days)
                        await db_manager.db.management_audit.insert_one(audit_entry)
                        
                except Exception as audit_err:
                    logger.error(f"Critical Audit Logging Failure: {audit_err}")

            return response
        return wrapper
    return decorator
