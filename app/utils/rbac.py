from fastapi import HTTPException, status, Depends, Request
from typing import List
import jwt
from app.config.config import get_settings
from fastapi.security import OAuth2PasswordBearer
from app.database import get_db

settings = get_settings()

# Define our own OAuth2 scheme here to avoid circular imports with `app.routes.auth`.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = [str(role).strip().lower() for role in allowed_roles]

    async def __call__(self, request: Request, token: str = Depends(oauth2_scheme), db = Depends(get_db)):
        try:
            token = token or request.cookies.get("warsoc_token")
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials for RBAC"
                )

            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
            username = payload.get("sub")
            tenant_id = payload.get("tenant_id")
            token_type = payload.get("type")
            if token_type != "user" or not username or not tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials for RBAC"
                )

            # Resolve authorization from current tenant-scoped database state.
            user = await db["users"].find_one(
                {"username": username, "tenant_id": tenant_id}
            )
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials for RBAC (User not found)"
                )

            user_role = str(user.get("role") or "").strip().lower()

            if user_role not in self.allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Operation restricted to roles: {', '.join(self.allowed_roles)}. Your role: {user_role}"
                )

            return user_role
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials for RBAC"
            )
