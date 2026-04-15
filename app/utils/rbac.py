from fastapi import HTTPException, status, Depends
from typing import List
import jwt
from app.config.config import get_settings
from fastapi.security import OAuth2PasswordBearer

settings = get_settings()

# Define our own OAuth2 scheme here to avoid circular imports with `app.routes.auth`.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
            user_role = payload.get("role")

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
