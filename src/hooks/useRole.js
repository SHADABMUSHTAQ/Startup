import { useMemo } from "react";
import { useAuthStore } from "../store/authStore";
import { hasAnyPermission, hasPermission, normalizeRole } from "../utils/roleContract";

export default function useRole() {
  const { role, user } = useAuthStore();
  const activeRole = normalizeRole(role || user?.role);
  return useMemo(() => ({
    role: activeRole,
    is: (expectedRole) => activeRole === normalizeRole(expectedRole),
    can: (permission) => hasPermission(activeRole, permission),
    canAny: (permissions) => hasAnyPermission(activeRole, permissions),
  }), [activeRole]);
}
