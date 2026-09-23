export const ROLE_PERMISSIONS = Object.freeze({
  admin: ["tenant.manage", "activation.manage", "holds.apply", "holds.release", "holds.read", "cases.create", "cases.attach", "cases.close", "custody.record", "archive.retrieve", "incidents.investigate", "operations.manage", "evidence.read", "cases.read", "custody.read", "exports.read", "retention.read", "operations.read", "endpoint.trust.read"],
  manager: ["archive.retrieve", "incidents.investigate", "operations.manage", "operations.read", "endpoint.trust.read"],
  analyst: ["incidents.investigate", "operations.manage", "operations.read", "endpoint.trust.read"],
  auditor: ["evidence.read", "cases.create", "cases.attach", "cases.read", "custody.record", "custody.read", "exports.read", "retention.read", "holds.read", "archive.retrieve", "operations.read", "endpoint.trust.read"],
});

export const normalizeRole = (role) => String(role || "").trim().toLowerCase();

export const hasPermission = (role, permission) => {
  const permissions = ROLE_PERMISSIONS[normalizeRole(role)] || [];
  return permissions.includes(permission);
};

export const hasAnyPermission = (role, permissions = []) => permissions.some((permission) => hasPermission(role, permission));
