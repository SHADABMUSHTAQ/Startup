const formatValidationItem = (item) => {
  if (!item || typeof item !== "object") return String(item || "");

  const rawLoc = Array.isArray(item.loc) ? item.loc : [];
  const field = rawLoc.filter((part) => part !== "body").join(".");
  const message = item.msg || item.message || item.type || "Invalid value";

  return field ? `${field}: ${message}` : message;
};

const stringifyDetail = (value) => {
  if (!value) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);

  if (Array.isArray(value)) {
    return value.map(stringifyDetail).filter(Boolean).join("; ");
  }

  if (typeof value === "object") {
    if (value.loc || value.msg || value.type) return formatValidationItem(value);
    if (value.detail) return stringifyDetail(value.detail);
    if (value.error) return stringifyDetail(value.error);
    if (value.message) return stringifyDetail(value.message);

    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }

  return String(value);
};

const INTERNAL_DETAIL_PATTERN = new RegExp(
  [
    'api synchronization',
    'backend',
    'database',
    'deployment',
    'exception',
    'fastapi',
    'mongo(?:db)?',
    'pipeline',
    'pydantic',
    'redis',
    'server',
    'ssot',
    'stack trace',
    'traceback',
    'worker',
  ].join('|'),
  'i',
);

const safeDetail = (value, fallback) => {
  const detail = stringifyDetail(value).trim();
  if (!detail || detail.length > 240 || /[\r\n]/.test(detail)) return fallback;
  if (INTERNAL_DETAIL_PATTERN.test(detail)) return fallback;
  return detail;
};

export const formatApiError = (error, fallback = "Request failed. Please try again.") => {
  const status = Number(error?.response?.status || 0);
  const data = error?.response?.data;
  const requestUrl = String(error?.config?.url || '');

  if (!status) return "Unable to complete the request. Check your connection and try again.";
  if (status === 401) {
    if (requestUrl.includes('/auth/2fa/')) return "Invalid verification code.";
    return requestUrl.includes('/auth/login')
      ? "Invalid email or password."
      : "Your session has expired. Please sign in again.";
  }
  if (status === 429) return "Too many requests. Please wait a moment and try again.";
  if (status === 422) return "Some information is missing or invalid. Review the form and try again.";
  if (status >= 500) return fallback;

  return safeDetail(
    data?.detail ?? data?.error ?? data?.message ?? error?.message,
    fallback,
  );
};

export const formatApiErrorData = (
  data,
  fallback = "Request failed. Please try again.",
  status = 0,
) => {
  if (status === 429) return "Too many requests. Please wait a moment and try again.";
  if (status === 422) return "Some information is missing or invalid. Review the form and try again.";
  if (status >= 500) return fallback;
  return safeDetail(data?.detail ?? data?.error ?? data?.message, fallback);
};
