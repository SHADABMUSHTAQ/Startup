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

export const formatApiError = (error, fallback = "Request failed. Please try again.") => {
  const data = error?.response?.data;

  return (
    stringifyDetail(data?.detail) ||
    stringifyDetail(data?.error) ||
    stringifyDetail(data?.message) ||
    stringifyDetail(error?.message) ||
    fallback
  );
};

export const formatApiErrorData = (data, fallback = "Request failed. Please try again.") => (
  stringifyDetail(data?.detail) ||
  stringifyDetail(data?.error) ||
  stringifyDetail(data?.message) ||
  fallback
);
