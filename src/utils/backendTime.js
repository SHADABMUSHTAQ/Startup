export const parseBackendTime = (value) => {
  if (!value) return null;
  // Mongo-backed API timestamps without an offset represent UTC, not browser time.
  const text = String(value);
  const utcValue = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(text) ? `${text}Z` : text;
  const date = new Date(utcValue);
  return Number.isFinite(date.getTime()) ? date : null;
};

export const formatBackendTime = (value, dateOnly = false) => {
  const date = parseBackendTime(value);
  return date ? dateOnly ? date.toLocaleDateString() : date.toLocaleString() : "Not recorded";
};
