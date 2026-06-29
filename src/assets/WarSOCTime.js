const DEFAULT_TIME_OPTIONS = {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
};

function detectBrowserTimeZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

function parseUtcTimestamp(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === "number") {
    const numericDate = new Date(value);
    return Number.isNaN(numericDate.getTime()) ? null : numericDate;
  }

  const raw = String(value).trim();
  if (!raw) {
    return null;
  }

  const hasTimeZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(raw);
  const normalized = !hasTimeZone && raw.includes("T") ? `${raw}Z` : raw;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatLocal(value, formatter, fallback = "N/A") {
  const parsed = parseUtcTimestamp(value);
  if (!parsed) {
    return value === null || value === undefined || value === "" ? fallback : String(value);
  }

  try {
    return formatter(parsed);
  } catch {
    return String(value);
  }
}

function toLocalDateTime(value, fallback = "N/A") {
  return formatLocal(
    value,
    (date) => date.toLocaleString([], { timeZone: detectBrowserTimeZone() }),
    fallback
  );
}

function toLocalDate(value, fallback = "N/A") {
  return formatLocal(
    value,
    (date) => date.toLocaleDateString([], { timeZone: detectBrowserTimeZone() }),
    fallback
  );
}

function toLocalTime(value, fallback = "N/A", options) {
  const formatOptions = options
    ? { ...options, timeZone: detectBrowserTimeZone() }
    : { ...DEFAULT_TIME_OPTIONS, timeZone: detectBrowserTimeZone() };

  return formatLocal(
    value,
    (date) => date.toLocaleTimeString([], formatOptions),
    fallback
  );
}

function nowLocalDateTime() {
  return toLocalDateTime(new Date());
}

export const WarSOCTime = {
  detectBrowserTimeZone,
  parseUtcTimestamp,
  toLocalDateTime,
  toLocalDate,
  toLocalTime,
  nowLocalDateTime,
};
