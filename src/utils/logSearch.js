export const shouldDisplayLog = (log, query, isLiveMode) => {
  // Historical rows already passed the backend's indexed exact-field search.
  if (!isLiveMode) return true;
  if (["INFO", "LOW"].includes(log.level)) return false;
  return String(log.message || "").toLowerCase().includes(String(query || "").toLowerCase());
};
