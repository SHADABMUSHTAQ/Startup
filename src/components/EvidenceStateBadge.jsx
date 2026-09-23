import React from "react";
import "./EvidenceStateBadge.css";

const OBSERVATION_STATES = new Set(["OBSERVED", "NOT_OBSERVED", "UNVERIFIED"]);
const CLAIM_STATES = new Set(["SUPPORTED", "CONDITIONALLY_SUPPORTED", "UNSUPPORTED"]);

const normalize = (value, type) => {
  const normalized = String(value || "").trim().toUpperCase().replace(/\s+/g, "_");
  if (type === "observation") return OBSERVATION_STATES.has(normalized) ? normalized : "UNVERIFIED";
  return CLAIM_STATES.has(normalized) ? normalized : "UNVERIFIED";
};

export default function EvidenceStateBadge({ type = "observation", state }) {
  const group = type === "claim" ? "claim" : "observation";
  const value = normalize(state, group);
  return <span className={`evidence-state-group evidence-state-group-${group}`}><small>{group === "claim" ? "Compliance / claim" : "Observation"}</small><span className={`evidence-state-badge evidence-state-${value.toLowerCase()}`}>{value.replaceAll("_", " ")}</span></span>;
}
