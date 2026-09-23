const text = (value) => String(value ?? "").trim();

const first = (...values) => values.map(text).find(Boolean) || "";

const vendorLabel = (value) => {
  const vendor = text(value).toLowerCase();
  return {
    pfsense: "pfSense",
    fortinet: "Fortinet",
    cisco_asa: "Cisco ASA",
    mikrotik: "MikroTik",
  }[vendor] || text(value) || "Firewall";
};

const endpoint = (address, port) => {
  const host = text(address);
  const service = text(port);
  if (!host) return "";
  if (!service) return host;
  return host.includes(":") ? `[${host}]:${service}` : `${host}:${service}`;
};

const isGenericNetworkMessage = (value) => {
  const message = text(value);
  return !message
    || /^security telemetry event net-[\w-]+ observed$/i.test(message)
    || /^windows event net-[\w-]+$/i.test(message)
    || /^endpoint telemetry$/i.test(message)
    || /^pfsense firewall (?:block|pass|allow|deny)(?: (?:in|out))?$/i.test(message)
    || /^unknown event$/i.test(message);
};

const networkMessage = (record, context, vendor) => {
  const eventType = first(record.event_type, context.event_type).toLowerCase();
  const actionValue = first(context.action, record.action).toLowerCase();
  const blocked = eventType === "network_connection_blocked"
    || ["block", "blocked", "deny", "denied", "drop", "dropped"].includes(actionValue);
  const permitted = eventType === "network_connection_permitted"
    || ["pass", "passed", "allow", "allowed", "accept", "accepted"].includes(actionValue);
  const action = blocked ? "blocked" : permitted ? "allowed" : "observed";
  const protocol = first(context.protocol, record.protocol).toUpperCase();
  const source = endpoint(
    first(context.source_address, record.source_ip, record.src_ip),
    first(context.source_port, record.source_port, record.src_port),
  );
  const destination = endpoint(
    first(context.destination_address, record.destination_ip, record.dst_ip),
    first(context.destination_port, record.destination_port, record.dst_port),
  );
  const route = `${source ? ` from ${source}` : ""}${destination ? ` to ${destination}` : ""}`;
  const directionValue = first(context.direction, record.direction).toLowerCase();
  const direction = { in: "inbound", out: "outbound" }[directionValue] || directionValue;
  const rule = first(context.rule_name, context.rule_label, context.rule_id, record.rule_name, record.rule_id);
  const networkInterface = first(context.interface, record.interface, record.interface_in, record.interface_out);
  const qualifiers = [
    direction,
    rule ? `rule ${rule}` : "",
    networkInterface ? `interface ${networkInterface}` : "",
  ].filter(Boolean);

  return `${vendor} ${action}${protocol ? ` ${protocol}` : ""} traffic${route}${qualifiers.length ? ` (${qualifiers.join(", ")})` : ""}`;
};

export const formatSecurityEvent = (record = {}) => {
  const context = record.context && typeof record.context === "object" ? record.context : {};
  const eventId = first(record.event_id, record.eventId, context.event_id);
  const isNetworkDevice = text(record.source_type).toLowerCase() === "network_device"
    || Boolean(first(record.network_vendor, context.network_vendor))
    || eventId.toUpperCase().startsWith("NET-");
  const suppliedMessage = first(
    record.display_message,
    record.summary,
    record.message,
    record.title,
  );

  if (!isNetworkDevice) {
    return {
      message: first(record.event_id_meaning, suppliedMessage, eventId ? `Windows Event ${eventId}` : "Endpoint telemetry"),
      host: first(record.computer, record.hostname, record.agent_id, context.endpoint, "Unknown endpoint"),
      sourceIp: first(context.source_address, record.source_ip, record.ip, "N/A"),
      sourceType: first(record.telemetry_family, record.engine_source, record.source_type, "WINDOWS"),
      isNetworkDevice: false,
    };
  }

  const vendor = vendorLabel(first(record.network_vendor, context.network_vendor));
  return {
    message: isGenericNetworkMessage(suppliedMessage)
      ? networkMessage(record, context, vendor)
      : suppliedMessage,
    host: first(
      record.network_device_id,
      context.network_device_id,
      record.source_id,
      context.endpoint,
      record.agent_id,
      "Unknown network device",
    ),
    sourceIp: first(context.source_address, record.source_ip, record.ip, "N/A"),
    sourceType: vendor.toUpperCase(),
    isNetworkDevice: true,
  };
};
