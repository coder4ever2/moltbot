export type DeviceAuthPayloadParams = {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token?: string | null;
  nonce?: string | null;
  version?: "v1" | "v2";
};

/**
 * Escapes the pipe delimiter character to prevent injection attacks.
 * Pipes in field values could otherwise be used to inject additional fields.
 */
function escapeDelimiter(value: string): string {
  return value.replace(/\|/g, "\\|");
}

export function buildDeviceAuthPayload(params: DeviceAuthPayloadParams): string {
  const version = params.version ?? (params.nonce ? "v2" : "v1");
  // Escape pipes in individual scopes before joining with comma
  const scopes = params.scopes.map(escapeDelimiter).join(",");
  const token = params.token ?? "";
  const base = [
    escapeDelimiter(version),
    escapeDelimiter(params.deviceId),
    escapeDelimiter(params.clientId),
    escapeDelimiter(params.clientMode),
    escapeDelimiter(params.role),
    scopes,
    String(params.signedAtMs), // numeric, no escaping needed
    escapeDelimiter(token),
  ];
  if (version === "v2") {
    base.push(escapeDelimiter(params.nonce ?? ""));
  }
  return base.join("|");
}
