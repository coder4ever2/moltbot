import { describe, expect, test } from "vitest";
import { buildDeviceAuthPayload } from "./device-auth.js";

describe("buildDeviceAuthPayload", () => {
  test("escapes pipe delimiters in all string fields (v1)", () => {
    const payload = buildDeviceAuthPayload({
      deviceId: "device|123",
      clientId: "client|456",
      clientMode: "mode|test",
      role: "user|admin",
      scopes: ["read|write", "execute|delete"],
      signedAtMs: 1234567890,
      token: "tok|en",
      version: "v1",
    });

    // All pipes should be escaped with backslash
    expect(payload).toBe(
      "v1|device\\|123|client\\|456|mode\\|test|user\\|admin|read\\|write,execute\\|delete|1234567890|tok\\|en",
    );
  });

  test("escapes pipe delimiters in all string fields (v2)", () => {
    const payload = buildDeviceAuthPayload({
      deviceId: "device|123",
      clientId: "client|456",
      clientMode: "mode|test",
      role: "user|admin",
      scopes: ["read|write", "execute|delete"],
      signedAtMs: 1234567890,
      token: "tok|en",
      nonce: "non|ce",
      version: "v2",
    });

    // All pipes should be escaped with backslash, including nonce
    expect(payload).toBe(
      "v2|device\\|123|client\\|456|mode\\|test|user\\|admin|read\\|write,execute\\|delete|1234567890|tok\\|en|non\\|ce",
    );
  });

  test("handles empty token and nonce", () => {
    const payload = buildDeviceAuthPayload({
      deviceId: "device123",
      clientId: "client456",
      clientMode: "test",
      role: "user",
      scopes: ["read"],
      signedAtMs: 1234567890,
      token: null,
      nonce: null,
      version: "v2",
    });

    expect(payload).toBe("v2|device123|client456|test|user|read|1234567890||");
  });

  test("handles values containing backslashes", () => {
    const payload = buildDeviceAuthPayload({
      deviceId: "device\\|123",
      clientId: "client",
      clientMode: "test",
      role: "user",
      scopes: ["read"],
      signedAtMs: 1234567890,
      version: "v1",
    });

    // The backslash is kept as-is, only the pipe is escaped
    expect(payload).toContain("device\\\\|123");
  });

  test("preserves normal payload structure without pipes", () => {
    const payload = buildDeviceAuthPayload({
      deviceId: "device123",
      clientId: "client456",
      clientMode: "test",
      role: "user",
      scopes: ["read", "write"],
      signedAtMs: 1234567890,
      token: "token123",
      version: "v1",
    });

    expect(payload).toBe("v1|device123|client456|test|user|read,write|1234567890|token123");
  });

  test("handles multiple pipes in a single field", () => {
    const payload = buildDeviceAuthPayload({
      deviceId: "device",
      clientId: "client",
      clientMode: "test",
      role: "user|||admin",
      scopes: ["read"],
      signedAtMs: 1234567890,
      version: "v1",
    });

    expect(payload).toContain("user\\|\\|\\|admin");
  });
});
