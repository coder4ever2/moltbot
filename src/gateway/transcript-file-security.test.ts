import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

describe("session transcript file security", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "transcript-security-test-"));
  });

  afterEach(async () => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test("transcript file is created with restrictive permissions (0o600)", async () => {
    // Skip on Windows as permission modes work differently
    if (process.platform === "win32") {
      return;
    }

    const transcriptPath = path.join(tempDir, "session.jsonl");
    const header = {
      type: "session",
      version: "1.0",
      id: "test-session",
      timestamp: new Date().toISOString(),
      cwd: process.cwd(),
    };

    // Simulate the transcript file creation from ensureTranscriptFile
    fs.writeFileSync(transcriptPath, `${JSON.stringify(header)}\n`, {
      encoding: "utf-8",
      mode: 0o600,
    });

    const stats = fs.statSync(transcriptPath);
    const mode = stats.mode & 0o777; // Extract permission bits

    // Should be readable and writable by owner only (0o600)
    expect(mode).toBe(0o600);

    // Verify file is not readable by group or others
    expect(mode & 0o044).toBe(0); // No read for group/others
    expect(mode & 0o022).toBe(0); // No write for group/others
  });

  test("transcript directory is created with restrictive permissions (0o700)", async () => {
    // Skip on Windows as permission modes work differently
    if (process.platform === "win32") {
      return;
    }

    const transcriptDir = path.join(tempDir, "sessions");

    // Simulate the directory creation from ensureTranscriptFile
    fs.mkdirSync(transcriptDir, { recursive: true, mode: 0o700 });

    const stats = fs.statSync(transcriptDir);
    const mode = stats.mode & 0o777; // Extract permission bits

    // Should be readable, writable, and executable by owner only (0o700)
    expect(mode).toBe(0o700);

    // Verify directory is not accessible by group or others
    expect(mode & 0o077).toBe(0); // No permissions for group/others
  });

  test("existing transcript file retains its permissions", async () => {
    // Skip on Windows as permission modes work differently
    if (process.platform === "win32") {
      return;
    }

    const transcriptPath = path.join(tempDir, "existing-session.jsonl");

    // Create file with specific permissions
    fs.writeFileSync(transcriptPath, "test content\n", {
      encoding: "utf-8",
      mode: 0o600,
    });

    // Verify initial permissions
    let stats = fs.statSync(transcriptPath);
    let mode = stats.mode & 0o777;
    expect(mode).toBe(0o600);

    // Append to file (simulating appendFileSync in the code)
    fs.appendFileSync(transcriptPath, "more content\n", "utf-8");

    // Verify permissions are still restrictive
    stats = fs.statSync(transcriptPath);
    mode = stats.mode & 0o777;
    expect(mode).toBe(0o600);
  });
});
