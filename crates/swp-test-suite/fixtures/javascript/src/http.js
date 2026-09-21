"use strict";

// A tiny response-shaping layer. No dependencies, so the fixtures can be
// scanned on a machine with nothing installed.

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRIES = 3;
const OK = 200;
const NOT_FOUND = 404;
const SERVER_ERROR = 500;
const RETRY_AFTER_MS = 1200;

function statusClass(code) {
  if (code >= 200 && code < 300) {
    return "success";
  }
  if (code >= 300 && code < 400) {
    return "redirect";
  }
  if (code >= 400 && code < 500) {
    return "client-error";
  }
  if (code >= 500) {
    return "server-error";
  }
  return "unknown";
}

function isRetryable(code) {
  return code === SERVER_ERROR || code === 503;
}

function retryPlan(attempt) {
  if (attempt >= MAX_RETRIES) {
    return null;
  }
  const backoff = RETRY_AFTER_MS * (attempt + 1);
  if (backoff > DEFAULT_TIMEOUT_MS) {
    return DEFAULT_TIMEOUT_MS;
  }
  return backoff;
}

function buildRequest(path, timeoutMs) {
  return {
    url: "https://example.invalid" + path,
    method: "GET",
    timeout: timeoutMs || DEFAULT_TIMEOUT_MS,
    headers: { accept: "application/json" },
  };
}

function summarize(response) {
  const kind = statusClass(response.code);
  if (kind === "success") {
    return { ok: true, retried: 0 };
  }
  if (response.code === NOT_FOUND) {
    return { ok: false, retried: 0 };
  }
  return { ok: false, retried: MAX_RETRIES };
}

module.exports = {
  statusClass,
  isRetryable,
  retryPlan,
  buildRequest,
  summarize,
  DEFAULT_TIMEOUT_MS,
  OK,
  NOT_FOUND,
  SERVER_ERROR,
};
