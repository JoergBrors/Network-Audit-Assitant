export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogRecord {
  ts: string;
  level: LogLevel;
  event: string;
  [field: string]: unknown;
}

export type LogSink = (record: LogRecord) => void;

export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const SENSITIVE_KEY =
  /authorization|token|secret|password|passwd|sharedkey|\bkey\b|apikey|connectionstring|sas|signature|cookie|credential/i;
const SENSITIVE_VALUE = /(bearer\s+[\w\-.~+/]+=*)|(eyJ[\w-]+\.[\w-]+\.[\w-]+)|([?&]sig=[^&\s]+)/gi;
const REDACTED = "[REDACTED]";

/** Recursively removes values whose key or content looks like a credential. Never mutates the input. */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[TRUNCATED]";
  if (typeof value === "string") return value.replace(SENSITIVE_VALUE, REDACTED);
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value instanceof Error) {
    return { name: value.name, message: redact(value.message, depth + 1) };
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function jsonLinesSink(write: (line: string) => void): LogSink {
  return (record) => write(JSON.stringify(record));
}

export function consoleSink(): LogSink {
  return (record) => {
    const { level, event, ...rest } = record;
    const method = level === "debug" ? "debug" : level;
    console[method](`[${event}]`, rest);
  };
}

export function createLogger(options: {
  sink: LogSink;
  level?: LogLevel;
  fields?: Record<string, unknown>;
  now?: () => Date;
}): Logger {
  const minLevel = LEVEL_ORDER[options.level ?? "info"];
  const base = options.fields ?? {};
  const now = options.now ?? (() => new Date());

  const emit = (level: LogLevel, event: string, fields?: Record<string, unknown>): void => {
    if (LEVEL_ORDER[level] < minLevel) return;
    const safe = redact({ ...base, ...fields }) as Record<string, unknown>;
    options.sink({ ...safe, ts: now().toISOString(), level, event });
  };

  return {
    debug: (event, fields) => emit("debug", event, fields),
    info: (event, fields) => emit("info", event, fields),
    warn: (event, fields) => emit("warn", event, fields),
    error: (event, fields) => emit("error", event, fields),
    child: (fields) => createLogger({ ...options, fields: { ...base, ...fields } }),
  };
}

export const silentLogger: Logger = createLogger({ sink: () => undefined, level: "error" });
