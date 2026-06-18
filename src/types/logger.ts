// =============================================================================
// Logger interface — minimal contract the SDK uses for diagnostics.
//
// We don't depend on winston/pino/etc. The caller injects any logger that
// has the standard .debug/.info/.warn/.error shape. NestJS's `Logger`
// satisfies this out of the box; so does a console-based stub for tests.
// =============================================================================

export interface Logger {
  debug(obj: Record<string, unknown>, msg?: string): void;
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
}

/**
 * Silent logger — for tests and the SDK's own internal use. Replace with
 * a real logger in production via the factory option.
 */
export const silentLogger: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

/**
 * Console-based logger — for local dev / scripts. NestJS services inject
 * the platform logger instead.
 */
export const consoleLogger: Logger = {
  debug: (obj, msg) => console.debug(JSON.stringify({ level: 'debug', ...obj, msg })),
  info: (obj, msg) => console.info(JSON.stringify({ level: 'info', ...obj, msg })),
  warn: (obj, msg) => console.warn(JSON.stringify({ level: 'warn', ...obj, msg })),
  error: (obj, msg) =>
    console.error(JSON.stringify({ level: 'error', ...obj, msg })),
};
