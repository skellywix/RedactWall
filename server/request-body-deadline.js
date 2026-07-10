'use strict';

const DEADLINE_EXPIRED = Symbol('redactwall.requestBodyDeadlineExpired');
const DEFAULT_TIMEOUT_MS = 30000;

function boundedTimeoutMs(value, fallback = DEFAULT_TIMEOUT_MS) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(100, Math.min(120000, Math.floor(parsed)));
}

function requestHasBody(req) {
  if (req.headers && req.headers['transfer-encoding']) return true;
  const raw = req.headers && req.headers['content-length'];
  if (raw === undefined || !/^\d+$/.test(String(raw))) return false;
  return Number(raw) > 0;
}

function requestBodyDeadlineExpired(req) {
  return !!(req && req[DEADLINE_EXPIRED]);
}

function holdLateRequestErrors(req) {
  const ignoreError = () => {};
  req.on('error', ignoreError);
  req.once('close', () => req.removeListener('error', ignoreError));
}

function requestBodyDeadline(options = {}) {
  const onTimeout = options.onTimeout || ((_req, res) => res.status(408).json({ error: 'request body deadline exceeded' }));
  return function requestBodyDeadlineMiddleware(req, res, next) {
    if (!requestHasBody(req)) return next();
    const configured = typeof options.timeoutMs === 'function' ? options.timeoutMs(req) : options.timeoutMs;
    const timeoutMs = boundedTimeoutMs(configured, boundedTimeoutMs(options.fallbackMs));
    let timer;
    let active = true;
    const cleanup = () => {
      if (!active) return;
      active = false;
      clearTimeout(timer);
      req.removeListener('end', cleanup);
      req.removeListener('aborted', cleanup);
      req.removeListener('close', cleanup);
    };
    const expire = () => {
      if (!active) return;
      if (req.complete) return cleanup();
      cleanup();
      req[DEADLINE_EXPIRED] = true;
      req.pause();
      holdLateRequestErrors(req);
      if (res.headersSent || res.writableEnded) {
        req.destroy();
        return;
      }
      res.shouldKeepAlive = false;
      res.setHeader('connection', 'close');
      onTimeout(req, res);
    };
    req.once('end', cleanup);
    req.once('aborted', cleanup);
    req.once('close', cleanup);
    timer = setTimeout(expire, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    return next();
  };
}

module.exports = { boundedTimeoutMs, requestBodyDeadline, requestBodyDeadlineExpired };
