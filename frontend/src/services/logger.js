// Simple browser-compatible logger
const LOG_LEVELS = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug'
};

class Logger {
  constructor() {
    this.logs = [];
    this.maxLogs = 1000; // Keep last 1000 logs in memory
  }

  _addToLogs(level, message, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data
    };
    this.logs.push(logEntry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift(); // Remove oldest log
    }
  }

  error(message, data = {}) {
    console.error(`[ERROR] ${message}`, data);
    this._addToLogs(LOG_LEVELS.ERROR, message, data);
  }

  warn(message, data = {}) {
    console.warn(`[WARN] ${message}`, data);
    this._addToLogs(LOG_LEVELS.WARN, message, data);
  }

  info(message, data = {}) {
    console.info(`[INFO] ${message}`, data);
    this._addToLogs(LOG_LEVELS.INFO, message, data);
  }

  debug(message, data = {}) {
    if (process.env.NODE_ENV !== 'production') {
      console.debug(`[DEBUG] ${message}`, data);
      this._addToLogs(LOG_LEVELS.DEBUG, message, data);
    }
  }

  logApiRequest(method, url, status, responseTime) {
    this.info('API Request', {
      method,
      url,
      status,
      responseTime: `${responseTime}ms`
    });
  }

  logError(error, context = {}) {
    this.error('Error occurred', {
      message: error.message,
      stack: error.stack,
      ...context
    });
  }

  logUserAction(action, userId, details = {}) {
    this.info('User Action', {
      action,
      userId,
      ...details
    });
  }

  // Get all logs
  getLogs() {
    return this.logs;
  }

  // Clear logs
  clearLogs() {
    this.logs = [];
  }
}

const logger = new Logger();
export default logger; 