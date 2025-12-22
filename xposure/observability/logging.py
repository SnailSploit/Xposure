"""Structured logging for X-POSURE."""

import json
import logging
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any


class LogLevel(str, Enum):
    """Log levels."""
    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def __init__(
        self,
        include_timestamp: bool = True,
        include_level: bool = True,
        include_logger: bool = True,
        extra_fields: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize JSON formatter.

        Args:
            include_timestamp: Include timestamp in output
            include_level: Include log level in output
            include_logger: Include logger name in output
            extra_fields: Extra fields to include in every log
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_level = include_level
        self.include_logger = include_logger
        self.extra_fields = extra_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {}

        if self.include_timestamp:
            log_data['timestamp'] = datetime.now(timezone.utc).isoformat()

        if self.include_level:
            log_data['level'] = record.levelname.lower()

        if self.include_logger:
            log_data['logger'] = record.name

        log_data['message'] = record.getMessage()

        # Add extra fields from record
        if hasattr(record, 'extra'):
            log_data.update(record.extra)

        # Add any exception info
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add static extra fields
        log_data.update(self.extra_fields)

        # Add any additional attributes set on the record
        for key, value in record.__dict__.items():
            if key not in (
                'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                'filename', 'module', 'lineno', 'funcName', 'created',
                'msecs', 'relativeCreated', 'thread', 'threadName',
                'processName', 'process', 'message', 'exc_info', 'exc_text',
                'stack_info', 'extra'
            ):
                if not key.startswith('_'):
                    log_data[key] = value

        return json.dumps(log_data, default=str)


class ContextLogger(logging.LoggerAdapter):
    """Logger adapter that adds context to all log messages."""

    def __init__(self, logger: logging.Logger, context: Optional[Dict[str, Any]] = None):
        """
        Initialize context logger.

        Args:
            logger: Base logger
            context: Context to add to all messages
        """
        super().__init__(logger, context or {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log message and add context."""
        extra = kwargs.get('extra', {})
        extra.update(self.extra)
        kwargs['extra'] = extra
        return msg, kwargs

    def with_context(self, **context) -> 'ContextLogger':
        """Create new logger with additional context."""
        new_context = {**self.extra, **context}
        return ContextLogger(self.logger, new_context)


# Global loggers registry
_loggers: Dict[str, ContextLogger] = {}
_json_mode: bool = False
_log_level: int = logging.INFO


def setup_logging(
    level: LogLevel = LogLevel.INFO,
    json_format: bool = False,
    log_file: Optional[str] = None,
    extra_fields: Optional[Dict[str, Any]] = None,
):
    """
    Setup logging configuration.

    Args:
        level: Log level
        json_format: Use JSON format for logs
        log_file: Optional file to write logs to
        extra_fields: Extra fields to include in JSON logs
    """
    global _json_mode, _log_level

    _json_mode = json_format
    _log_level = getattr(logging, level.value.upper())

    # Configure root logger
    root_logger = logging.getLogger('xposure')
    root_logger.setLevel(_log_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create handlers
    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(_log_level)

    if json_format:
        console_handler.setFormatter(JSONFormatter(extra_fields=extra_fields))
    else:
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

    handlers.append(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(_log_level)

        if json_format:
            file_handler.setFormatter(JSONFormatter(extra_fields=extra_fields))
        else:
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            ))

        handlers.append(file_handler)

    # Add handlers
    for handler in handlers:
        root_logger.addHandler(handler)


def get_logger(
    name: str = 'xposure',
    context: Optional[Dict[str, Any]] = None,
) -> ContextLogger:
    """
    Get a logger instance.

    Args:
        name: Logger name
        context: Optional context to add to all messages

    Returns:
        Context logger instance
    """
    if name not in _loggers:
        base_logger = logging.getLogger(name)
        _loggers[name] = ContextLogger(base_logger, context or {})

    return _loggers[name]


# Convenience functions for structured logging
def log_finding(
    finding_id: str,
    credential_type: str,
    severity: str,
    source: Optional[str] = None,
    **extra,
):
    """Log a finding event."""
    logger = get_logger('xposure.findings')
    logger.info(
        f'Finding detected: {credential_type}',
        extra={
            'event': 'finding.detected',
            'finding_id': finding_id,
            'credential_type': credential_type,
            'severity': severity,
            'source': source,
            **extra,
        }
    )


def log_verification(
    finding_id: str,
    status: str,
    method: str,
    duration_ms: Optional[float] = None,
    **extra,
):
    """Log a verification event."""
    logger = get_logger('xposure.verification')
    logger.info(
        f'Verification: {status}',
        extra={
            'event': 'verification.completed',
            'finding_id': finding_id,
            'status': status,
            'method': method,
            'duration_ms': duration_ms,
            **extra,
        }
    )


def log_scan_event(
    scan_id: str,
    event: str,
    target: Optional[str] = None,
    **extra,
):
    """Log a scan event."""
    logger = get_logger('xposure.scan')
    logger.info(
        f'Scan {event}',
        extra={
            'event': f'scan.{event}',
            'scan_id': scan_id,
            'target': target,
            **extra,
        }
    )


def log_error(
    error: Exception,
    context: Optional[str] = None,
    **extra,
):
    """Log an error event."""
    logger = get_logger('xposure.errors')
    logger.error(
        f'Error: {str(error)}',
        extra={
            'event': 'error',
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            **extra,
        },
        exc_info=True,
    )
