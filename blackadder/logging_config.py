"""
Logging configuration for Blackadder.

Sets up structured logging with appropriate levels and formatters.
"""

import logging
import sys
from pathlib import Path

# Fields present on every LogRecord — never treat these as "extra"
_STANDARD_LOG_FIELDS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",  # added by Formatter.format() itself
    "asctime",  # added by Formatter.formatTime()
    "taskName",  # added in Python 3.12+
}


class _ExtraFormatter(logging.Formatter):
    """Formatter that appends key=value pairs from logger.debug(..., extra={...})."""

    def __init__(self, fmt: str, datefmt: str | None = None):
        super().__init__(fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _STANDARD_LOG_FIELDS and not k.startswith("_")
        }
        if extras:
            pairs = " ".join(f"{k}={v!r}" for k, v in extras.items())
            return f"{base}  {pairs}"
        return base


def setup_logging(log_level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """
    Set up logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file (if None, logs to stderr)

    Returns:
        Configured logger instance
    """
    # Get root logger
    logger = logging.getLogger("blackadder")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create formatters
    detailed_formatter = _ExtraFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    simple_formatter = _ExtraFormatter("%(levelname)s: %(message)s")

    # Console handler (always stderr, always simple format)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(logging.DEBUG)  # File gets everything
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not set up file logging: {e}")

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"blackadder.{name}")


# Module-level loggers for key components
logger = logging.getLogger("blackadder")
parser_logger = logging.getLogger("blackadder.parser")
db_logger = logging.getLogger("blackadder.db")
analyzer_logger = logging.getLogger("blackadder.analyzer")
cli_logger = logging.getLogger("blackadder.cli")
