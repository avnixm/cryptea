"""Application logging utilities."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .data_paths import log_dir

_LOG_FILE_NAME = "ctf-helper.log"


def configure_logging() -> logging.Logger:
    """Configure a rotating log file in the user data directory."""
    logger = logging.getLogger("ctf_helper")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    log_directory: Path = log_dir()
    handler = RotatingFileHandler(
        log_directory / _LOG_FILE_NAME,
        maxBytes=1_048_576,
        backupCount=5,
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.info("Logger initialised; logs available at %s", handler.baseFilename)
    return logger
