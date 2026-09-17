"""Logging configuration shared by the whole app. Powers the Console page."""
import logging
from logging.handlers import RotatingFileHandler


def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("oxysintx")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger  # already configured (e.g. reloader re-import)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger
