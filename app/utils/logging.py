import logging
from enum import Enum

LOG_FORMAT_DEBUG = (
    "%(asctime)s %(levelname)s:%(message)s:%(pathname)s:%(funcName)s:%(lineno)d"
)
LOG_FORMAT_SIMPLE = "%(asctime)s %(levelname)s:%(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class LogLevels(str, Enum):
    info = "INFO"
    warn = "WARN"
    error = "ERROR"
    debug = "DEBUG"


def configure_logging(log_level: str | LogLevels = LogLevels.error):
    if isinstance(log_level, LogLevels):
        level_name = log_level.value.upper()
    else:
        level_name = str(log_level).upper()

    if level_name == "WARN":
        level_name = "WARNING"

    valid_levels = {"CRITICAL", "FATAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
    if level_name not in valid_levels:
        level_name = "ERROR"

    logging.basicConfig(
        level=level_name,
        format=LOG_FORMAT_DEBUG if level_name == "DEBUG" else LOG_FORMAT_SIMPLE,
        datefmt=DATE_FORMAT,
        force=True,
    )
