import logging
from enum import Enum

LOG_FORMAT_DEBUG = "%(levelname)s:%(message)s:%(pathname)s:%(funcName)s:%(lineno)d"


class LogLevels(str, Enum):
    info = "INFO"
    warn = "WARN"
    error = "ERROR"
    debug = "DEBUG"


def configure_logging(log_level: str = LogLevels.error):
    log_level_str = str(log_level).upper()
    log_levels = [level.value for level in LogLevels]

    if log_level_str not in log_levels:
        logging.basicConfig(level=LogLevels.error.value)
        return

    if log_level_str == LogLevels.debug.value:
        logging.basicConfig(level=log_level_str, format=LOG_FORMAT_DEBUG)
        return

    logging.basicConfig(level=log_level_str)
