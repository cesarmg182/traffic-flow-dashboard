import os
import sys
import logging
import gzip

from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import Union

DEFAULT_LOGGER_FORMAT = "%(asctime)s:%(levelname)s: %(message)s"
DEFAULT_FILE_LOGGER_FORMAT = "%(asctime)s [%(process)d:%(levelname)s] %(module)s.%(funcName)s.%(lineno)d: %(message)s"
DEFAULT_LOGGING_LEVEL = logging.INFO

IS_WINDOWS = sys.platform.startswith('win')

if not IS_WINDOWS:
    import fcntl


class Logger(object):
    def __init__(self, logger_name=None, log_level=DEFAULT_LOGGING_LEVEL, color_logger: bool = False,
                 log_file_path: Union[Path, str] = None, logger_format=DEFAULT_LOGGER_FORMAT):
        """
        Initiate a logger
        :param logger_name: The loggers name
        :param log_level: The log level
        :param log_file_path: If specified, log also to a file in log_file_path. If log_file_path contains '*' sign,
        replace it with the current time
        :param color_logger: Whether to color the logs according to the log level
        :param logger_format: Override the default logger format
        :return: A logger object
        """
        handler = logging.StreamHandler(stream=sys.stdout)
        if color_logger:
            formatter = ColoredFormatter(logger_format, full_line_color=True)
        else:
            formatter = logging.Formatter(logger_format)
        handler.setFormatter(formatter)
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(log_level)
        self.logger.addHandler(handler)
        if log_file_path:
            fh = logging.FileHandler(Path(log_file_path))
            fh.setLevel(log_level)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def setLevel(self, log_level):
        self.logger.setLevel(log_level)

    def info(self, text):
        """write new log info level"""
        self.logger.info(text)

    def warning(self, text):
        """write new log warning level"""
        self.logger.warning(text)

    def error(self, text):
        """write new log critical level"""
        self.logger.error(text)

    def debug(self, text):
        """write new log debug level"""
        self.logger.debug(text)


class ColoredFormatter(logging.Formatter):
    """class ColoredFormatter(Formatter)
    A color formatter to support color logging.
    """

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
    COLORS = {'WARNING': YELLOW,
              'INFO': WHITE,
              'ERROR': RED,
              'DEBUG': MAGENTA
              }
    RESET_SEQ = "\033[0m"
    COLOR_SEQ = "\033[1;%dm"
    BOLD_SEQ = "\033[1m"

    def __init__(self, fmt, full_line_color=False):
        logging.Formatter.__init__(self, fmt)

        if full_line_color:
            self.format = self._format_full_line_color
        else:
            self.format = self._format

    def _format_full_line_color(self, record):
        levelname = record.levelname

        if levelname in ColoredFormatter.COLORS:
            return ColoredFormatter.COLOR_SEQ % (30 + ColoredFormatter.COLORS[levelname]) + super(ColoredFormatter,
                                                                                                  self).format(
                record) + ColoredFormatter.RESET_SEQ

        return super(ColoredFormatter, self).format(record)

    def _format(self, record):
        levelname = record.levelname

        if levelname in ColoredFormatter.COLORS:
            levelname_color = ColoredFormatter.COLOR_SEQ % (
                30 + ColoredFormatter.COLORS[levelname]) + levelname + ColoredFormatter.RESET_SEQ
            record.levelname = levelname_color

        return super(ColoredFormatter, self).format(record)


class RotatingFileLogger(object):
    """ Rotating file logger for linux servers. Copied from the devops repository """
    def __init__(self, logging_app_name="LOG_APP",
                 log_file_name="LOG_NAME",
                 log_level=DEFAULT_LOGGING_LEVEL,
                 attach_handler_to_root_logger: bool = False):
        logging.basicConfig(level=log_level, format=DEFAULT_LOGGER_FORMAT)
        self.logging_app_name = logging_app_name
        self.log_file_path = None
        self.logger = logging.getLogger(logging_app_name)
        if not IS_WINDOWS:
            self.set_log_file(logging_app_name, log_file_name)
            self.set_handler(logging_app_name=logging_app_name,
                             attach_handler_to_root_logger=attach_handler_to_root_logger)

    def set_handler(self, log_file_name=None, logging_app_name=None, attach_handler_to_root_logger=False):
        """ setting handler to the logger """
        if self.logger.handlers:
            self.close()
        if not logging_app_name:
            logging_app_name = self.logging_app_name
        if log_file_name:
            self.set_log_file(logging_app_name=logging_app_name, log_file_name=log_file_name)
        handler = CompressedRotatingFileHandler(self.log_file_path, maxBytes=100000000, backupCount=10)
        formatter = logging.Formatter(DEFAULT_FILE_LOGGER_FORMAT)
        handler.setFormatter(formatter)
        logging.FileHandler(self.log_file_path)
        self.logger = logging.getLogger(logging_app_name)
        if attach_handler_to_root_logger:
            logging.getLogger().addHandler(handler)
        else:
            self.logger.addHandler(handler)

    def set_log_file(self, logging_app_name, log_file_name):
        os.system("mkdir -p /var/log/%s" % logging_app_name)
        self.log_file_path = "/var/log/%s/%s.log" % (logging_app_name, log_file_name)

    def setLevel(self, log_level):
        self.logger.setLevel(log_level)

    def info(self, text, **kwargs):
        """write new log info level"""
        self.logger.info(text, **kwargs)

    def warning(self, text, **kwargs):
        """write new log warning level"""
        self.logger.warning(text, **kwargs)

    def error(self, text, **kwargs):
        """write new log error level"""
        self.logger.error(text, **kwargs)

    def critical(self, text, **kwargs):
        """write new log critical level"""
        self.logger.critical(text, **kwargs)

    def debug(self, text, **kwargs):
        """write new log debug level"""
        self.logger.debug(text, **kwargs)

    def close(self):
        """ close the handlers. useful to prevent OOM while running logger inside as part of a service. """
        handlers = self.logger.handlers[:]
        for handler in handlers:
            handler.close()
            self.logger.removeHandler(handler)


class CompressedRotatingFile(object):
    """ Compress rotated file. Copied from Centra logging module """
    READ_BUFFER_SIZE = 1024 * 1024  # 1MB

    def __init__(self, filename):
        self.filename = filename

    def do_rollover(self, output_compress_file):
        if os.path.exists(output_compress_file):
            os.remove(output_compress_file)

        if os.path.exists(self.filename):
            # compress the file
            with open(self.filename, "rb") as unpacked, gzip.GzipFile(output_compress_file, "wb") as packed:
                while True:
                    chunk = unpacked.read(self.READ_BUFFER_SIZE)
                    if not chunk:
                        break
                    packed.write(chunk)

            # remove origin file
            try:
                os.remove(self.filename)
            except:
                pass

    def do_index_rollover(self, index):
        output_compress_file = self.filename + ".%d.gz" % index
        self.do_rollover(output_compress_file)


class CompressedRotatingFileHandler(RotatingFileHandler):
    """Class CompressedRotatingFileHandler(RotatingFileHandler)

    Extended version of RotatingFileHandler which compress the rotated
    file using gzip on each roll-over.
    """

    def __init__(self, filename, *args, **kwargs):
        super(CompressedRotatingFileHandler, self).__init__(filename, *args, **kwargs)
        self.file_compressor = CompressedRotatingFile(filename)

    def _open(self):
        stream = super(CompressedRotatingFileHandler, self)._open()

        # if possible, force the logger stream to be closed inside sub-processes to avoid
        # unnecessary fd leakage.
        if not IS_WINDOWS and getattr(stream, "fileno", None) is not None:
            fcntl.fcntl(stream.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)

        return stream

    def doRollover(self):
        """
        Do a rollover, as described in __init__().
        """
        if self.stream:
            self.stream.close()
            self.stream = None

        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = "%s.%d.gz" % (self.baseFilename, i)
                dfn = "%s.%d.gz" % (self.baseFilename, i + 1)
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            dfn = self.baseFilename + ".1.gz"

            # Issue 18940: A file may not have been created if delay is True.
            self.file_compressor.do_rollover(dfn)
        if not getattr(self, 'delay', False):
            self.stream = self._open()
