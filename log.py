import logging
import logging.handlers
import datetime

import time

import os


class Log:

    def __init__(self, logger_name, adir, filename):
        t = time.gmtime()
        date = time.strftime('%Y%m', t)
        dir = adir + date
        if os.path.exists(dir) == False:
            os.makedirs(dir)
        date = time.strftime('%d', t)
        dir = dir + "/" + date
        if os.path.exists(dir) == False:
            os.makedirs(dir)
        if os.path.exists(dir + filename) == False:
            os.mknod(dir + filename)
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            f_handler = logging.FileHandler(dir + "/" + filename)
            f_handler.setLevel(logging.INFO)
            f_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s - %(message)s"))
            self.logger.addHandler(f_handler)

    def debug(self, m):
        self.logger.debug(m)

    def info(self, m):
        self.logger.info(m)

    def warning(self, m):
        self.logger.warning(m)

    def error(self, m):
        self.logger.error(m)
