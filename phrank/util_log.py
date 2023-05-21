import logging


def get_logger():
	return logging.getLogger("phrank_logger")

def set_log_debug():
	logger = get_logger()
	for h in logger.handlers:
		h.setLevel(logging.DEBUG)
	logger.setLevel(logging.DEBUG)

def set_log_info():
	logger = get_logger()
	for h in logger.handlers:
		h.setLevel(logging.INFO)
	logger.setLevel(logging.INFO)

def set_log_warn():
	logger = get_logger()
	for h in logger.handlers:
		h.setLevel(logging.WARNING)
	logger.setLevel(logging.WARNING)

def set_log_err():
	logger = get_logger()
	for h in logger.handlers:
		h.setLevel(logging.ERROR)
	logger.setLevel(logging.ERROR)

def set_log_critical():
	logger = get_logger()
	for h in logger.handlers:
		h.setLevel(logging.CRITICAL)
	logger.setLevel(logging.CRITICAL)

def log_debug(msg:str):
	get_logger().debug(msg)

def log_info(msg:str):
	get_logger().info(msg)

def log_warn(msg:str):
	get_logger().warning(msg)

def log_err(msg:str):
	get_logger().error(msg)

def log_critical(msg:str):
	get_logger().critical(msg)