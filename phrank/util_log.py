import logging


def get_logger():
	return logging.getLogger("phrank_logger")

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