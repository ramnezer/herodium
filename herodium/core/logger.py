import logging
import logging.handlers
import os
import sys

# ==============================================================================
# Herodium Logger Module
# Handles internal log rotation and formatting.
# English comments provided for clarity.
# ==============================================================================

def setup_logger(log_file_path, level_name="INFO"):
    """
    Configures the logging system with internal rotation and console output.
    
    Args:
        log_file_path (str): Path to the log file.
        level_name (str): Logging level (DEBUG, INFO, WARNING, ERROR).
    
    Returns:
        logger: A configured logger instance.
    """
    
    # Create the directory for logs if it doesn't exist
    log_dir = os.path.dirname(log_file_path)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            print(f"CRITICAL ERROR: Cannot create log directory at {log_dir}. Run as root.")
            sys.exit(1)

    # Convert string level to logging constant
    level = getattr(logging, level_name.upper(), logging.INFO)

    logger = logging.getLogger("Herodium")
    logger.setLevel(level)

    # Clean existing handlers to avoid duplicate logs if re-initialized
    if logger.hasHandlers():
        logger.handlers.clear()

    # Format: Time - Module - [Level] - Message
    formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')

    # 1. File Handler (Internal Rotating Backup)
    # Change: We set maxBytes to 5MB and backupCount to 3.
    # This acts as a first line of defense before the system's logrotate (daily) kicks in.
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path, maxBytes=5*1024*1024, backupCount=3
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except PermissionError:
        print(f"CRITICAL ERROR: Cannot write to log file {log_file_path}. Permission denied.")

    # 2. Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
