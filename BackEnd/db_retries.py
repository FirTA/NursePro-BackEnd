import time
import logging
from functools import wraps
from django.db.utils import OperationalError, InterfaceError

logger = logging.getLogger(__name__)

def retry_database_operation(max_attempts = 3, backoff_factor = 0.5):
    """
    Decorator to retry database operations that fail with connection errors.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 1
            last_error = None
            
            while attempt <= max_attempts:
                try:
                    return func(*args, **kwargs)
                except (OperationalError, InterfaceError) as e:
                    last_error = e
                    wait_time = backoff_factor * (2 ** (attempt - 1))
                    logger.warning(
                        f"Database connection error on attempt {attempt}/{max_attempts}. "
                        f"Retrying in {wait_time:.2f}s. Error: {str(e)}"
                    )
                    time.sleep(wait_time)
                    attempt += 1
            
            # If we get here, all retries failed
            logger.error(f"All {max_attempts} database connection attempts failed. Last error: {str(last_error)}")
            raise last_error
            
        return wrapper
    return decorator