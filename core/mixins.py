from functools import wraps
from BackEnd.db_retries import retry_database_operation

class DatabaseRetryMixin:
    """Mixin that adds retry capability to class-based views."""
    
    def dispatch(self, request, *args, **kwargs):
        # Wrap the dispatch method with our retry decorator
        wrapped_dispatch = retry_database_operation()(super().dispatch)
        return wrapped_dispatch(request, *args, **kwargs)

