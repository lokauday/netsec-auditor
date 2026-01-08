"""
Request logging middleware for production error tracking.
"""
import time
import uuid
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests with trace_id, latency, and error details."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate trace_id for this request
        trace_id = str(uuid.uuid4())
        request.state.trace_id = trace_id
        
        # Record start time
        start_time = time.time()
        
        # Process request
        try:
            response = await call_next(request)
            latency_ms = int((time.time() - start_time) * 1000)
            
            # Log request details
            status_code = response.status_code
            log_level = logging.WARNING if status_code >= 400 else logging.INFO
            
            logger.log(
                log_level,
                f"[{trace_id}] {request.method} {request.url.path} -> {status_code} ({latency_ms}ms)"
            )
            
            # For 4xx/5xx errors, try to log response body if safe
            if status_code >= 400:
                try:
                    # Read response body (if it's a JSON response)
                    if hasattr(response, 'body') and response.body:
                        # Response body is bytes, decode if possible
                        try:
                            body_str = response.body.decode('utf-8')
                            if len(body_str) < 1000:  # Only log if reasonable size
                                logger.warning(
                                    f"[{trace_id}] Error response body: {body_str[:500]}"
                                )
                        except Exception:
                            pass  # Skip if can't decode
                except Exception:
                    pass  # Skip if can't read body
            
            # Add trace_id to response headers (for debugging)
            response.headers["X-Trace-ID"] = trace_id
            
            return response
            
        except Exception as exc:
            # Unhandled exception during request processing
            latency_ms = int((time.time() - start_time) * 1000)
            logger.error(
                f"[{trace_id}] {request.method} {request.url.path} -> EXCEPTION after {latency_ms}ms: {exc}",
                exc_info=True
            )
            # Re-raise to let global exception handler deal with it
            raise

