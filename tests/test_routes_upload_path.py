"""
Route introspection tests to verify upload endpoint matches UI expectations.

This test ensures that the FastAPI route registry contains the exact route
that the Streamlit UI calls, preventing path/method mismatches.
"""
import pytest
from fastapi.routing import APIRoute
from app.main import app


def test_upload_route_exists_for_ui_path():
    """
    Verify that the upload route exists with the exact path and method the UI uses.
    
    The Streamlit UI calls: POST /api/v1/upload/ (with trailing slash)
    This test ensures that route exists in FastAPI's route registry.
    """
    # Get all APIRoute instances
    routes = [r for r in app.routes if isinstance(r, APIRoute)]
    
    # The UI calls POST /api/v1/upload/ (with trailing slash)
    expected_path = "/api/v1/upload/"
    
    # Find routes matching the expected path
    target_routes = [r for r in routes if r.path == expected_path]
    
    assert target_routes, (
        f"No route found for {expected_path}. "
        f"Available upload routes: {[(r.path, list(r.methods)) for r in routes if 'upload' in r.path.lower()]}"
    )
    
    # Verify at least one route accepts POST
    post_routes = [r for r in target_routes if "POST" in r.methods]
    assert post_routes, (
        f"Route {expected_path} exists but does not accept POST method. "
        f"Available methods: {[list(r.methods) for r in target_routes]}"
    )
    
    # Verify the route handler is the upload function
    upload_route = post_routes[0]
    assert upload_route.endpoint.__name__ == "upload_config_file", (
        f"Route handler is {upload_route.endpoint.__name__}, expected 'upload_config_file'"
    )


def test_upload_route_no_conflicting_methods():
    """
    Verify that the upload route doesn't have conflicting method definitions.
    
    There should be exactly one POST handler for /api/v1/upload/
    """
    routes = [r for r in app.routes if isinstance(r, APIRoute)]
    upload_routes = [r for r in routes if r.path == "/api/v1/upload/"]
    
    # Should have exactly one route
    assert len(upload_routes) == 1, (
        f"Expected exactly one route for /api/v1/upload/, found {len(upload_routes)}: "
        f"{[(r.path, list(r.methods), r.endpoint.__name__) for r in upload_routes]}"
    )
    
    upload_route = upload_routes[0]
    
    # Should only accept POST (not GET, PUT, DELETE, etc.)
    assert upload_route.methods == {"POST"}, (
        f"Upload route should only accept POST, but accepts: {upload_route.methods}"
    )


def test_parse_route_exists():
    """
    Verify that the parse route exists with the correct path.
    
    The UI calls: POST /api/v1/upload/{config_file_id}/parse
    """
    routes = [r for r in app.routes if isinstance(r, APIRoute)]
    
    # Find parse routes
    parse_routes = [r for r in routes if "parse" in r.path and "upload" in r.path]
    
    assert parse_routes, "No parse route found under /api/v1/upload/"
    
    # Should have a route like /api/v1/upload/{config_file_id}/parse
    expected_pattern = "/api/v1/upload/{"
    matching_routes = [r for r in parse_routes if expected_pattern in r.path and "parse" in r.path]
    
    assert matching_routes, (
        f"No parse route matching pattern {expected_pattern}...parse. "
        f"Found routes: {[r.path for r in parse_routes]}"
    )
    
    # Verify it accepts POST
    post_parse_routes = [r for r in matching_routes if "POST" in r.methods]
    assert post_parse_routes, "Parse route does not accept POST method"

