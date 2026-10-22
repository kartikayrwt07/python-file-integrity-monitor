"""
Sample user management API module for demonstration.
"""

def get_user_role(user_id: int) -> str:
    """Check user permissions."""
    if user_id == 1:
        return "admin"
    return "guest"
