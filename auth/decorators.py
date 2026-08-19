# auth/decorators.py
from functools import wraps
from flask import session, request, jsonify, redirect
from auth.token_store import token_store
from auth.user_store import get_role

def _extract_bearer_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""

def _authenticate_request() -> bool:
    if session.get("authenticated"):
        return True
    token = _extract_bearer_token()
    if token:
        username = token_store.validate_token(token)
        if username:
            session["authenticated"] = True
            session["username"] = username
            session["role"] = get_role(username)
            session.permanent = True
            return True
    return False

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _authenticate_request():
            return redirect("/login.html")
        return f(*args, **kwargs)
    return wrapper

def api_login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _authenticate_request():
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not _authenticate_request():
                return jsonify({"error": "unauthorized"}), 401
            if session.get("role") not in allowed_roles:
                return jsonify({"error": "forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator