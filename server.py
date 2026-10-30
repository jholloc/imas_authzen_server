from datetime import datetime

from flask import Flask, request, jsonify
from flask_caching import Cache

config = {
    "DEBUG": True,
    "CACHE_TYPE": "FileSystemCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_DIR": "cache",
}
app = Flask(__name__)
app.config.from_mapping(config)
cache = Cache(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error_response(status_code, message, request_id=None):
    """Return a plain-text error response with the given HTTP status code."""
    resp = jsonify(message)
    resp.status_code = status_code
    if request_id:
        resp.headers["X-Request-ID"] = request_id
    return resp


def _is_authorised(subject_id: str, resource_id: str, context: dict) -> bool:
    """TODO: Add authorisation logic here

    The function should return True if the user is authorised, or False otherwise.

    The arguments are:
        subject_id      The email address of the user
        resource_id     The IDS being requested
        context         A context dictionary containing machine specific context information
                        that can be used in the authorisation decision. This is mainly the extra
                        parameters provided on the IMAS URI - i.e. for 'imas:...?shot=12345' the
                        context dictionary would contain {'shot': 12345}.
    """
    return False


# ---------------------------------------------------------------------------
# AuthZEN Access Evaluation API  –  POST /access/v1
# ---------------------------------------------------------------------------


@app.route("/access/v1", methods=["POST"])
def access_evaluation():
    """
    AuthZEN Access Evaluation endpoint (§6 of the AuthZEN 1.0 spec).

    Accepted constraints
    --------------------
    - subject.type  : "user"   (subject.id is treated as an email address)
    - resource.type : "IDS"
    - action.name   : "can_read"

    Request body (JSON)
    -------------------
    {
        "subject":  { "type": "user", "id": "<email>" },
        "resource": { "type": "IDS",  "id": "<resource-id>" },
        "action":   { "name": "can_read" },
        "context":  { ... } // optional
    }

    Response body (JSON)
    --------------------
    { "decision": true | false }

    The X-Request-ID header is echoed back when present in the request.
    """
    request_id = request.headers.get("X-Request-ID")

    # ---- Parse body --------------------------------------------------------
    body = request.get_json(silent=True)
    if body is None:
        return _error_response(400, "Bad Request: body must be valid JSON", request_id)

    subject = body.get("subject")
    resource = body.get("resource")
    action = body.get("action")
    context = body.get("context", {})

    if subject is None or resource is None or action is None:
        return _error_response(
            400,
            "Bad Request: 'subject', 'resource', and 'action' are required",
            request_id,
        )

    subject_type = subject.get("type")
    subject_id = subject.get("id")
    resource_type = resource.get("type")
    resource_id = resource.get("id")
    action_name = action.get("name")

    missing = [
        field
        for field, value in [
            ("subject.type", subject_type),
            ("subject.id", subject_id),
            ("resource.type", resource_type),
            ("action.name", action_name),
        ]
        if not value
    ]
    if missing:
        return _error_response(
            400,
            f"Bad Request: missing required field(s): {', '.join(missing)}",
            request_id,
        )

    # ---- Validate supported values -----------------------------------------
    if subject_type != "user":
        return _error_response(
            400,
            f"Bad Request: unsupported subject type '{subject_type}', expected 'user'",
            request_id,
        )

    if resource_type != "IDS":
        return _error_response(
            400,
            f"Bad Request: unsupported resource type '{resource_type}', expected 'IDS'",
            request_id,
        )

    if action_name != "can_read":
        return _error_response(
            400,
            f"Bad Request: unsupported action '{action_name}', expected 'can_read'",
            request_id,
        )

    # ---- Evaluate ----------------------------------------------------------
    decision = _is_authorised(subject_id, resource_id, context)

    resp = jsonify({"decision": decision})
    if request_id:
        resp.headers["X-Request-ID"] = request_id
    return resp
