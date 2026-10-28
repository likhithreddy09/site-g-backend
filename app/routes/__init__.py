from flask import request


def body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}
