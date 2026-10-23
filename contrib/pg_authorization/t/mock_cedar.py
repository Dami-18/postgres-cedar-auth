#!/usr/bin/env python3
import json
import time
import argparse
import threading
from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory storage for synced entities
entities = {}

# Test controls: the current decision mode and a log of every request received
lock = threading.Lock()
mode = {"name": "basic", "arg": None}
requests_log = []

DENY = {"decision": "Deny", "diagnostics": {"reason": [], "errors": []}}
ALLOW = {"decision": "Allow", "diagnostics": {"reason": [], "errors": []}}


def action_name(action):
    """'Action::"SELECT"' (optionally namespaced) -> 'SELECT'."""
    if '::"' in action:
        return action.rsplit('::"', 1)[1].rstrip('"')
    return action


def decide(data):
    principal = data.get("principal", "")
    action = action_name(data.get("action", ""))
    resource = data.get("resource", "")
    ip = data.get("context", {}).get("ip", {}).get("__extn", {}).get("arg", "")

    name, arg = mode["name"], mode["arg"]

    if name == "basic":
        # Alice rules
        if principal == 'User::"alice"':
            # Deny SELECT on test_col table
            if 'Table' in resource and 'public.test_col' in resource and action == 'SELECT':
                return {"decision": "Deny", "reason": "No table-level SELECT"}
            # Default allow for alice otherwise (to allow USAGE on schema, columns, etc)
            return {"decision": "Allow"}
        # Default deny
        return {"decision": "Deny", "reason": "Default deny in mock"}

    if name == "allow_all":
        return ALLOW
    if name == "deny_all":
        return DENY
    if name == "table_deny_column_allow":
        # Only column-level policies allow; table-level requests are denied
        return ALLOW if resource.startswith('Column::') or 'Schema' in resource else DENY
    if name == "deny_with_allow_reason":
        # A Deny whose diagnostics name a policy with id "Allow"
        return {"decision": "Deny", "diagnostics": {"reason": ["Allow"], "errors": []}}
    if name == "allow_ip":
        # Only requests whose context.ip equals arg are allowed (schema usage always allowed)
        return ALLOW if ip == arg or 'Schema' in resource else DENY
    if name == "slow_allow":
        # Allow, but take `arg` seconds to answer
        time.sleep(float(arg))
        return ALLOW
    return DENY


@app.route('/v1/is_authorized', methods=['POST'])
def is_authorized():
    data = request.get_json()
    with lock:
        requests_log.append(data)
    return jsonify(decide(data))


@app.route('/v1/data/single/<path:entity_id>', methods=['PUT'])
def sync_entity_upsert(entity_id):
    data = request.get_json()
    with lock:
        requests_log.append({"method": "PUT", "entity": entity_id})
    entities[entity_id] = data
    return jsonify({"status": "success"}), 200


@app.route('/v1/data/single/<path:entity_id>', methods=['DELETE'])
def sync_entity_delete(entity_id):
    with lock:
        requests_log.append({"method": "DELETE", "entity": entity_id})
    if entity_id in entities:
        del entities[entity_id]
        return jsonify({"status": "success"}), 200
    return jsonify({"error": "not found"}), 404


@app.route('/test/entities', methods=['GET'])
def get_entities():
    return jsonify(entities)


@app.route('/test/mode', methods=['POST'])
def set_mode():
    data = request.get_json()
    with lock:
        mode["name"] = data.get("mode", "basic")
        mode["arg"] = data.get("arg")
    return jsonify(mode)


@app.route('/test/requests', methods=['GET'])
def get_requests():
    with lock:
        return jsonify(requests_log)


@app.route('/test/clear', methods=['POST'])
def clear_requests():
    with lock:
        requests_log.clear()
    return jsonify({"status": "cleared"})


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8180)
    args = parser.parse_args()
    app.run(port=args.port, threaded=True)
