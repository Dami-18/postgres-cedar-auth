#!/usr/bin/env python3
import json
import argparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory storage for synced entities
entities = {}

@app.route('/v1/is_authorized', methods=['POST'])
def is_authorized():
    data = request.get_json()
    principal = data.get("principal", "")
    action = data.get("action", "")
    resource = data.get("resource", "")
    
    # print(f"DEBUG: principal={principal}, action={action}, resource={resource}")
    
    # Alice rules
    if principal == 'User::"alice"':
        # Deny SELECT on test_col table
        if 'Table' in resource and 'public.test_col' in resource and action == 'SELECT':
            # print("DEBUG: Denying Alice on Table public.test_col")
            return jsonify({"decision": "Deny", "reason": "No table-level SELECT"})
        
        # Default allow for alice otherwise (to allow USAGE on schema, columns, etc)
        return jsonify({"decision": "Allow"})
    
    # Default deny
    return jsonify({"decision": "Deny", "reason": "Default deny in mock"})

@app.route('/v1/data/single/<path:entity_id>', methods=['PUT'])
def sync_entity_upsert(entity_id):
    data = request.get_json()
    entities[entity_id] = data
    return jsonify({"status": "success"}), 200

@app.route('/v1/data/single/<path:entity_id>', methods=['DELETE'])
def sync_entity_delete(entity_id):
    if entity_id in entities:
        del entities[entity_id]
        return jsonify({"status": "success"}), 200
    return jsonify({"error": "not found"}), 404

@app.route('/test/entities', methods=['GET'])
def get_entities():
    return jsonify(entities)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8180)
    args = parser.parse_args()
    app.run(port=args.port)
