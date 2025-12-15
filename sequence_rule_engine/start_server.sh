#!/bin/bash
# Start the Wazuh Sequence Rule Engine backend server

cd "$(dirname "$0")"

echo "Starting Wazuh Sequence Rule Engine API..."
echo "API will be available at http://localhost:8000"
echo "API docs available at http://localhost:8000/docs"
echo ""

uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
