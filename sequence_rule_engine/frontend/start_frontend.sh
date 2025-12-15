#!/bin/bash
# Start a simple HTTP server for the frontend

cd "$(dirname "$0")"

echo "Starting Wazuh Sequence Rule Engine Frontend..."
echo "Frontend will be available at http://localhost:8080"
echo ""
echo "Make sure the backend API is running at http://localhost:8000"
echo ""

python3 -m http.server 8080
