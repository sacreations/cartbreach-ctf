#!/bin/bash
# CartBreach Microservices Healthcheck Probe
set -e

BASE_URL="http://localhost"
echo "=== CartBreach Health Probes ==="

echo -n "Checking Nginx Gateway: "
curl -sf "$BASE_URL:80" > /dev/null && echo "UP" || echo "FAIL"

echo -n "Checking Git Staging Repo: "
curl -sf "$BASE_URL:8080" > /dev/null && echo "UP" || echo "FAIL"

echo -n "Checking Storefront API: "
curl -sf "$BASE_URL/api/v1/health" > /dev/null && echo "UP" || echo "FAIL"

echo -n "Checking Payment Gateway: "
curl -sf "$BASE_URL/api/v1/payment/sample" > /dev/null && echo "UP" || echo "FAIL"

echo "=== All active services verified ==="
