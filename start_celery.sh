#!/bin/bash
# Load .env for API key
export $(grep -v '^#' .env | xargs)
cd "$(dirname "$0")"
exec celery -A config.celery_config worker --queues=orchestrator,recon,vuln,exploit,report --concurrency=2 --loglevel=info
