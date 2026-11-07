#!/bin/sh
# Apply database migrations, then serve the app. Settings come from environment variables.
set -eu

alembic upgrade head
exec uvicorn medicare.main:create_app --factory --host 0.0.0.0 --port 8000
