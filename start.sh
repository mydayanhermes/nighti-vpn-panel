#!/bin/bash
PORT=${PORT:-8000}
exec gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4
