#!/bin/bash

uv run gunicorn --capture-output --access-logfile access.log --error-logfile error.log --bind 0.0.0.0:8080 --workers=3 --timeout=120 server:app
