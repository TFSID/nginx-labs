#!/bin/bash
cd /app
python3 server.py &>/dev/null &
exec nginx -g 'daemon off;'
