#!/bin/bash

# Exit script on error
set -e

echo "Waiting for database to be ready..."
until python3 - <<'PY'
import os
import MySQLdb

host = os.environ.get("DB_HOST", "mysql")
port = int(os.environ.get("DB_PORT", "3306"))
user = os.environ.get("DB_USER")
password = os.environ.get("DB_PASS")
db = os.environ.get("DB_NAME")

MySQLdb.connect(host=host, port=port, user=user, passwd=password, db=db).close()
PY
do
  echo "Database not ready yet. Sleeping..."
  sleep 3
done

# Run initial_setup file
echo "Running initial setup"
python3 manage.py initial_setup

# Start the Django app with waitress
echo "Starting Django server with Waitress..."
exec python3 run_waitress.py
