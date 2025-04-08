#!/bin/bash
DB_HOST="$DB_PRIVATE_IP"
DB_PORT=3306
MAX_RETRIES=30
RETRY_INTERVAL=10

check_mysql() {
    nc -z "$DB_HOST" "$DB_PORT"
    return $?
}

retry_count=0
while [ $retry_count -lt $MAX_RETRIES ]; do
    if check_mysql; then
        echo "Successfully connected to MySQL at $DB_HOST:$DB_PORT"
        exit 0
    fi
    echo "Attempt $((retry_count + 1))/$MAX_RETRIES: Cannot connect to MySQL at $DB_HOST:$DB_PORT. Retrying in $RETRY_INTERVAL seconds..."
    sleep $RETRY_INTERVAL
    retry_count=$((retry_count + 1))
done

echo "Failed to connect to MySQL after $MAX_RETRIES attempts"
exit 1
