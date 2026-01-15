#!/bin/bash
set -e
set -o pipefail

# ============================================================
# cf-doh GeoIP Import Script
# Data Source: Loyalsoldier/geoip (Country.mmdb)
# ============================================================

: "${WORKERS_DEV:=true}"

# Cloudflare credentials are still required for D1 operations
if [ -z "$CLOUDFLARE_ACCOUNT_ID" ] || [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "Error: Please set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN"
    exit 1
fi

# ============================================================
# Utility Functions
# ============================================================

# Retry with exponential backoff
retry_with_backoff() {
    local max_retries=3
    local retry=0
    local delay=2
    
    while [ $retry -lt $max_retries ]; do
        if "$@"; then
            return 0
        fi
        
        retry=$((retry + 1))
        if [ $retry -lt $max_retries ]; then
            echo "Retry $retry/$max_retries in ${delay}s..."
            sleep $delay
            delay=$((delay * 2))
        fi
    done
    
    echo "Error: Failed after $max_retries attempts"
    return 1
}

# Prepare workspace (clean old tmp if exists)
rm -rf tmp
mkdir -p tmp
cd tmp

database_filename=geoip.db
merged_ipv4_table="merged_ipv4_data"
merged_ipv6_table="merged_ipv6_data"

# ============================================================
# Step 1: Download Country.mmdb and install dependencies (parallel)
# ============================================================
echo "Starting parallel download and dependency installation..."
MMDB_URL="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"

# Run download and pip install in parallel
(retry_with_backoff wget -q -O Country.mmdb "$MMDB_URL" || retry_with_backoff curl -sSfL -o Country.mmdb "$MMDB_URL") &
DOWNLOAD_PID=$!
pip install -q maxminddb &
INSTALL_PID=$!

# Wait for both to complete
wait $DOWNLOAD_PID || { echo "Download failed"; exit 1; }
wait $INSTALL_PID || { echo "pip install failed"; exit 1; }
echo "Download and dependencies ready."

# Get version from release date (YYYYMMDD format from Loyalsoldier tags)
database_version=$(date +%Y%m%d)
echo "Database version: $database_version"

# ============================================================
# Step 2: Extract data using Python script
# ============================================================
echo "Extracting data from MMDB..."
python3 ../extract_mmdb.py Country.mmdb blocks_ipv4.csv blocks_ipv6.csv

# ============================================================
# Step 3: Create SQLite database (single session for both tables)
# ============================================================
echo "Creating SQLite database..."

sqlite3 $database_filename <<EOF
-- Create IPv4 table
CREATE TABLE ${merged_ipv4_table} (
    network_start INTEGER,
    country_iso_code TEXT,
    network TEXT
);
CREATE INDEX idx_ipv4_network_start ON ${merged_ipv4_table} (network_start);

-- Create IPv6 table
CREATE TABLE ${merged_ipv6_table} (
    network_start TEXT,
    country_iso_code TEXT,
    network TEXT
);
CREATE INDEX idx_ipv6_network_start ON ${merged_ipv6_table} (network_start);

-- Import IPv4 data
.mode csv
.import blocks_ipv4.csv ${merged_ipv4_table}_import
INSERT INTO ${merged_ipv4_table} (network_start, country_iso_code, network)
SELECT network_start, country_iso_code, network FROM ${merged_ipv4_table}_import WHERE network_start != 'network_start';
DROP TABLE ${merged_ipv4_table}_import;

-- Import IPv6 data
.import blocks_ipv6.csv ${merged_ipv6_table}_import
INSERT INTO ${merged_ipv6_table} (network_start, country_iso_code, network)
SELECT network_start, country_iso_code, network FROM ${merged_ipv6_table}_import WHERE network_start != 'network_start';
DROP TABLE ${merged_ipv6_table}_import;
EOF

echo "IPv4 records: $(sqlite3 $database_filename "SELECT COUNT(*) FROM ${merged_ipv4_table};")"
echo "IPv6 records: $(sqlite3 $database_filename "SELECT COUNT(*) FROM ${merged_ipv6_table};")"

# ============================================================
# Step 4: Export SQL dump for D1 (idempotent)
# ============================================================
echo "Exporting SQL dump..."
{
    # Drop existing tables for idempotent re-runs
    echo "DROP TABLE IF EXISTS ${merged_ipv4_table};"
    echo "DROP TABLE IF EXISTS ${merged_ipv6_table};"
    
    # Schema + Data
    sqlite3 $database_filename ".schema ${merged_ipv4_table}"
    sqlite3 $database_filename ".dump ${merged_ipv4_table} --data-only"
    sqlite3 $database_filename ".schema ${merged_ipv6_table}"
    sqlite3 $database_filename ".dump ${merged_ipv6_table} --data-only"
} > dump.sql

# ============================================================
# Step 5: Upload to Cloudflare D1
# ============================================================
if [ -z "$database_location" ]; then
    database_location="weur"
fi

database="geoip_${database_version}_${database_location}"
echo "Creating D1 database: $database"

npx wrangler d1 create $database --location=$database_location || true
npx wrangler d1 execute $database -y --remote --file=dump.sql
database_id=$(npx wrangler d1 info $database --json | jq --raw-output .uuid)

# Enable read replication
echo "Enabling read replication..."
curl -sS -X PUT "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/d1/database/$database_id" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"read_replication": {"mode": "auto"}}' > /dev/null

# ============================================================
# Step 6: Generate wrangler.toml
# ============================================================
echo "Generating wrangler.toml..."
sed -e "s/^database_name =.*/database_name = \"$database\"/" \
    -e "s/^database_id =.*/database_id = \"$database_id\"/" \
    -e "s/^workers_dev =.*/workers_dev = $WORKERS_DEV/" \
    ../wrangler.template.toml > wrangler.toml

# ============================================================
# Step 7: Cleanup old databases (keep last 3)
# ============================================================
echo "Cleaning up old databases..."
num_databases_retained=3
npx wrangler d1 list --json | jq ".[].name" --raw-output \
    | grep '^geoip_' | tail -n +$num_databases_retained \
    | while read db; do
        echo "Deleting old database: $db"
        npx wrangler d1 delete $db -y || true
    done

echo "Import complete!"
