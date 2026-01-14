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

# Prepare workspace
rm -rf tmp
mkdir -p tmp
cd tmp

database_filename=geoip.db
merged_ipv4_table="merged_ipv4_data"
merged_ipv6_table="merged_ipv6_data"

# ============================================================
# Step 1: Download Country.mmdb from Loyalsoldier
# ============================================================
echo "Downloading Country.mmdb from Loyalsoldier..."
MMDB_URL="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
wget -q -O Country.mmdb "$MMDB_URL" || curl -sSfL -o Country.mmdb "$MMDB_URL"

# Get version from release date (YYYYMMDD format from Loyalsoldier tags)
database_version=$(date +%Y%m%d)
echo "Database version: $database_version"

# ============================================================
# Step 2: Extract data using Python script
# ============================================================
echo "Extracting data from MMDB..."
pip install -q maxminddb
python3 ../extract_mmdb.py Country.mmdb blocks_ipv4.csv blocks_ipv6.csv

# ============================================================
# Step 3: Create SQLite database
# ============================================================
echo "Creating SQLite database..."

# Create IPv4 table
sqlite3 $database_filename <<EOF
CREATE TABLE ${merged_ipv4_table} (
    network_start INTEGER,
    country_iso_code TEXT,
    network TEXT
);
CREATE INDEX idx_ipv4_network_start ON ${merged_ipv4_table} (network_start);
.mode csv
.import blocks_ipv4.csv ${merged_ipv4_table}_import
INSERT INTO ${merged_ipv4_table} (network_start, country_iso_code, network)
SELECT network_start, country_iso_code, network FROM ${merged_ipv4_table}_import WHERE network_start != 'network_start';
DROP TABLE ${merged_ipv4_table}_import;
EOF

# Create IPv6 table
sqlite3 $database_filename <<EOF
CREATE TABLE ${merged_ipv6_table} (
    network_start TEXT,
    country_iso_code TEXT,
    network TEXT
);
CREATE INDEX idx_ipv6_network_start ON ${merged_ipv6_table} (network_start);
.mode csv
.import blocks_ipv6.csv ${merged_ipv6_table}_import
INSERT INTO ${merged_ipv6_table} (network_start, country_iso_code, network)
SELECT network_start, country_iso_code, network FROM ${merged_ipv6_table}_import WHERE network_start != 'network_start';
DROP TABLE ${merged_ipv6_table}_import;
EOF

echo "IPv4 records: $(sqlite3 $database_filename "SELECT COUNT(*) FROM ${merged_ipv4_table};")"
echo "IPv6 records: $(sqlite3 $database_filename "SELECT COUNT(*) FROM ${merged_ipv6_table};")"

# ============================================================
# Step 4: Export Schema (DDL only, no indexes yet)
# ============================================================
echo "Exporting schema..."
{
    echo "DROP TABLE IF EXISTS ${merged_ipv4_table};"
    echo "DROP TABLE IF EXISTS ${merged_ipv6_table};"
    echo ""
    
    # Create tables without indexes
    sqlite3 $database_filename ".schema ${merged_ipv4_table}" | \
        sed 's/CREATE TABLE/CREATE TABLE IF NOT EXISTS/' | \
        grep -v "CREATE INDEX"
    
    sqlite3 $database_filename ".schema ${merged_ipv6_table}" | \
        sed 's/CREATE TABLE/CREATE TABLE IF NOT EXISTS/' | \
        grep -v "CREATE INDEX"
} > schema.sql

# ============================================================
# Step 5: Export Data in Batches
# ============================================================
echo "Exporting data in batches..."
BATCH_SIZE=100000

# Export IPv4 data and split into batches
sqlite3 $database_filename ".dump ${merged_ipv4_table}" | grep "^INSERT" | \
    split -l $BATCH_SIZE - batch_ipv4_

# Export IPv6 data and split into batches
sqlite3 $database_filename ".dump ${merged_ipv6_table}" | grep "^INSERT" | \
    split -l $BATCH_SIZE - batch_ipv6_

# Count batches
batch_count=$(ls -1 batch_* 2>/dev/null | wc -l)
echo "Created $batch_count data batches ($BATCH_SIZE rows each)"

# ============================================================
# Step 6: Export Indexes
# ============================================================
echo "Exporting indexes..."
{
    sqlite3 $database_filename ".schema ${merged_ipv4_table}" | grep "CREATE INDEX"
    sqlite3 $database_filename ".schema ${merged_ipv6_table}" | grep "CREATE INDEX"
} > indexes.sql

# ============================================================
# Step 7: Upload to Cloudflare D1
# ============================================================
if [ -z "$database_location" ]; then
    database_location="weur"
fi

database="geoip_${database_version}_${database_location}"
echo "Creating D1 database: $database"

npx wrangler d1 create $database --location=$database_location || true

# Import schema first
echo "Importing schema..."
npx wrangler d1 execute $database -y --remote --file=schema.sql

# Import data batches
echo "Importing data batches..."
batch_num=1
for batch_file in batch_*; do
    echo "  [$batch_num/$batch_count] Importing $batch_file..."
    npx wrangler d1 execute $database -y --remote --file=$batch_file || {
        echo "Failed to import $batch_file"
        exit 1
    }
    batch_num=$((batch_num + 1))
done

# Create indexes last (for better insert performance)
echo "Creating indexes..."
npx wrangler d1 execute $database -y --remote --file=indexes.sql

database_id=$(npx wrangler d1 info $database --json | jq --raw-output .uuid)

# Enable read replication
echo "Enabling read replication..."
curl -sS -X PUT "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/d1/database/$database_id" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"read_replication": {"mode": "auto"}}' > /dev/null

# ============================================================
# Step 8: Generate wrangler.toml
# ============================================================
echo "Generating wrangler.toml..."
sed -e "s/^database_name =.*/database_name = \"$database\"/" \
    -e "s/^database_id =.*/database_id = \"$database_id\"/" \
    -e "s/^workers_dev =.*/workers_dev = $WORKERS_DEV/" \
    ../wrangler.template.toml > wrangler.toml

# ============================================================
# Step 9: Cleanup old databases (keep last 3)
# ============================================================
echo "Cleaning up old databases..."
num_databases_retained=3
npx wrangler d1 list --json | jq ".[].name" --raw-output \
    | grep '^geoip_' | tail -n +$num_databases_retained \
    | while read db; do
        echo "Deleting old database: $db"
        npx wrangler d1 delete $db --yes || true
    done

echo "Import complete!"
