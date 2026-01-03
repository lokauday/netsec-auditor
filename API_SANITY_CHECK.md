# API Sanity Check Guide

This document describes the expected behavior for each endpoint in the upload → parse → audit workflow.

## Test Configuration: Minimal Cisco ASA Config

Save this as `test_asa_config.txt`:

```
hostname test-asa
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
access-list OUTSIDE-IN extended permit tcp any host 203.0.113.10 eq 443
access-list OUTSIDE-IN extended permit tcp any host 203.0.113.10 eq 80
access-list OUTSIDE-IN extended deny ip any any
!
nat (inside) 1 192.168.1.0 255.255.255.0
!
route outside 0.0.0.0 0.0.0.0 203.0.113.254 1
!
```

---

## Step 1: POST /api/v1/upload/

### Request
```bash
curl -X POST "http://localhost:8000/api/v1/upload/" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test_asa_config.txt"
```

### Expected HTTP Status
**201 Created**

### Expected JSON Response
```json
{
  "id": 1,
  "filename": "cisco_asa_test_asa_config.txt",
  "vendor": "cisco_asa",
  "original_filename": "test_asa_config.txt",
  "file_size": 342,
  "uploaded_at": "2024-01-15T10:30:00Z",
  "parsed_at": null
}
```

### Key Fields to Verify
- ✅ `id`: Integer (auto-incrementing, starts at 1)
- ✅ `filename`: Prefixed with vendor (e.g., `cisco_asa_test_asa_config.txt`)
- ✅ `vendor`: Should be `"cisco_asa"` (auto-detected)
- ✅ `original_filename`: Your original filename
- ✅ `file_size`: Number of bytes
- ✅ `uploaded_at`: ISO 8601 timestamp
- ✅ `parsed_at`: `null` (not parsed yet)

### What's Stored in PostgreSQL
**Table: `config_files`**
- One new row with:
  - `id`: Primary key
  - `filename`: Vendor-prefixed filename
  - `vendor`: `cisco_asa` (enum)
  - `original_filename`: Original upload name
  - `file_path`: Path to saved file on disk (e.g., `./uploads/cisco_asa_test_asa_config.txt`)
  - `file_size`: File size in bytes
  - `uploaded_at`: Current timestamp
  - `parsed_at`: `NULL`

**On Disk:**
- File saved to `./uploads/cisco_asa_test_asa_config.txt`

**No other tables populated yet** (ACLs, NAT rules, etc. are created during parse)

---

## Step 2: POST /api/v1/upload/{id}/parse

### Request
```bash
curl -X POST "http://localhost:8000/api/v1/upload/1/parse" \
  -H "accept: application/json"
```

### Expected HTTP Status
**200 OK**

### Expected JSON Response
```json
{
  "config_file_id": 1,
  "parsed": true,
  "parsed_at": "2024-01-15T10:31:00Z",
  "elements_parsed": {
    "acls": 3,
    "nat_rules": 1,
    "vpns": 0,
    "interfaces": 2,
    "routes": 1
  }
}
```

### Key Fields to Verify
- ✅ `config_file_id`: Matches the ID from upload step
- ✅ `parsed`: `true`
- ✅ `parsed_at`: ISO 8601 timestamp (not null)
- ✅ `elements_parsed`: Object with counts:
  - `acls`: Should be 3 (from our test config)
  - `nat_rules`: Should be 1
  - `vpns`: Should be 0 (no VPN config in test)
  - `interfaces`: Should be 2 (outside and inside)
  - `routes`: Should be 1 (default route)

### What's Stored in PostgreSQL

**Table: `config_files`**
- `parsed_at` field updated to current timestamp

**Table: `acls`**
- 3 rows (one per `access-list` line):
  - ACL named "OUTSIDE-IN" with 3 rules
  - Each row has: `name`, `action` (permit/deny), `protocol`, `source`, `destination`, `port`, etc.

**Table: `interfaces`**
- 2 rows:
  - `GigabitEthernet0/0` (outside interface)
  - `GigabitEthernet0/1` (inside interface)
  - Each has: `name`, `ip_address`, `status`, etc.

**Table: `nat_rules`**
- 1 row:
  - NAT rule for inside interface
  - Has: `source_original`, `source_translated`, `interface`, etc.

**Table: `routes`**
- 1 row:
  - Default route (0.0.0.0/0) to outside interface
  - Has: `network`, `next_hop`, `interface`, `protocol` (static)

**Table: `vpns`**
- 0 rows (no VPN config in test)

All rows have `config_file_id` foreign key pointing to the config file.

---

## Step 3: POST /api/v1/audit/{id}

### Request
```bash
curl -X POST "http://localhost:8000/api/v1/audit/1" \
  -H "accept: application/json"
```

### Expected HTTP Status
**200 OK**

### Expected JSON Response
```json
{
  "config_file_id": 1,
  "vendor": "cisco_asa",
  "filename": "cisco_asa_test_asa_config.txt",
  "risk_score": 20,
  "summary": "Found 2 security finding(s) (1 critical, 1 medium severity). Risk score: 20/100.",
  "findings": [
    {
      "severity": "critical",
      "code": "ACL_ANY_ANY_INBOUND",
      "description": "ACL 'OUTSIDE-IN' permits any-to-any traffic (any source to any destination)",
      "affected_objects": ["ACL:OUTSIDE-IN", "Rule ID:3"],
      "recommendation": "Replace 'any' with specific source and destination networks. This rule allows unrestricted access and should be avoided."
    },
    {
      "severity": "medium",
      "code": "DEFAULT_ROUTE_UNTRUSTED",
      "description": "Default route (0.0.0.0/0) points to interface 'outside' which appears to be an external/untrusted interface.",
      "affected_objects": ["Route:1", "Interface:outside"],
      "recommendation": "Verify this is intentional. Ensure proper firewall rules are in place to protect against unauthorized access. Consider adding specific routes before the default route for internal networks."
    }
  ]
}
```

### Key Fields to Verify
- ✅ `config_file_id`: Matches the ID
- ✅ `vendor`: `"cisco_asa"`
- ✅ `filename`: Matches uploaded filename
- ✅ `risk_score`: Integer between 0-100
  - Critical finding = +20 points
  - High finding = +10 points
  - Medium finding = +5 points
  - Low finding = +2 points
- ✅ `summary`: Human-readable string describing findings
- ✅ `findings`: Array of security findings, each with:
  - `severity`: "critical", "high", "medium", or "low"
  - `code`: Unique code (e.g., "ACL_ANY_ANY_INBOUND")
  - `description`: Detailed description
  - `affected_objects`: Array of affected object identifiers
  - `recommendation`: Suggested fix

### Expected Findings for Test Config

Based on the test config, you should see:

1. **DEFAULT_ROUTE_UNTRUSTED** (Medium) - **Will definitely appear**
   - Triggered by: Default route (0.0.0.0/0) pointing to "outside" interface
   - The audit service detects that "outside" is an untrusted interface

2. **ACL_ANY_ANY_INBOUND** (Critical) - **May or may not appear**
   - **Note**: The audit logic checks for `permit` + `source == "any"` + `destination == "any"`
   - Our test config has:
     - `permit tcp any host 203.0.113.10` - NOT any-to-any (destination is specific host)
     - `deny ip any any` - This is a deny rule, not permit, so won't trigger
   - **To test this finding**, modify the config to have: `access-list OUTSIDE-IN extended permit ip any any`

**Expected minimum**: At least 1 finding (the default route finding)

### What's Stored in PostgreSQL

**No new data is written during audit** - the audit is read-only and generates findings on-the-fly.

The audit:
- Reads from: `config_files`, `acls`, `nat_rules`, `routes`, `interfaces`, `vpns` tables
- Performs rule-based checks
- Optionally calls OpenAI API (if configured)
- Returns findings in response (not stored)

---

## Success Criteria

✅ **All three endpoints return 200/201 status codes**

✅ **Upload response** contains valid `id`, `vendor` is detected correctly, `parsed_at` is null

✅ **Parse response** shows `parsed: true`, `parsed_at` is not null, element counts match config

✅ **Audit response** contains `risk_score` (0-100), `summary` string, `findings` array with at least one finding (the default route finding)

✅ **Database verification** (optional):
```sql
-- Connect to PostgreSQL
docker-compose exec db psql -U postgres -d netsec_auditor

-- Check config file
SELECT id, filename, vendor, parsed_at FROM config_files;

-- Check parsed elements
SELECT COUNT(*) FROM acls WHERE config_file_id = 1;
SELECT COUNT(*) FROM interfaces WHERE config_file_id = 1;
SELECT COUNT(*) FROM routes WHERE config_file_id = 1;
SELECT COUNT(*) FROM nat_rules WHERE config_file_id = 1;
```

---

## Common Issues & Troubleshooting

### Issue: Upload returns 400 "Could not detect vendor type"
**Fix**: Ensure your config file contains vendor-specific keywords (e.g., "Cisco Adaptive Security Appliance" or "interface" for Cisco)

### Issue: Parse returns 404 "Config file not found"
**Fix**: Make sure you're using the correct `id` from the upload response

### Issue: Audit returns empty findings array
**Possible causes**:
- Config doesn't match any rule-based checks
- Parser didn't extract data correctly
- Check that parse step completed successfully

### Issue: Database connection errors
**Fix**: Ensure PostgreSQL container is healthy:
```bash
docker-compose ps
docker-compose logs db
```

---

## Quick Test Script

```bash
#!/bin/bash
# Quick test script

API_URL="http://localhost:8000/api/v1"

# 1. Upload
echo "Step 1: Uploading config..."
UPLOAD_RESPONSE=$(curl -s -X POST "${API_URL}/upload/" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test_asa_config.txt")

CONFIG_ID=$(echo $UPLOAD_RESPONSE | jq -r '.id')
echo "Uploaded config ID: $CONFIG_ID"

# 2. Parse
echo "Step 2: Parsing config..."
PARSE_RESPONSE=$(curl -s -X POST "${API_URL}/upload/${CONFIG_ID}/parse")
echo "Parse response: $PARSE_RESPONSE"

# 3. Audit
echo "Step 3: Running audit..."
AUDIT_RESPONSE=$(curl -s -X POST "${API_URL}/audit/${CONFIG_ID}")
echo "Audit response: $AUDIT_RESPONSE"

# Check results
if echo "$UPLOAD_RESPONSE" | jq -e '.id' > /dev/null; then
  echo "✅ Upload successful"
else
  echo "❌ Upload failed"
fi

if echo "$PARSE_RESPONSE" | jq -e '.parsed == true' > /dev/null; then
  echo "✅ Parse successful"
else
  echo "❌ Parse failed"
fi

if echo "$AUDIT_RESPONSE" | jq -e '.risk_score' > /dev/null; then
  echo "✅ Audit successful"
else
  echo "❌ Audit failed"
fi
```

