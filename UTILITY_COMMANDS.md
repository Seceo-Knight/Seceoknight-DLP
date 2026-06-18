# Utility Commands Reference

This file contains useful commands for managing and testing the SeceoKnight DLP system.

---

## MongoDB Event Management

### Clear All Events from MongoDB
```bash
cd /home/vansh/Code/Data-Loss-Prevention
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp --eval "const before = db.dlp_events.countDocuments({}); print('Events before: ' + before); const result = db.dlp_events.deleteMany({}); print('Deleted: ' + result.deletedCount); const after = db.dlp_events.countDocuments({}); print('Events after: ' + after);"
```

**What it does:**
- Reads MongoDB password from `.env` file
- Connects to MongoDB with authentication
- Shows event count before deletion
- Deletes all events from `dlp_events` collection
- Shows deletion count and final event count

### Check Event Count
```bash
cd /home/vansh/Code/Data-Loss-Prevention
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp --eval "print('Total events:', db.dlp_events.countDocuments({})); print('Windows agent events:', db.dlp_events.countDocuments({agent_id: 'windows-agent-001'})); print('Linux agent events:', db.dlp_events.countDocuments({agent_id: {$ne: 'windows-agent-001'}}))"
```

### View Recent Events
```bash
cd /home/vansh/Code/Data-Loss-Prevention
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp --eval "db.dlp_events.find({}).sort({timestamp: -1}).limit(10).forEach(e => print(JSON.stringify(e, null, 2)))"
```

### View Windows Agent Events Only
```bash
cd /home/vansh/Code/Data-Loss-Prevention
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp --eval "db.dlp_events.find({agent_id: 'windows-agent-001'}).sort({timestamp: -1}).limit(5).forEach(e => print(JSON.stringify(e, null, 2)))"
```

---

## Docker Management

### Stop All Services
```bash
cd /home/vansh/Code/Data-Loss-Prevention
docker compose down
```

### Start All Services
```bash
cd /home/vansh/Code/Data-Loss-Prevention
docker compose up -d
```

### Restart Manager Service (API Server)
```bash
cd /home/vansh/Code/Data-Loss-Prevention
docker compose restart manager
```

### View Manager Logs
```bash
docker compose logs manager -f
```

### View MongoDB Logs
```bash
docker compose logs mongodb -f
```

---

## Agent Management

### Check Running Agents (Linux)
```bash
ps aux | grep agent.py | grep -v grep
```

### Kill All Agent Processes (Linux)
```bash
pkill -f agent.py
```

### Check Agent Logs (Linux)
```bash
tail -f ~/seceoknight_agent.log
```

---

## API Testing

### Test API Health
```bash
curl http://localhost:55000/health
```

### Test Event Creation (Manual)
```bash
curl -X POST http://localhost:55000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "test-manual-123",
    "event_type": "file",
    "agent_id": "windows-agent-001",
    "source_type": "agent",
    "severity": "low",
    "file_path": "C:\\test.txt"
  }'
```

### Get Auth Token
```bash
TOKEN=$(curl -s -X POST http://localhost:55000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN
```

### Get Events (with auth)
```bash
TOKEN=$(curl -s -X POST http://localhost:55000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:55000/api/v1/events?limit=5 \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Database Management

### Initialize Database
```bash
cd /home/vansh/Code/Data-Loss-Prevention
docker compose run --rm manager python init_db.py
```

### Access PostgreSQL
```bash
docker compose exec postgres psql -U dlp_user -d seceoknight_dlp
```

### Access MongoDB Shell
```bash
cd /home/vansh/Code/Data-Loss-Prevention
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec -it seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp
```

---

## Quick Testing Workflow

### Full Reset and Test
```bash
# 1. Stop everything
docker compose down
pkill -f agent.py

# 2. Start services
docker compose up -d

# 3. Wait for services to be healthy
sleep 30

# 4. Initialize database (if needed)
docker compose run --rm manager python init_db.py

# 5. Clear events
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp --eval "db.dlp_events.deleteMany({})"

# 6. Start Linux agent (in separate terminal)
cd /home/vansh/Code/Data-Loss-Prevention/agents/endpoint/linux
python3 agent.py

# 7. Test - create file
echo "SSN: 123-45-6789" > /tmp/test.txt

# 8. Check events
MONGODB_PASSWORD=$(grep "^MONGODB_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
docker exec seceoknight-mongodb mongosh -u dlp_user -p "$MONGODB_PASSWORD" --authenticationDatabase admin seceoknight_dlp --eval "print('Events:', db.dlp_events.countDocuments({}))"
```

---

## Notes

- All MongoDB commands use authentication from `.env` file
- Replace `windows-agent-001` with your actual agent ID if different
- Commands assume you're in the project root directory
- For Windows agent testing, use PowerShell commands from `WINDOWS_AGENT_TEST.md`

