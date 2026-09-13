import sqlite3, os
db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
rows = conn.execute('SELECT id, opcode, length(payload_hex)/2 as sz, seen_at FROM protocol_raw_events ORDER BY id DESC LIMIT 40').fetchall()
print(f"Latest 40 events in DB:")
for r in rows:
    print(f"ID {r['id']}: {r['seen_at']} | Opcode {r['opcode']} | {r['sz']} bytes")
