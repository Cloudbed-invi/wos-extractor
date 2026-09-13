import sqlite3, os, binascii, struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

rows = conn.execute("SELECT id, payload_hex FROM protocol_raw_events WHERE opcode='7d02' ORDER BY id DESC LIMIT 500").fetchall()
print(f'Scanning {len(rows)} map packets...')

targets = [
    (25, 493, 'นิกกี้ พิ้ม'),
    (185, 1079, 'minipopor'),
    (753, 1181, 'น้ำตกคอหมู'),
    (772, 1179, 'lord852305348'),
    (833, 1143, 'Tim Bradford'),
    (1116, 1154, 'GaMEkag12'),
    (1165, 1044, 'Ail'),
    (1160, 1019, 'Fxnn37'),
    (1167, 949, 'Jeee'),
    (1151, 835, 'lord625999966')
]

for row in rows:
    try:
        frame = binascii.unhexlify(row['payload_hex'])
    except:
        continue
        
    for x, y, name in targets:
        xbI = struct.pack('<I', x)
        ybI = struct.pack('<I', y)
        
        pos = 0
        while True:
            idx = frame.find(xbI, pos)
            if idx == -1: break
            y_idx = frame.find(ybI, max(0, idx-30), min(len(frame), idx+30))
            if y_idx != -1:
                print(f'[Packet {row["id"]}] Found X={x} AND Y={y} as <I for {name}! (X at {idx}, Y at {y_idx}, dist={y_idx - idx})')
            pos = idx + 1
