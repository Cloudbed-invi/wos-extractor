import sqlite3
import csv
import os

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute(\"\"\"
    SELECT pseudo_display, alliance_tag, atlas_x, atlas_y, seen_at
    FROM map_observations
    WHERE atlas_x IS NOT NULL AND atlas_y IS NOT NULL
    GROUP BY pseudo_display
    ORDER BY seen_at DESC
\"\"\")

rows = c.fetchall()

if not rows:
    print('No map coordinates found in the database. Scroll around the map first!')
else:
    output_file = 'Live_Map_Scan.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Alliance', 'Chunk_X', 'Chunk_Y', 'Last_Seen'])
        for r in rows:
            writer.writerow(r)
    print(f'Success! Exported {len(rows)} players to {output_file}')
    print('Note: The X and Y are the approximate Map Tile (Chunk) coordinates.')
