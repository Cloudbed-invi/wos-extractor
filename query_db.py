import sqlite3
import os

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

names = ['Kobe', 'TMNT', 'Mori', 'Przemo851', 'Jenna35', 'Mone']
for name in names:
    rows = conn.execute("SELECT pseudo_display, atlas_x, atlas_y FROM players WHERE pseudo_display LIKE ?", (f'%{name}%',)).fetchall()
    for row in rows:
        print(f"{row['pseudo_display']}: Atlas X={row['atlas_x']}, Y={row['atlas_y']}")
    if not rows:
        print(f"{name}: Not found in DB")
