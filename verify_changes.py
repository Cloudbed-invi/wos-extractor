code_ui = open('WOS_Unified_Manager_V4_0_49.py', encoding='utf-8').read()
code_eng = open('wos_collector_engine.py', encoding='utf-8').read()

checks_ui = [
    ('lang_cb', 'Language dropdown widget', code_ui),
    ('_on_lang_change', 'Language change handler', code_ui),
    ('city opened', 'French fix: ville ouverte', code_ui),
    ('MAP Scan in progress', 'French fix: en cours', code_ui),
    ("=='ALL'", 'French fix: TOUTES', code_ui),
    ('MAP Scan interrupted:', 'French fix: interrompu', code_ui),
]
checks_eng = [
    ('Live coords:', 'Live coord log', code_eng),
    ('update_player_live_coords', 'DB coord update call', code_eng),
    ('_extract_map_xy', 'Coord extractor', code_eng),
    ('coord_source', 'coord_source field', code_eng),
]
for needle, label, code in checks_ui + checks_eng:
    found = needle in code
    status = 'OK' if found else 'MISSING'
    print(f'[{status}] {label}')
