import re

filepath = "wos_collector_engine.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Disable the Power-withholding gate in upsert_player
gate_search = "            if power is not None and wos is None and established_wos is None:\n                power=None"
gate_replace = "            if power is not None and wos is None and established_wos is None:\n                pass # power=None # V4.0.17 bypassed by Antigravity to allow Power-only updates!"

if gate_search in code:
    code = code.replace(gate_search, gate_replace)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(code)
    print("Power-withholding gate disabled!")
else:
    print("Gate not found! Maybe it was already replaced?")
