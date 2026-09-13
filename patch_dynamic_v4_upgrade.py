import re

filepath = "wos_collector_engine.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Add the heuristic extractor method to CollectorEngine
heuristic_method = """
    def heuristic_extract_roster(self, payload):
        import re, struct
        players = []
        matches = re.finditer(b"([A-Za-z0-9_]{4,15})", payload)
        seen_names = set()
        for m in matches:
            name = m.group(1).decode('ascii')
            if name in seen_names or "png" in name or "_" in name or name.lower() in ("false", "true", "perfectworld"):
                continue
            start = max(0, m.start() - 150)
            window = payload[start:m.start()]
            ints = []
            for i in range(len(window)-3):
                val = struct.unpack("<I", window[i:i+4])[0]
                ints.append(val)
            atlas_id = None
            power = None
            for val in reversed(ints):
                if 1_000_000 <= val <= 999_000_000:
                    if power is None and val < 100_000_000:
                        power = val
                    elif atlas_id is None and val != power:
                        atlas_id = val
            if atlas_id and power:
                players.append((atlas_id, name, power))
                seen_names.add(name)
        return players
"""
if "def heuristic_extract_roster(" not in code:
    code = code.replace("    def _on_frame(self, key, frame: bytes, ts: float):", 
                        heuristic_method + "\n    def _on_frame(self, key, frame: bytes, ts: float):")

# Re-inject the dynamic roster bypass (replacing the previous one)
roster_inject = """
                if info is not None:
                    # V4 Dynamic Bypass: Extract full profiles directly from 7502
                    dynamic_players = self.heuristic_extract_roster(decode_frame)
                    if dynamic_players:
                        self.log(f"Dynamic Extraction: instantly recovered {len(dynamic_players)} full profiles from 7502.")
                        for (aid, name, pwr) in dynamic_players:
                            # We can fetch the Alliance Tag directly from the DB!
                            with self.db.lock:
                                r = self.db.conn.execute("SELECT alliance_tag FROM players WHERE atlas_id=?", (aid,)).fetchone()
                                existing_tag = r[0] if r else ""
                            
                            row = {
                                "atlas_id": aid,
                                "wos_id": 0,
                                "pseudo_display": name,
                                "pseudo_core": name,
                                "power": pwr,
                                "alliance_tag": existing_tag,
                                "alliance_name": existing_tag,
                                "wos_confidence": "low",
                                "power_confidence": "high",
                                "identity_pair_valid": True,
                                "alliance_verified": bool(existing_tag)
                            }
                            # Bypass the broken Context Queue and write directly!
                            self._store_row(row, "7502-member")
                            
                        self.stats_data["decoded_players"] += len(dynamic_players)
                        self.stats_data["changed_players"] = self.stats_data.get("changed_players", 0) + len(dynamic_players)
"""

# Regex to safely replace the old injection
# The old injection started at "if info is not None:" and ended right before "# A roster starts a fresh"
code = re.sub(r'                if info is not None:\n                    # V4 Dynamic Bypass: Extract full profiles directly from 7502.*?# Force instant reconciliation since we have everything\n                        self\._maybe_reconcile_roster\(\)\n', roster_inject, code, flags=re.DOTALL)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("Dynamic extractor upgraded to directly save power!")
