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
# Insert before _on_frame
code = code.replace("    def _on_frame(self, key, frame: bytes, ts: float):", 
                    heuristic_method + "\n    def _on_frame(self, key, frame: bytes, ts: float):")

# Inject the dynamic roster bypass when 7502 is received
roster_inject = """
                if info is not None:
                    # V4 Dynamic Bypass: Extract full profiles directly from 7502
                    dynamic_players = self.heuristic_extract_roster(decode_frame)
                    if dynamic_players:
                        self.log(f"Dynamic Extraction: instantly recovered {len(dynamic_players)} full profiles from 7502.")
                        for (aid, name, pwr) in dynamic_players:
                            row = {
                                "atlas_id": aid,
                                "wos_id": 0,
                                "pseudo_display": name,
                                "pseudo_core": name,
                                "power": pwr,
                                "alliance_tag": "",
                                "alliance_name": "",
                                "wos_confidence": "low",
                                "power_confidence": "high",
                                "identity_pair_valid": True,
                            }
                            self._pending_context_rows.append(row)
                            self._current_requested_ids.add(aid)
                            self._current_roster_hint_ids.add(aid)
                        self.stats_data["decoded_players"] += len(dynamic_players)
                        # Force instant reconciliation since we have everything
                        self._maybe_reconcile_roster()
"""
code = code.replace("                if info is not None:\n                    # A roster starts a fresh", roster_inject + "\n                    # A roster starts a fresh")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("Dynamic extractor patched into V4 7502 processor!")
