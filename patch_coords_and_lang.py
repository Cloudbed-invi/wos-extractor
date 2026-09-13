"""
Patch: 
  1. Fix remaining French strings
  2. Add Language dropdown setting
  3. Add live coordinate extractor to _decode_map_frame
  4. Write live X/Y back to players table
"""
import re

# ── 1. Fix remaining French in WOS_Unified_Manager ──────────────────────────
with open("WOS_Unified_Manager_V4_0_49.py", "r", encoding="utf-8") as f:
    ui = f.read()

fr_fixes = [
    # _nav_ready remaining French
    ("messagebox.showerror('Navigation PC','pyautogui est absent. Lance INSTALL_DEPENDENCIES.bat.')",
     "messagebox.showerror('Navigation PC','pyautogui is not installed. Run INSTALL_DEPENDENCIES.bat.')"),
    ("messagebox.showwarning('Incomplete Calibration','Calibre d'abord : '+', '.join(miss))",
     "messagebox.showwarning('Incomplete Calibration','Calibrate first: '+', '.join(miss))"),
    ("messagebox.showwarning('New Calibration Required','This version uses calibration relative to the WOS window. Redo the 5 points une fois.')",
     "messagebox.showwarning('New Calibration Required','This version uses calibration relative to the WOS window. Redo the 5 calibration points once.')"),
    # _scan_worker remaining French
    ("ville ouverte", "city opened"),
    ("'Trace visite A", "'Visit trace A"),
    ("MAP Scan en cours", "MAP Scan in progress"),
    ("MAP Scan interrompu:", "MAP Scan interrupted:"),
    # Alliance combo
    ("'TOUTES'", "'ALL'"),
    ("=='TOUTES'", "=='ALL'"),
    # nav_ready comment
    ("# WOS PC n'accepte pas toujours correctement pyautogui.write() dans ses champs\n        # custom. We go through the Windows clipboard + Ctrl+V.",
     "# WOS PC does not always correctly accept pyautogui.write() in its custom fields.\n        # We go through the Windows clipboard + Ctrl+V."),
    # scan worker comment
    ("\"\"\"Envoie des frappes Windows en scan-codes (SendInput).", '"""Send Windows keystrokes via scan-codes (SendInput).'),
    # V4.0.28 comment
    ("# V4.0.28 : Google Play Games/WOS ne reconnait pas Ctrl+A dans ces champs.\n        # Les coordonnees WOS tiennent sur 4 chiffres maximum : on efface donc\n        # Les frappes passent toujours par SendInput scan-codes ; fallback pyautogui.",
     "# V4.0.28: Google Play Games/WOS doesn't recognize Ctrl+A in these fields.\n        # WOS coordinates are max 4 digits: we erase with 4 Backspace presses.\n        # Keystrokes always go through SendInput scan-codes; fallback to pyautogui."),
    # V4.0.33 comment
    ("# V4.0.33 : Echap est envoye par SendInput avec le scan-code materiel 0x01.",
     "# V4.0.33: Escape is sent by SendInput with hardware scan-code 0x01."),
    # SendInput unavailable
    ("f'Navigation PC: SendInput indisponible ({exc})'",
     "f'Navigation PC: SendInput unavailable ({exc})'"),
]

for fr, en in fr_fixes:
    ui = ui.replace(fr, en)

# ── 2. Language dropdown ──────────────────────────────────────────────────────
# Insert dropdown after the status label on the right side of the top bar
old_status_line = "        self.atlas_session_status=tk.StringVar(value='Atlas: not connected'); ttk.Label(top,textvariable=self.atlas_session_status).pack(side='left',padx=(10,4)); self.status=tk.StringVar(value='Ready'); ttk.Label(top,textvariable=self.status).pack(side='right')"
new_status_line = """        self.atlas_session_status=tk.StringVar(value='Atlas: not connected'); ttk.Label(top,textvariable=self.atlas_session_status).pack(side='left',padx=(10,4)); self.status=tk.StringVar(value='Ready'); ttk.Label(top,textvariable=self.status).pack(side='right')
        # Language setting dropdown
        ttk.Label(top,text='Lang:').pack(side='right',padx=(0,2))
        self._lang_var=tk.StringVar(value=self.nav_config.get('lang','en').upper())
        lang_cb=ttk.Combobox(top,textvariable=self._lang_var,values=['EN','FR'],width=4,state='readonly')
        lang_cb.pack(side='right',padx=(0,6))
        lang_cb.bind('<<ComboboxSelected>>',self._on_lang_change)"""

ui = ui.replace(old_status_line, new_status_line)

# Insert _on_lang_change method before reset_everything
lang_method = '''
    def _on_lang_change(self, event=None):
        val = self._lang_var.get().lower()
        self.nav_config['lang'] = val
        self._save_nav_config()
        self.log(f"Language set to '{val.upper()}'. Restart the app to apply.")
        from tkinter import messagebox as _mb
        _mb.showinfo("Language Changed", f"Language set to {val.upper()}.\\nRestart WOS Extract to apply the change.")

'''

ui = ui.replace("    def reset_everything(self):", lang_method + "    def reset_everything(self):")

with open("WOS_Unified_Manager_V4_0_49.py", "w", encoding="utf-8") as f:
    f.write(ui)

print("UI patched: French fixes + language dropdown added.")

# ── 3. Live coordinate extractor in engine ─────────────────────────────────
with open("wos_collector_engine.py", "r", encoding="utf-8") as f:
    eng = f.read()

# Add helper function + update_player_coords to StateDB (inject after map_record_observation)
coord_db_method = '''
    def update_player_live_coords(self, atlas_id: int, x: int, y: int) -> bool:
        """Update atlas_x/atlas_y for an existing player from live map traffic.
        Only updates if the player already exists in the DB (never creates new rows).
        Returns True if the row was actually changed."""
        with self.lock, self.conn:
            old = self.conn.execute(
                "SELECT atlas_x, atlas_y FROM players WHERE atlas_id=?", (atlas_id,)
            ).fetchone()
            if old is None:
                return False  # Player not in DB — don't create phantom entries
            if old['atlas_x'] == x and old['atlas_y'] == y:
                return False  # No change
            self.conn.execute(
                "UPDATE players SET atlas_x=?, atlas_y=?, coord_source='live-map', last_seen=? WHERE atlas_id=?",
                (x, y, utc_now(), atlas_id)
            )
            return True

'''

# Inject after map_record_observation def
insert_after = "    def map_session_stats(self,session_id):"
eng = eng.replace(insert_after, coord_db_method + "    def map_session_stats(self,session_id):")

# Add coordinate extractor helper + inject into _decode_map_frame
coord_extractor = '''
    @staticmethod
    def _extract_map_xy(block: bytes):
        """Extract X/Y coordinate pair from a raw world-map 7D02 block.
        WoS map is exactly 800x800. We scan for two uint16 little-endian values
        both in [1, 800] that appear within 4 bytes of each other near the block.
        Returns (x, y) or None.
        """
        import struct
        candidates = []
        for i in range(len(block) - 1):
            try:
                v = struct.unpack_from('<H', block, i)[0]
            except Exception:
                break
            if 1 <= v <= 800:
                candidates.append((i, v))
        # Find two candidate values within 4 bytes of each other
        for j in range(len(candidates) - 1):
            pos_a, va = candidates[j]
            pos_b, vb = candidates[j + 1]
            if 0 < pos_b - pos_a <= 4 and va != vb:
                return va, vb
        return None

'''

# Inject before _decode_map_frame
insert_before = "    def _decode_map_frame(self, frame: bytes):"
eng = eng.replace(insert_before, coord_extractor + "    def _decode_map_frame(self, frame: bytes):")

# Now patch _decode_map_frame to call the extractor and write coords back to DB
# Replace the line that stores the map row with extended logic
old_store = '''            if decoded_atlas==atlas:
                self.stats_data["map_rows"] = self.stats_data.get("map_rows",0)+1
                # V4.0.24: MAP records can identify Atlas/WOS structurally, but
                # decode_member_power() does NOT yet identify total player power
                # in this record family. Keep Pcand only in map_observations; do
                # not feed it into players/power_observations.
                anchored["power"]=""
                anchored["power_candidate"]=""
                anchored["power_confidence"]="map-field-unverified"
                self._store_row(anchored,"map-7d02-atlas-anchored")'''

new_store = '''            if decoded_atlas==atlas:
                self.stats_data["map_rows"] = self.stats_data.get("map_rows",0)+1
                # V4.0.24: MAP records can identify Atlas/WOS structurally, but
                # decode_member_power() does NOT yet identify total player power
                # in this record family. Keep Pcand only in map_observations; do
                # not feed it into players/power_observations.
                anchored["power"]=""
                anchored["power_candidate"]=""
                anchored["power_confidence"]="map-field-unverified"
                self._store_row(anchored,"map-7d02-atlas-anchored")

            # --- Live coordinate extraction (Antigravity patch) ---
            # Try to extract X/Y from the raw block regardless of atlas match quality.
            # Only write back to existing DB rows — never create phantom players.
            try:
                coord_updater = getattr(self.db, "update_player_live_coords", None)
                if callable(coord_updater):
                    xy = self._extract_map_xy(block)
                    if xy:
                        x, y = xy
                        changed = coord_updater(atlas, x, y)
                        if changed:
                            name = anchored.get("pseudo_display") or f"Atlas {atlas}"
                            tag = anchored.get("alliance_tag") or "?"
                            self.log(f"Live coords: [{tag}] {name} X={x} Y={y}")
                            self.stats_data["changed_players"] = self.stats_data.get("changed_players", 0) + 1
            except Exception:
                pass'''

eng = eng.replace(old_store, new_store)

with open("wos_collector_engine.py", "w", encoding="utf-8") as f:
    f.write(eng)

print("Engine patched: live coord extractor + DB write added.")
