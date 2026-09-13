import re

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Add auto-loader to _build
build_search = """        self.atlas_session_status=tk.StringVar(value='Atlas: non connecté'); ttk.Label(top,textvariable=self.atlas_session_status).pack(side='left',padx=(10,4)); self.status=tk.StringVar(value='Prêt'); ttk.Label(top,textvariable=self.status).pack(side='right')"""
build_replace = """        self.atlas_session_status=tk.StringVar(value='Atlas: not connected'); ttk.Label(top,textvariable=self.atlas_session_status).pack(side='left',padx=(10,4)); self.status=tk.StringVar(value='Ready'); ttk.Label(top,textvariable=self.status).pack(side='right')
        
        # --- AUTO-LOAD COOKIES ---
        cookie_path = BASE_DIR / 'atlas_cookies.txt'
        if cookie_path.exists():
            try:
                raw_txt = cookie_path.read_text(encoding='utf-8')
                extracted = self._extract_atlas_cookie(raw_txt)
                if extracted:
                    self.atlas_cookie = extracted
                    self.atlas_session_status.set('Atlas: session configured (auto)')
                    self.log('WOS Atlas cookies automatically loaded from file.')
            except Exception as e:
                self.log(f'Error reading atlas_cookies.txt: {e}')"""
code = code.replace(build_search, build_replace)

# Save cookies on configure
config_search = """            self.atlas_cookie=cookie; self.atlas_session_status.set('Atlas: session configurée'); self.log('WOS Atlas Session configurée (cookies chargés en mémoire, valeurs masquées).'); win.destroy()"""
config_replace = """            self.atlas_cookie=cookie; self.atlas_session_status.set('Atlas: session configured'); self.log('WOS Atlas Session configured (cookies saved).'); 
            try:
                (BASE_DIR / 'atlas_cookies.txt').write_text(cookie, encoding='utf-8')
            except Exception as e:
                self.log(f'Failed to save cookies: {e}')
            win.destroy()"""
code = code.replace(config_search, config_replace)

# French translations
code = code.replace("'Atlas: non connecté'", "'Atlas: not connected'")
code = code.replace("'Prêt'", "'Ready'")
code = code.replace("Impossible de trouver wos_at et wos_rt dans ce texte.", "Cannot find wos_at and wos_rt in this text.")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("Cookie auto-loader restored!")
