import re

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Add Alliance Filter to UI
ui_search = "        ttk.Label(f_atlas_import,text='State:').pack(side='left')"
ui_replace = """        ttk.Label(f_atlas_import,text='State:').pack(side='left')
        self.var_state=tk.StringVar()
        ttk.Entry(f_atlas_import,textvariable=self.var_state,width=6).pack(side='left',padx=4)
        
        ttk.Label(f_atlas_import,text='Alliance:').pack(side='left',padx=(8,0))
        self.var_alliance_filter=tk.StringVar()
        ttk.Entry(f_atlas_import,textvariable=self.var_alliance_filter,width=6).pack(side='left',padx=4)
        
        ttk.Button(f_atlas_import,text='Import WOS Atlas',command=self.start_atlas_sync).pack(side='left',padx=2,fill='x',expand=True)
"""
code = re.sub(r"        ttk\.Label\(f_atlas_import,text='State:'\)\.pack\(side='left'\)\s*self\.var_state=tk\.StringVar\(\)\s*ttk\.Entry\(f_atlas_import,textvariable=self\.var_state,width=6\)\.pack\(side='left',padx=4\)\s*ttk\.Button\(f_atlas_import,text='Import WOS Atlas',command=self\.start_atlas_sync\)\.pack\(side='left',padx=2,fill='x',expand=True\)", ui_replace, code, flags=re.MULTILINE)

# Apply Filter in _atlas_worker
worker_search = """            entries=lead.get('entries')
            if not isinstance(entries,list):
                raise RuntimeError(f'ÉCHEC API ATLAS : réponse leaderboard invalide pour l’État {kid} (champ entries absent/invalide). Import annulé.')"""
worker_replace = """            entries=lead.get('entries')
            if not isinstance(entries,list):
                raise RuntimeError(f'ÉCHEC API ATLAS : réponse leaderboard invalide pour l’État {kid} (champ entries absent/invalide). Import annulé.')
            
            # User Alliance Filter
            target_alliance = self.var_alliance_filter.get().strip().upper()
            if target_alliance:
                entries = [a for a in entries if (a.get('abbr') or '').upper() == target_alliance]
                if not entries:
                    self.log(f"Atlas State {kid}: No alliance found matching '{target_alliance}'.")
                    return
            else:
                entries = entries[:10] # Top 10 limit
"""
code = code.replace(worker_search, worker_replace)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("Alliance filter injected.")
