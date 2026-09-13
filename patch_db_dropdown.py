import re

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Add Combobox to Player DB Tab
db_ui_search = "        filt=ttk.Frame(data); filt.pack(fill='x'); ttk.Label(filt,text='Search:').pack(side='left'); self.query=tk.StringVar(); ttk.Entry(filt,textvariable=self.query,width=35).pack(side='left',padx=6); ttk.Button(filt,text='Refresh',command=self.refresh).pack(side='left')"
db_ui_replace = """        filt=ttk.Frame(data); filt.pack(fill='x'); 
        ttk.Label(filt,text='Alliance:').pack(side='left',padx=2)
        self.db_alliance_filter = tk.StringVar(value='')
        self.db_alliance_combo = ttk.Combobox(filt, textvariable=self.db_alliance_filter, state='readonly', width=10)
        self.db_alliance_combo.pack(side='left', padx=4)
        ttk.Label(filt,text='Search:').pack(side='left',padx=(10,2))
        self.query=tk.StringVar(); ttk.Entry(filt,textvariable=self.query,width=25).pack(side='left',padx=2); ttk.Button(filt,text='Refresh',command=self.refresh).pack(side='left',padx=6)
"""
code = code.replace(db_ui_search, db_ui_replace)

# Bind the combobox
bind_search = "        self.query.trace_add('write',lambda *_: self.refresh()); self.refresh()"
bind_replace = "        self.query.trace_add('write',lambda *_: self.refresh()); self.db_alliance_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh()); self.refresh()"
code = code.replace(bind_search, bind_replace)

# Populate combobox in refresh
refresh_search = """    def refresh(self):
        kid=self.get_kid()"""
refresh_replace = """    def refresh(self):
        kid=self.get_kid()
        # Update alliance dropdown
        if kid is not None:
            with self.db.lock:
                tags = [r[0] for r in self.db.conn.execute('SELECT DISTINCT alliance_tag FROM players WHERE kid=? AND alliance_tag IS NOT NULL AND alliance_tag!="" ORDER BY alliance_tag', (kid,)).fetchall()]
                current = self.db_alliance_combo.cget('values')
                if list(current) != [''] + tags:
                    self.db_alliance_combo.configure(values=[''] + tags)
"""
code = code.replace(refresh_search, refresh_replace)

# Apply combobox filter to data
data_search = """        rows=self.db.atlas_rows(kid,q)"""
data_replace = """        tag_filter = getattr(self, 'db_alliance_filter', None)
        if tag_filter and tag_filter.get():
            rows = [r for r in self.db.atlas_rows(kid,q) if r['alliance_tag'] == tag_filter.get()]
        else:
            rows = self.db.atlas_rows(kid,q)"""
code = code.replace(data_search, data_replace)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("DB dropdown injected.")
