import re

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Add the UI button
ui_search = "        ttk.Button(top,text='Diagnostic Export',command=self.export_diagnostic).pack(side='left',padx=4)"
ui_replace = """        ttk.Button(top,text='Diagnostic Export',command=self.export_diagnostic).pack(side='left',padx=4)
        ttk.Button(top,text='Reset Everything',command=self.reset_everything).pack(side='left',padx=4)"""
code = code.replace(ui_search, ui_replace)

# Add the method
reset_method = """
    def reset_everything(self):
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to completely erase all players, alliances, and collected data? The application will close after resetting."):
            try:
                # Stop any active captures
                self.stop_live()
                
                # Close DB
                if hasattr(self, 'db') and self.db:
                    self.db.conn.close()
                
                # Delete files
                import os, pathlib
                db_dir = pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home()/'AppData'/'Local')) / 'WOS_Unified_Manager' / 'data'
                for suffix in ['', '-wal', '-shm']:
                    f = db_dir / f'wos_unified.sqlite3{suffix}'
                    if f.exists():
                        try:
                            f.unlink()
                        except Exception as e:
                            self.log(f"Warning: Could not delete {f}: {e}")
                
                messagebox.showinfo("Reset Complete", "All data has been erased. The application will now close. Please restart it.")
                self.root.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset: {e}")
"""

# Insert the method before export_diagnostic
code = code.replace("    def export_diagnostic(self):", reset_method + "\n    def export_diagnostic(self):")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("Reset Everything button added!")
