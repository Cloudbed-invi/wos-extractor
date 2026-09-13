import re

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

translations = {
    # Scorecards
    "('Joueurs Atlas','players')": "('Atlas Players','players')",
    "('À consolider','pending')": "('Pending Consolidation','pending')",
    
    # Tree Columns
    "('lv','Niv.',55)": "('lv','Level',55)",
    "('pseudo','Pseudo',230)": "('pseudo','Name',230)",
    "('pseudo','Pseudo',200)": "('pseudo','Name',200)",
    "('result','Résultat',100)": "('result','Result',100)",
    "('detail','Détail',430)": "('detail','Detail',430)",
    
    # Navigation labels
    "('coord','Bouton coordonnées')": "('coord','Coordinates Button')",
    "('x','Champ X')": "('x','X Field')",
    "('y','Champ Y')": "('y','Y Field')",
    "('go','Bouton Aller')": "('go','Go Button')",
    "('city','Ville ciblée')": "('city','Target City')",
    "'Fenêtre WOS : non liée'": "'WOS Window : Unlinked'",
    "non calibrée": "uncalibrated",
    
    # Vision zones
    "('pseudo','Pseudo')": "('pseudo','Name')",
    "('coords','Coordonnées X/Y')": "('coords','X/Y Coordinates')",
    "('power','Puissance')": "('power','Power')",
    "' — coin haut-gauche'": "' — Top-Left corner'",
    "' — coin bas-droit'": "' — Bottom-Right corner'",
    
    # Verification
    "Aucune vérification lancée": "No verification started",
    
    # CSV Header
    "'Etat','Atlas ID','Pseudo','Alliance','X','Y','Niveau','Power Atlas','WOS ID','Power WOS','Derniere synchro Atlas'": "'State','Atlas ID','Name','Alliance','X','Y','Level','Atlas Power','WOS ID','WOS Power','Last Atlas Sync'",
}

for fr, en in translations.items():
    code = code.replace(fr, en)

# Inject the Reset button safely
btn_search = r"(ttk\.Button\(top,text='Diagnostic Export',command=self\.export_diagnostic\)\.pack\(side='left',padx=4\))"
btn_replace = r"\1; ttk.Button(top,text='Reset Everything',command=self.reset_everything).pack(side='left',padx=4)"
code = re.sub(btn_search, btn_replace, code)

# Inject the Reset Method
reset_method = """
    def reset_everything(self):
        from tkinter import messagebox
        import os, pathlib, sys
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to completely erase all players, alliances, and collected data? The application will close after resetting."):
            try:
                # Stop any active captures
                self.stop_live()
                
                # Close DB
                if hasattr(self, 'db') and self.db:
                    self.db.conn.close()
                
                # Delete files
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
if "def reset_everything" not in code:
    code = code.replace("    def export_diagnostic(self):", reset_method + "\n    def export_diagnostic(self):")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("Translations applied and Reset button injected safely.")
