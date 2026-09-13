with open("WOS_Unified_Manager_V4_0_49.py", "r", encoding="utf-8") as f:
    code = f.read()

# Use direct Unicode strings since we're in a .py file
fixes = [
    (
        "messagebox.showwarning('Map Discovery','Arrête d'abord la capture en cours avant de lancer un test carte.')",
        "messagebox.showwarning('Map Discovery','Stop the current capture before starting a map scan.')"
    ),
    (
        "raise RuntimeError(f'ÉCHEC API ATLAS : impossible de récupérer la liste des alliances de l'État {kid}. Import annulé.')",
        "raise RuntimeError(f'ATLAS API FAILURE: unable to retrieve alliance list for State {kid}. Import cancelled.')"
    ),
    (
        "raise RuntimeError(f'ÉCHEC API ATLAS : réponse leaderboard invalide pour l'État {kid} (entries field missing/invalid). Import cancelled.')",
        "raise RuntimeError(f'ATLAS API FAILURE: invalid leaderboard response for State {kid} (entries field missing/invalid). Import cancelled.')"
    ),
    (
        "messagebox.showerror('Invalid State','Saisis un numéro d'État WOS valide.')",
        "messagebox.showerror('Invalid State','Enter a valid WOS State number.')"
    ),
    (
        "self.log(f'MAP Scan automatique : {total} position(s) à visiter. Déplace la souris dans le coin haut-gauche pour arrêt d'urgence PyAutoGUI.')",
        "self.log(f'Automatic MAP Scan: {total} position(s) to visit. Move mouse to top-left corner for PyAutoGUI emergency stop.')"
    ),
]

for fr, en in fixes:
    if fr in code:
        code = code.replace(fr, en)
        print(f"Fixed: {fr[:70]}")
    else:
        print(f"NOT FOUND: {fr[:70]}")

# WOS Atlas Session warning - find and replace with regex
import re
code = re.sub(
    r"messagebox\.showwarning\('WOS Atlas Session','Configure d.abord la session WOS Atlas avec le bouton [^']*then paste Copy as",
    "messagebox.showwarning('WOS Atlas Session','First configure the WOS Atlas session using the WOS Atlas Session button, then paste Copy as",
    code
)

# IDENTITY diagnostic line
code = re.sub(
    r"lines \+= \['=== IDENTIT[ÉE] \([^=]*\) ===',",
    "lines += ['=== IDENTITY (current state, not an event history) ===',",
    code
)

with open("WOS_Unified_Manager_V4_0_49.py", "w", encoding="utf-8") as f:
    f.write(code)

print("Final pass done.")
