with open("WOS_Unified_Manager_V4_0_49.py", "r", encoding="utf-8") as f:
    code = f.read()

replacements = [
    # Comments
    ("# Une lecture OCR incomplète n'est PAS un conflit. On ne déclare\n        # VISION_CONFLICT que lorsque les coordonnées ont réellement été lues\n        # et contredisent la cible Atlas. Cela évite les faux conflits dus à\n        # des textes parasites (barre DeepL, UI Windows, boutons du jeu, etc.).",
     "# An incomplete OCR reading is NOT a conflict. VISION_CONFLICT is only declared\n        # when coordinates were actually read and contradict the Atlas target.\n        # This avoids false conflicts from parasitic text (DeepL bar, Windows UI, game buttons)."),
    ("# Une valeur Power déjà présente dans players ne prouve pas qu'elle a\n            # été revérifiée pendant CETTE visite. C'est ce qui faisait afficher\n            # Mori SEEN_OK avec une ancienne puissance de 37 M alors que la fiche\n            # courante affichait 217 M. On exige désormais une observation de\n            # puissance de la session courante pour déclarer SEEN_OK.",
     "# A Power value already present in players does not prove it was\n            # re-verified during THIS visit. We now require a power observation\n            # from the current session to declare SEEN_OK."),
    # Detail strings
    ("'Conflit réseau ou visuel : pseudo / localisation différents de la cible Atlas.'",
     "'Network or vision conflict: name / location different from Atlas target.'"),
    ("'Vision OK (pseudo, X/Y, puissance) ; WOS ID réseau encore manquant.' if aw is None else 'Vision OK mais puissance non promue.'",
     "'Vision OK (name, X/Y, power); WOS ID still missing from network.' if aw is None else 'Vision OK but power not promoted.'"),
    ("detail='Vision partielle ('+', '.join(bits)+') ; WOS ID ou puissance encore manquant.' if bits else 'Vision inexploitable ; WOS ID ou puissance toujours manquant après visite.'",
     "detail='Partial vision ('+', '.join(bits)+'); WOS ID or power still missing.' if bits else 'Vision unusable; WOS ID or power still missing after visit.'"),
    ("else: detail='WOS ID ou puissance toujours manquant après visite.'",
     "else: detail='WOS ID or power still missing after visit.'"),
    ("detail=f'Joueur revu; puissance revérifiée et mise à jour {int(bp):,} -> {int(ap):,}.'",
     "detail=f'Player revisited; power re-verified and updated {int(bp):,} -> {int(ap):,}.'"),
    ("detail='Joueur revu; WOS ID présent et puissance revérifiée pendant cette session.'",
     "detail='Player revisited; WOS ID present and power re-verified this session.'"),
    ("result='NOT_SEEN'; detail='Joueur revu, mais puissance NON revérifiée pendant cette visite : ancienne valeur conservée, pas de SEEN_OK.'",
     "result='NOT_SEEN'; detail='Player revisited, but power NOT re-verified this visit: old value kept, no SEEN_OK.'"),
    ("result='NOT_SEEN'; detail='Données complètes en base mais aucun record Atlas ancré revu pendant cette visite.'",
     "result='NOT_SEEN'; detail='Complete data in DB but no anchored Atlas record revisited this visit.'"),
    # Atlas API errors
    ("raise RuntimeError(f'ÉCHEC API ATLAS : impossible de récupérer la liste des alliances de l'État {kid}. Import annulé.')",
     "raise RuntimeError(f'ATLAS API FAILURE: unable to retrieve alliance list for State {kid}. Import cancelled.')"),
    ("raise RuntimeError(f'ÉCHEC API ATLAS : réponse leaderboard invalide pour l'État {kid} (entries field missing/invalid). Import cancelled.')",
     "raise RuntimeError(f'ATLAS API FAILURE: invalid leaderboard response for State {kid} (entries field missing/invalid). Import cancelled.')"),
    # Atlas members error
    ("WOS Atlas erreur", "WOS Atlas error"),
    ("réponse 200 mais members vide", "200 response but members empty"),
    ("attendu≈", "expected≈"),
    ("viewerTier=", "viewerTier="),
    # Navigation / window errors
    ("# ---------- Fenêtre WOS / bureau multi-écrans ----------", "# ---------- WOS Window / multi-monitor desktop ----------"),
    ("\"\"\"Retourne la fenêtre top-level située sous un point du bureau virtuel.\"\"\"", '"""Returns the top-level window under a point on the virtual desktop."""'),
    ("\"\"\"Retrouve la fenêtre calibrée même après redémarrage / déplacement d'écran.\"\"\"", '"""Finds the calibrated window even after restart / monitor move."""'),
    ("# Si plusieurs fenêtres ont la même classe, privilégie le titre exact puis la plus grande.", "# If multiple windows share the same class, prefer exact title then the largest."),
    ("'Navigation PC: fenêtre WOS calibrée introuvable. Recalibre un point dans la fenêtre WOS.'",
     "'PC Navigation: calibrated WOS window not found. Recalibrate a point in the WOS window.'"),
    ("raise RuntimeError('La fenêtre WOS est minimisée.')", "raise RuntimeError('The WOS window is minimized.')"),
    ("\"\"\"Convertit un point calibré relatif à WOS vers le bureau virtuel courant.\"\"\"", '"""Converts a calibrated point relative to WOS to the current virtual desktop."""'),
    ("raise RuntimeError(f'Point {key} non calibré')", "raise RuntimeError(f'Point {key} not calibrated')"),
    ("raise RuntimeError('Ancienne calibration absolue détectée : refais les 5 points de calibration.')", "raise RuntimeError('Legacy absolute calibration detected: redo the 5 calibration points.')"),
    ("\"\"\"Capture uniquement la fenêtre WOS, y compris si elle est sur un écran à coordonnées négatives.\"\"\"", '"""Captures only the WOS window, including if on a negative-coordinate monitor."""'),
    ("# V4.0.47 : calibration déterministe des 3 zones de la pancarte player.", "# V4.0.47: deterministic calibration of the 3 player card zones."),
    ("# Chaque rectangle est défini par deux coins, eux-mêmes relatifs à la fenêtre WOS.", "# Each rectangle is defined by two corners, themselves relative to the WOS window."),
    ("'non calibré'", "'not calibrated'"),
    ("'Calibration visuelle : zones pseudo / X-Y / puissance effacées.'", "'Visual calibration: name / X-Y / power zones cleared.'"),
    ("messagebox.showwarning('Fenêtre WOS non liée','Calibre d'abord au moins un des 5 points de navigation dans la fenêtre WOS.')",
     "messagebox.showwarning('WOS Window Not Linked','Calibrate at least one of the 5 navigation points in the WOS window first.')"),
    ("messagebox.showinfo('Calibration visuelle',f'After OK you have 3 seconds to place the mouse on :\\n{label}\\n\\nLa plaque player doit être ouvert",
     "messagebox.showinfo('Visual Calibration',f'After OK you have 3 seconds to place the mouse on:\\n{label}\\n\\nThe player card must be open"),
    ("messagebox.showerror('Calibration visuelle','Impossible d'identifier la fenêtre sous le curseur.')",
     "messagebox.showerror('Visual Calibration','Cannot identify the window under the cursor.')"),
    ("messagebox.showwarning('Calibration visuelle incomplète','Calibrate the plate zones before scanning",
     "messagebox.showwarning('Incomplete Visual Calibration','Calibrate the plate zones before scanning"),
    ("messagebox.showerror('Calibration','Impossible d'identifier la fenêtre sous le curseur.')",
     "messagebox.showerror('Calibration','Cannot identify the window under the cursor.')"),
    # MAP scan
    ("self.log(f'MAP Scan automatique : {total} position(s) à visiter. Déplace la souris dans le coin haut-gauche pour arrêt d'urgence PyAutoGUI.')",
     "self.log(f'Automatic MAP Scan: {total} position(s) to visit. Move mouse to top-left corner for PyAutoGUI emergency stop.')"),
    ("self.events.put(('refresh','MAP Scan terminé'))", "self.events.put(('refresh','MAP Scan complete'))"),
    # Clean Vision remaining
    ("messagebox.showinfo('Clean Vision','Aucune base Clean Vision créée.')", "messagebox.showinfo('Clean Vision','No Clean Vision database created.')"),
    # Atlas state number error
    ("messagebox.showerror('Invalid State','Saisis un numéro d'État WOS valide.')", "messagebox.showerror('Invalid State','Enter a valid WOS State number.')"),
    # Atlas session warning
    ("messagebox.showwarning('WOS Atlas Session','Configure d'abord la session WOS Atlas avec le bouton « WOS Atlas Session » puis colle Copy as",
     "messagebox.showwarning('WOS Atlas Session','First configure the WOS Atlas session using the WOS Atlas Session button, then paste Copy as"),
    # Map Discovery stop warning
    ("messagebox.showwarning('Map Discovery','Arrête d'abord la capture en cours avant de lancer un test carte.')",
     "messagebox.showwarning('Map Discovery','Stop the current capture before starting a map scan.')"),
    # Diagnostic lines
    ("=== IDENTITY (current state, not an event history) ===",
     "=== IDENTITY (current state, not an event history) ==="),
    ("lines += ['=== IDENTITÉ (état actuel, pas un historique d\\'événements) ===',",
     "lines += ['=== IDENTITY (current state, not an event history) ===',"),
    # Helper error
    ("raise RuntimeError(f'{key}: helper erreur {cp.returncode}: {(cp.stderr or \"\").strip()[:350]}')",
     "raise RuntimeError(f'{key}: helper error {cp.returncode}: {(cp.stderr or \"\").strip()[:350]}')"),
]

for fr, en in replacements:
    code = code.replace(fr, en)

with open("WOS_Unified_Manager_V4_0_49.py", "w", encoding="utf-8") as f:
    f.write(code)

print("Pass 4 complete.")
