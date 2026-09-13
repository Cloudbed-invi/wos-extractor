import re

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

replacements = {
    "Consolider WOS LIVE": "Consolidate WOS Live",
    "Découverte CARTE": "Map Discovery",
    "Importer WOS Atlas": "Import WOS Atlas",
    "Session WOS Atlas": "WOS Atlas Session",
    "Valider": "Validate",
    "Effacer session": "Clear Session",
    "Fermer": "Close",
    "Colle ici Copy as cURL de WOS Atlas, ou uniquement les cookies wos_at + wos_rt.": "Paste Copy as cURL from WOS Atlas here, or just wos_at + wos_rt cookies.",
    "La session reste uniquement en mémoire pendant cette exécution et n’est pas enregistrée dans le ZIP ou la base.": "The session remains in memory only during this execution and is not saved to ZIP or database.",
    "Arrêter capture": "Stop Capture",
    "Ouvrir capture": "Open Capture",
    "Export diagnostic": "Diagnostic Export",
    "Ouvrir dossier DB": "Open DB Folder",
    "Rapport diagnostic": "Diagnostic Report",
    "Copier tout": "Copy All",
    "Journal / Live": "Log / Live",
    "Base joueurs": "Player Database",
    "État sélectionné": "Selected State",
    "Recherche :": "Search:",
    "Filtre :": "Filter:",
    "Actualiser": "Refresh",
    "Exporter CSV": "Export CSV",
    "Scan MAP / Vérification": "MAP Scan / Verification",
    "Vérification d’une alliance": "Alliance Verification",
    "Alliance :": "Alliance:",
    "État :": "State:",
    "Lancer vérification": "Start Verification",
    "Scan ciblé des comptes manquants": "Targeted scan of missing accounts",
    "Seulement WOS ID / puissance manquants": "Only missing WOS ID / power",
    "Démarrer scan automatique": "Start Auto Scan",
    "ARRÊTER navigation": "STOP Navigation",
    "Temps ville ouverte (s) :": "Open City Time (s):",
    "Calibration V4.0.49 : navigation + zones visuelles sont enregistrées RELATIVEMENT à la fenêtre WOS. Tu peux déplacer WOS sur l’autre écran sans recalibrer.": "Calibration V4.0.49: navigation + visual zones are saved RELATIVE to the WOS window. You can move WOS to another screen without recalibrating.",
    "Navigation PC (souris/clavier)": "PC Navigation (mouse/keyboard)",
    "Calibrer ": "Calibrate ",
    "Tester une coordonnée": "Test Coordinate",
    "Calibration visuelle de la plaque joueur (profil standard)": "Visual calibration of player plate (standard profile)",
    "Ouvre manuellement une plaque joueur standard puis calibre les coins HG/BD de chaque zone. L’agent ne lira ensuite QUE ces rectangles.": "Manually open a standard player plate then calibrate Top-Left/Bottom-Right corners. The agent will ONLY read these rectangles.",
    "Effacer zones visuelles": "Clear Visual Zones",
    "Agent visuel : pseudo + puissance + X/Y": "Visual Agent: nickname + power + X/Y",
    "Ouvrir résultats Vision": "Open Vision Results",
    "VISION PROPRE (base vierge)": "CLEAN VISION (empty DB)",
    "Le module visite chaque ville. L’agent visuel vérifie pseudo + puissance + X/Y ; le réseau conserve la récupération du WOS ID.": "The module visits each city. The visual agent verifies nickname+power+X/Y; the network retains WOS ID recovery.",
    "Annuler": "Cancel",
    "Coin HG": "Top-Left",
    "Coin BD": "Bottom-Right",
    "Actualiser alliances": "Refresh Alliances",
}

for fr, en in replacements.items():
    content = content.replace(fr, en)

# Do the same for the engine
with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

# And translate engine logs
with open("wos_collector_engine.py", "r", encoding="utf-8") as f:
    c = f.read()

c = c.replace("Capture LIVE démarrée. Ouvre WOS puis une liste d'alliance.", "LIVE Capture started. Open WOS then an alliance list.")
c = c.replace("Capture arrêtée et session enregistrée.", "Capture stopped and session saved.")
c = c.replace("CSV exporté :", "CSV exported:")
c = c.replace("ÉCHEC API ATLAS", "ATLAS API FAILED")
c = c.replace("Import annulé", "Import canceled")
c = c.replace("Session WOS Atlas effacée de la mémoire.", "WOS Atlas session cleared from memory.")
c = c.replace("Session WOS Atlas configurée", "WOS Atlas session configured")

with open("wos_collector_engine.py", "w", encoding="utf-8") as f:
    f.write(c)

print("V4 Translation Complete!")
