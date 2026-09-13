import re

# =====================================================================
# COMPREHENSIVE FRENCH → ENGLISH TRANSLATION PATCH
# Covers both WOS_Unified_Manager_V4_0_49.py and wos_collector_engine.py
# =====================================================================

def translate(code):
    replacements = [
        # ----- UI labels & buttons -----
        ("Démarrer capture", "Start Capture"),
        ("▶ Démarrer capture", "▶ Start Capture"),
        ("■ Arrêter", "■ Stop"),
        ("Données / Exports", "Data / Exports"),
        ("Exporter joueurs CSV", "Export Players CSV"),
        ("Exporter refresh queue", "Export Refresh Queue"),
        ("Analyser PCAPNG", "Analyze PCAPNG"),
        ("Blocs", "Blocks"),
        ("Décodés", "Decoded"),
        ("Joueurs", "Players"),
        ("Découverte", "Discovery"),
        ("Résolus", "Resolved"),
        ("Alliances découvertes", "Alliances Discovered"),
        ("Journal", "Log"),
        ("Prêt.", "Ready."),
        ("Capture arrêtée.", "Capture stopped."),
        ("Choisir capture", "Choose capture file"),
        ("Analyse offline", "Offline analysis"),
        ("Analyse offline terminée.", "Offline analysis complete."),
        ("Erreur offline:", "Offline error:"),
        ("File refresh exportée", "Refresh queue exported"),
        ("File refresh", "Refresh file"),
        ("Active Lab - Choisir un joueur", "Active Lab - Choose a player"),
        ("Aucune cible pending dans le roster courant.", "No pending target in the current roster."),
        ("Sélectionne un joueur puis double-clique, ou clique sur Armer.", "Select a player then double-click, or click Arm."),
        ("Annuler", "Cancel"),
        ("Armer la cible", "Arm Target"),
        ("Sequence Lab - Choisir 5 joueurs", "Sequence Lab - Choose 5 players"),
        ("Choisis exactement 5 joueurs.", "Choose exactly 5 players."),
        ("Sequence Lab : ouvre", "Sequence Lab: open"),
        ("Demarrer", "Start"),
        ("Counter Lab - Choisir un joueur", "Counter Lab - Choose a player"),
        ("Counter Lab : ouvre 5 fois", "Counter Lab: open 5 times"),
        ("Choisis UN joueur et ouvre/ferme son profil 5 fois.", "Choose ONE player and open/close their profile 5 times."),
        ("Démarrer x5", "Start x5"),
        ("Counter Lab arrêté.", "Counter Lab stopped."),
        ("Raw Counter Builder - Choisir une cible", "Raw Counter Builder - Choose a target"),
        ("Request Builder : ", "Request Builder: "),
        ("compteur prédit", "predicted counter"),
        ("Raw Builder armé", "Raw Builder armed"),
        ("Après Armer : ouvre immédiatement ce profil dans WOS, sans autre action.", "After Arming: immediately open this profile in WOS, without any other action."),
        ("Request Builder exporté", "Request Builder exported"),
        ("Counter Tracker exporté", "Counter Tracker exported"),
        ("Arme, ouvre ce profil UNE fois, attends 5 s, puis Stop Raw.", "Arm, open this profile ONCE, wait 5s, then Stop Raw."),
        ("Raw Diagnostic terminé", "Raw Diagnostic complete"),
        ("Raw Diagnostic exporté", "Raw Diagnostic exported"),
        ("Raw Counter exporté", "Raw Counter exported"),
        ("Couverture Alliances / État", "Alliance / State Coverage"),
        ("Rosters complets:", "Complete Rosters:"),
        ("Membres capturés:", "Captured Members:"),
        ("Profils résolus:", "Resolved Profiles:"),
        ("Annoncé", "Announced"),
        ("Capturés", "Captured"),
        ("Résolus", "Resolved"),
        ("Dernier roster", "Last Roster"),
        ("Couverture alliances exportée", "Alliance coverage exported"),
        ("Découverte alliances exportée", "Alliance discovery exported"),
        ("Découverte État exportée", "State discovery exported"),
        ("Exporter la base CSV puis quitter", "Export CSV database then quit"),
        ("détection...", "detecting..."),

        # ----- Diagnostic export -----
        ("Diagnostic Report copié dans le presse-papiers.", "Diagnostic Report copied to clipboard."),
        ("Snapshot SQLite cohérent, même si l'application continue à tourner.", "Consistent SQLite snapshot, even if the application keeps running."),
        ("Export joueurs de l'État sans dialogue supplémentaire.", "Export State players without extra dialog."),
        ("Journal visible: utile même si le PCAP n'est pas transférable.", "Visible log: useful even if the PCAP is not transferable."),
        ("journal.txt", "journal.txt"),
        ("Résumé machine + session + compteurs, sans cookies/token Atlas.", "Machine + session + counters summary, without Atlas cookies/token."),
        ("Inclure le PCAP de la session active/dernière s'il existe réellement.", "Include the PCAP of the active/last session if it really exists."),
        ("README_DIAGNOSTIC.txt", "README_DIAGNOSTIC.txt"),
        ("Diagnostic exporté", "Diagnostic exported"),
        ("Diagnostic Export créé:", "Diagnostic Export created:"),
        ("PCAP inclus", "PCAP included"),
        ("aucun PCAP disponible", "no PCAP available"),
        ("Diagnostic créé", "Diagnostic created"),
        ("Archive créée :\\n", "Archive created:\\n"),
        ("Tu peux me transmettre uniquement ce ZIP.", "You can send me just this ZIP file."),
        ("Erreur export diagnostic:", "Diagnostic export error:"),

        # ----- Engine logs -----
        ("Cette cible n'est pas pending dans le roster courant.", "This target is not pending in the current roster."),
        ("Aucune cible valide.", "No valid target."),
        ("Aucune reponse cible apres", "No target response after"),
        ("candidats /", "candidates /"),
        ("Correspondance cible par", "Target match by"),
        ("apres", "after"),
        ("candidats", "candidates"),
        ("Roster/7902 corrélé :", "Roster/7902 correlated:"),
        ("AID compatibles — ignoré", "compatible AIDs — ignored"),
        ("Batch 7902 ambigu ignoré pour le roster :", "Ambiguous 7902 batch ignored for roster:"),
        ("mappés,", "mapped,"),
        ("Roster/7902 corrélé en amont :", "Upstream roster/7902 correlated:"),
        ("AID du roster déjà vus", "roster AIDs already seen"),
        ("Roster identité CONSENSUS verrouillée :", "CONSENSUS identity roster locked:"),
        ("SEQUENCE-LAB ERREUR ouverture :", "SEQUENCE-LAB OPEN ERROR:"),
        ("decode les fiches membres avec le moteur V2.1 valide", "decodes member records with the validated V2.1 engine"),
        ("requêtes vers les serveurs WOS est volontairement desactivee tant que la", "requests to WOS servers are intentionally disabled as long as the"),

        # ----- Header/status bar -----
        ("Atlas: non connecté", "Atlas: not connected"),
        ("session configurée", "session configured"),
    ]

    for fr, en in replacements:
        code = code.replace(fr, en)
    return code


for filepath in ["WOS_Unified_Manager_V4_0_49.py", "wos_collector_engine.py"]:
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()
    code = translate(code)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(code)
    print(f"Translated: {filepath}")

print("\nAll done! Deep French sweep complete.")
