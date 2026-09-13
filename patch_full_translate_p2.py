import re

# Deep sweep pass 2 - catches everything the scanner found
def translate(code):
    replacements = [
        # Vision tab
        ("Résultats Clean Vision — SQL — V", "Clean Vision Results — SQL — V"),
        ("LOC Vision", "LOC Vision"),
        ("Puissance Vision", "Power Vision"),
        ("Statut Vision", "Vision Status"),
        ("Vu le", "Seen on"),
        ("Total ", "Total "),
        ("Vérifiés ", "Verified "),
        ("Partiels ", "Partial "),
        ("Conflits ", "Conflicts "),
        ("Non vus ", "Unseen "),
        ("Aucune capture enregistrée pour cette ligne.", "No capture recorded for this row."),
        ("Exporter résultats Vision", "Export Vision Results"),
        ("Export Vision", "Export Vision"),
        ("Export créé :\\n", "Export created:\\n"),

        # Verification
        ("Vérification", "Verification"),
        ("Une navigation est déjà active.", "Navigation is already active."),
        ("Aucun membre [", "No members ["),
        ("] avec coordonnées Atlas.", "] with Atlas coordinates."),
        ("Vérifier alliance", "Verify Alliance"),
        ("Visiter automatiquement", "Auto-visit"),
        ("membre(s) de [", "member(s) of ["),
        ("WOS doit être ouvert et la cart", "WOS must be open and the map"),
        ("Verification [", "Verification ["),
        ("interrompue:", "interrupted:"),

        # Session dialog
        ("Accepte soit la valeur Cookie brute, soit", "Accepts either a raw Cookie value or"),
        ("WOS Atlas Session effacée de la mémoire.", "WOS Atlas Session cleared from memory."),
        ("État invalide", "Invalid State"),
        ("Saisis un numéro d'État WOS valide.", "Enter a valid WOS State number."),
        ("Configure d'abord la session WOS Atlas avec le bouton « WOS Atlas Session » puis colle Copy as", "First configure the WOS Atlas session with the 'WOS Atlas Session' button then paste Copy as"),

        # Atlas import log messages
        ("Import Atlas État ", "Atlas Import State "),
        ("ÉCHEC API ATLAS : impossible de récupérer la liste des alliances de l'État", "ATLAS API FAILURE: unable to retrieve the alliance list for State"),
        ("ÉCHEC API ATLAS : réponse leaderboard invalide pour l'État", "ATLAS API FAILURE: invalid leaderboard response for State"),
        ("(champ entries absent/invalide). Import annulé.", "(entries field missing/invalid). Import cancelled."),
        ("ÉCHEC API ATLAS : impossible de récupérer les members de", "ATLAS API FAILURE: unable to retrieve members for"),
        ("AUTH WOS ATLAS : la session est absente ou expirée (viewerTier=ANONYMOUS). Recopie un nouveau « Copy as cURL »", "WOS ATLAS AUTH: session is missing or expired (viewerTier=ANONYMOUS). Paste a new Copy as cURL"),
        ("ÉCHEC API ATLAS : réponse /members invalide pour", "ATLAS API FAILURE: invalid /members response for"),
        ("Atlas history UID", "Atlas history UID"),
        ("erreur non bloquante:", "non-blocking error:"),
        ("Atlas power UID", "Atlas power UID"),
        ("Atlas: enrichissement terminé avec", "Atlas: enrichment finished with"),
        ("erreur(s) non bloquante(s); les joueurs valides ont été conservés.", "non-blocking error(s); valid players were retained."),
        ("Atlas ", "Atlas "),  # keep but catch "terminé" below
        ("terminé : ", "complete: "),

        # Live consolidation
        ("Consolidation LIVE active —", "LIVE Consolidation active —"),
        ("joueurs à enrichir", "players to enrich"),
        ("Map Discovery","Map Discovery"),
        ("Arrête d'abord la capture en cours avant de lancer un test carte.", "Stop the current capture before launching a map scan."),
        ("Map Discovery : reste 5–10 s immobile, déplace la carte plusieurs fois, fais un zoom/dézoom, sans ouvrir ville/profil/alliance/class", "Map Discovery: stay still 5-10s, drag the map several times, zoom in/out, without opening city/profile/alliance/rank"),
        ("Capture WOS arrêtée", "WOS Capture stopped"),
        ("CSV exporté", "CSV exported"),
        ("État invalide.", "Invalid State."),

        # Diagnostic report strings
        ("WOS Unified Manager V", "WOS Unified Manager V"),
        ("Base persistante:", "Persistent DB:"),
        ("WOS ID vérifiés/connus:", "Verified/known WOS IDs:"),
        ("En attente consolidation:", "Pending consolidation:"),
        ("ALLIANCES LES MOINS COUVERTES (ouvre celles-ci en priorité)", "LEAST COVERED ALLIANCES (open these first)"),
        ("members officiels vérifiés", "verified official members"),
        ("DERNIÈRE SESSION LIVE", "LAST LIVE SESSION"),
        ("capture_active: True (compteurs LIVE, sans attendre Stop Capture)", "capture_active: True (LIVE counters, without waiting for Stop Capture)"),
        ("50 PREMIERS NON CONSOLIDÉS", "FIRST 50 NOT CONSOLIDATED"),
        ("affichés", "shown"),
        ("IDENTITÉ (état actuel, pas un historique d'événements)", "IDENTITY (current state, not an event history)"),
        ("VERIFIED (WOS ID confirmé):", "VERIFIED (WOS ID confirmed):"),
        ("EN CONFLIT (candidature contestée, pas encore tranchée):", "IN CONFLICT (contested candidacy, not yet resolved):"),
        ("Identité: indisponible", "Identity: unavailable"),
        ("DÉCOUVERTE PROTOCOLE EXHAUSTIVE", "EXHAUSTIVE PROTOCOL DISCOVERY"),
        ("Trames WOS réassemblées sauvegardées:", "Saved reassembled WOS frames:"),
        ("ÉCHANTILLONS OPCODES NON CONNUS", "UNKNOWN OPCODE SAMPLES"),
        ("<tronqué>", "<truncated>"),
        ("ÉCHANTILLONS BRUTS CARTE (S>C 7D02 / 7902)", "RAW MAP SAMPLES (S>C 7D02 / 7902)"),
        ("Aucune grosse réponse carte sauvegardée dans cette session.", "No large map response saved in this session."),
        ("DÉCODEUR MAP V4.0.15", "MAP DECODER V4.0.15"),
        ("joueurs uniques:", "unique players:"),
        ("ancres Atlas-ID strictes:", "strict Atlas-ID anchors:"),
        ("Aucun bloc MAP ancré dans cette session.", "No MAP block anchored in this session."),
        ("Décodeur MAP: indisponible", "MAP Decoder: unavailable"),
        ("cibles Atlas décodées:", "decoded Atlas targets:"),
        ("7502 sauvegardées:", "7502 saved:"),
        ("compteurs décodés:", "decoded counters:"),
        ("Aucune paire ciblée complète dans cette session.", "No complete targeted pair in this session."),
        ("PAIRES BRUTES 7D02 -> 7502 (même compteur)", "RAW PAIRS 7D02 -> 7502 (same counter)"),
        ("Paires compteur exact affichées:", "Exact counter pairs shown:"),
        ("ÉCHANTILLON 7502 BRUTES", "RAW 7502 SAMPLES"),
        ("120 DERNIERS ÉVÉNEMENTS PROTOCOLE", "LAST 120 PROTOCOL EVENTS"),
        ("Événements: indisponibles", "Events: unavailable"),

        # Engine small fixes
        ("Offline analysis terminée.", "Offline analysis complete."),
        ("Discovery alliances exportée", "Alliance discovery exported"),
        ("Discovery État exportée", "State discovery exported"),
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
    print(f"Pass 2 translated: {filepath}")

print("Deep sweep pass 2 done.")
