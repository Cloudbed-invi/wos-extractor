import re

filepath = "wos_collector_engine.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

translations = {
    # Logging messages
    "MODE DÉCOUVERTE PROTOCOLE actif : toutes les trames WOS réassemblées seront sauvegardées (limite": "PROTOCOL DISCOVERY MODE active: all reassembled WOS frames will be saved (limit",
    "Mode découverte protocole désactivé.": "Protocol discovery mode disabled.",
    "ACTIVE-LAB arme": "ACTIVE-LAB armed",
    "Ouvre maintenant UNE SEULE FOIS ce profil dans WOS. V3.7 ignore les 7D02 auxiliaires et attend la requete profil primaire 6C7D.": "Open this profile EXACTLY ONCE in WOS now. V3.7 ignores auxiliary 7D02s and waits for the 6C7D primary profile request.",
    "SEQUENCE-LAB demarre": "SEQUENCE-LAB started",
    "cibles.": "targets.",
    "Ouvre maintenant :": "Open now:",
    "requetes capturees.": "requests captured.",
    "SEQUENCE-LAB capture": "SEQUENCE-LAB capture",
    "cible=": "target=",
    "dynamique=": "dynamic=",
    "SEQUENCE-LAB TERMINE. Clique Export Sequence.": "SEQUENCE-LAB FINISHED. Click Export Sequence.",
    "ouvre puis ferme": "open then close",
    "cinq fois.": "five times.",
    "Ferme le profil puis rouvre LE MEME joueur.": "Close the profile then reopen THE SAME player.",
    "COUNTER-LAB TERMINE. Clique Export Counter.": "COUNTER-LAB FINISHED. Click Export Counter.",
    "RAW-BUILDER ARME :": "RAW-BUILDER ARMED :",
    "Compteur brut courant=": "Current raw counter=",
    "prediction provisoire=": "provisional prediction=",
    "Ouvre maintenant CE profil. La prediction sera ajustee en temps reel sur chaque requete intermediaire.": "Open THIS profile now. The prediction will be adjusted in real-time on each intermediate request.",
    "precedent=": "previous=",
    "predit=": "predicted=",
    "reel=": "actual=",
    "PREDIT :": "PREDICTED :",
    "REEL   :": "ACTUAL   :",
    "RAW-DIAG ARME :": "RAW-DIAG ARMED :",
    "Ouvre CE profil une fois, attends 5 secondes, puis Stop Raw.": "Open THIS profile once, wait 5 seconds, then Stop Raw.",
    "payloads TCP bruts.": "raw TCP payloads.",
    "candidats observes sans cible.": "candidates observed without a target.",
    "ACTIVE-LAB VALIDE :": "ACTIVE-LAB VALIDATED :",
    "Roster contexte fermé": "Roster context closed",
    "AID corrélés": "correlated AIDs",
    "Roster contexte reconcilié": "Roster context reconciled",
    "identités de haut-niveau trouvées et écrites en DB.": "high-level identities found and written to DB.",
    "Audit roster : diagnostic indisponible": "Roster audit: diagnostic unavailable",
    "Découverte protocole :": "Protocol discovery:",
    "trames brutes sauvegardées": "raw frames saved",
    "erreur sauvegarde brute :": "raw save error:",
    "AID détectés,": "AIDs detected,",
    "nouveaux": "new",
    "Roster epoch fermé explicitement": "Roster epoch explicitly closed",
    "Atlas hints en attente d'une identité alliance supprimés": "Atlas hints waiting for an alliance identity discarded",
    "Alliance ID détectés,": "Alliance IDs detected,",
    "Roster classement détecté :": "Ranking roster detected:",
    "entrees compactes": "compact entries",
    "en attente des": "waiting for",
    "Candidat roster ignoré :": "Roster candidate ignored:",
    "entrees,": "entries,",
    "Atlas hints et taille hors plage classement": "Atlas hints and size out of ranking range",
    "Roster detecte :": "Roster detected:",
    "Atlas hints autoritaires": "authoritative Atlas hints",
    "nouveau roster": "new roster",
    "Atlas/roster bridge erreur:": "Atlas/roster bridge error:",
    "Roster epoch étendu via identité locale reconnue": "Roster epoch extended via recognized local identity",
    "Roster epoch ignoré": "Roster epoch ignored",
    "Identité non résolue malgré match DB": "Identity unresolved despite DB match",
    "Bloc non decode :": "Block not decoded:",
    "Atlas ignoré": "Atlas ignored",
    "hors plage classement": "out of ranking range",
    "Profil partiel sans alliance": "Partial profile without alliance",
    "identité alliance indisponible ou suspecte": "alliance identity unavailable or suspect",
    "Roster RAW-hint": "Roster RAW-hint",
    "ignoré pendant vote": "ignored during vote",
    "Profil WOS ID local 0": "Local WOS ID 0 Profile",
    "Erreur packet:": "Packet error:",
}

for fr, en in translations.items():
    code = code.replace(fr, en)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("French engine logs translated to English.")
