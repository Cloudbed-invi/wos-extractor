import re

filepath = "wos_collector_engine.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

translations = {
    "Bloc sans Atlas ID (ignore) | alliance devinee": "Block without Atlas ID (ignore) | guessed alliance",
    "Roster identité ATLAS verrouillée :": "ATLAS identity roster locked :",
    "hints Atlas mappés": "mapped Atlas hints",
    "hints roster": "roster hints",
    "Roster verrouille": "Roster locked",
    "Atlas verifies": "verified Atlas",
    "Audit roster": "Roster audit",
    "WOS connus": "known WOS",
    "sans WOS": "without WOS",
    "conflits obs.": "conflicts obs.",
    "provisoires obs.": "provisional obs.",
    "doublons WOS": "WOS duplicates",
    "requête 7D02 cible confirmée": "target 7D02 request confirmed",
}

for fr, en in translations.items():
    code = code.replace(fr, en)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

filepath = "WOS_Unified_Manager_V4_0_49.py"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

translations = {
    "alliances trouvées.": "alliances found.",
    "membres": "members",
    "joueurs uniques. Historique + puissance...": "unique players. History + power...",
    "Import Atlas interrompu": "Atlas Import interrupted",
    "Consolidation LIVE État": "LIVE Consolidation State",
    "joueurs en attente. Ouvre simplement le classement WOS. V4.0.10 utilise les affiliations Atlas déjà importées comme ancrage et ne doit plus exiger l’ouverture alliance par alliance.": "players pending. Simply open the WOS ranking. V4.0.10 uses the already imported Atlas affiliations as an anchor and no longer requires opening alliance by alliance.",
    "Joueurs enrichis": "Players enriched",
    "(erreurs non bloquantes:": "(non-blocking errors:",
}

for fr, en in translations.items():
    code = code.replace(fr, en)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

print("More French logs translated!")
