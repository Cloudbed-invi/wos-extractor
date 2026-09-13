import re

# Scan both files for French text
for filepath in ["WOS_Unified_Manager_V4_0_49.py", "wos_collector_engine.py"]:
    print(f"\n=== {filepath} ===")
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()
    
    accents = re.compile(r"[àâäéèêëîïôùûüçœæÀÂÄÉÈÊËÎÏÔÙÛÜÇŒÆ]")
    french_words = re.compile(r"\b(joueur|joueurs|membres|état|champ|bouton|cible|ville|ouvre|ferme|annuler|demarrer|choisir|puissance|coordonnées|résultat|décodés|journal|exporter|fenêtre|erreur|découverte|vérif|profil|classe|recher|trouver|attendre|limite|connecté|requête|réponse|Décodés|Joueurs|Blocs|Annuler|Demarrer|Choisir|Journal|Rapport|Valeur|Prévu|Observé|Analyse|Affich|Statut)\b", re.I)
    
    for i, line in enumerate(lines, 1):
        stripped = line.rstrip()
        if accents.search(stripped) or french_words.search(stripped):
            print(f"  L{i}: {stripped[:150]}")
