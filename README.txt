V4.0.49 CLEAN VISION
- Nouveau bouton VISION PROPRE (base vierge).
- La base clean_vision.sqlite3 est recréée pour le test avec seulement Atlas ID, pseudo, alliance, X/Y comme entrées.
- Aucune ancienne puissance ni WOS ID n’est copiée.
- L’agent remplit pseudo observé, X/Y observés, puissance, statut, captures et texte OCR uniquement à partir de la visite courante.
- Une sauvegarde de la précédente base clean est faite avant remise à zéro.
- La base principale n’est pas utilisée pour promouvoir les puissances pendant ce benchmark.

WOS Unified Manager V4.0.41

- Base restauree depuis V4.0.35 (version qui demarrait).
- OCR totalement isole dans wos_ocr_helper.py : aucun import RapidOCR/ONNX au demarrage de la GUI.
- Si l'OCR plante, seul le helper s'arrete; le Manager reste ouvert.
- OCR accepte uniquement une puissance si le WOS ID est deja etabli.
- Captures conservees dans le dossier de session /screens.

WOS Unified Manager V4.0.35

NOUVEAU : diagnostic protocole par visite. Pendant chaque ouverture de ville, toutes les trames WOS reassemblees sont rattachees au joueur visite et ecrites dans %LOCALAPPDATA%\WOS_Unified_Manager\sessions\<session>\visits\VISIT_<AtlasID>_<pseudo>.txt. Cela permet d'isoler exactement le champ puissance sans OCR ni assouplir les gardes d'identite.

WOS Unified Manager V4.0.31

NOUVEAU — SCAN MAP / VERIFICATION
- Onglet « Scan MAP / Vérification ».
- Pilotage du PC par souris/clavier via PyAutoGUI : WOS n'est ni injecté ni modifié.
- Calibration de 4 positions : bouton coordonnées, champ X, champ Y, bouton Aller.
- Scan ciblé des joueurs incomplets, par alliance ou sur tout l'Etat.
- Le collecteur réseau continue de faire l'identification; l'automatisation sert seulement à provoquer le chargement des zones.
- Vérification d'alliance : revisite tous les membres Atlas et classe chaque ligne SEEN_OK / MISSING / CONFLICT / NOT_SEEN.
- Résultats de vérification enregistrés dans la base persistante.
- Arrêt d'urgence PyAutoGUI : déplacer la souris dans le coin supérieur gauche.

INSTALLATION
Lancer INSTALL_DEPENDENCIES.bat une fois pour installer les dépendances, dont pyautogui.

IMPORTANT
- La base persistante reste dans %%LOCALAPPDATA%%\WOS_Unified_Manager\data\wos_unified.sqlite3.
- Le scan n'invente jamais WOS ID ou puissance : les mêmes garde-fous du moteur de collecte restent applicables.
- NOT_SEEN signifie qu'aucun record ancré n'a été revu pendant la visite; cela ne signifie pas que les données existantes sont fausses.
- La navigation automatisée d'un jeu peut être soumise aux règles de l'éditeur : utilisation sous la responsabilité de l'utilisateur.

V4.0.27 : correction navigation X/Y PC. Les champs sont maintenant vidés explicitement puis remplis via presse-papiers Windows (Ctrl+V), avec délai d'ouverture et perte de focus avant Aller. Cela corrige les champs WOS qui ignoraient pyautogui.write/CTRL+A et conservaient les coordonnées par défaut.


V4.0.27 - Navigation PC : saisie X/Y via Windows SendInput scan-codes (compatible contrôles WOS qui ignorent pyautogui.write/Ctrl+V).

V4.0.31 - Navigation X/Y Google Play Games : suppression complete de Ctrl+A. Chaque champ est vide avec exactement 4 Backspace, puis les chiffres sont saisis via SendInput.

V4.0.31 - visite ville réelle
- Ajout d'un 5e point de calibration : Ville ciblée.
- Après saisie X/Y et Aller, le module attend le recentrage puis clique sur la ville.
- Scan MAP et Vérification utilisent désormais cette ouverture de ville avant l'attente réseau.
- Le panneau ville est fermé avec Escape avant la visite suivante.


V4.0.31
- Ajout d'un 6e point de calibration : Fermer ville.
- Après chaque visite, le logiciel clique explicitement sur le bouton/X de fermeture de la fiche ville.
- Le test de coordonnée vérifie désormais le cycle complet : aller -> ouvrir -> attendre -> fermer.


V4.0.31
- Suppression du point de calibration 'Fermer ville'.
- Après ouverture d'une ville, la fiche reste ouverte 5 secondes par défaut puis est fermée avec Echap.
- Le délai est visible dans l'onglet Scan MAP / Vérification et peut être ajusté si nécessaire.
- La fermeture par Echap évite tout clic accidentel sur une autre ville.

V4.0.33 - Fermeture ville : correction du binding Escape. Le scan-code ESC 0x01 est maintenant defini dans la couche Windows SendInput ; la V4.0.31 tentait SendInput sans avoir ESC dans sa table, puis retombait silencieusement sur pyautogui.press('esc').

V4.0.47 - correction environnement Python / Scapy
--------------------------------------------------
Le lanceur et l'installateur utilisaient potentiellement deux installations Python differentes.
INSTALL_DEPENDENCIES.bat cree maintenant un environnement local .venv et y installe Scapy,
PyAutoGUI, Pillow et RapidOCR. START_WOS_UNIFIED_MANAGER.bat reutilise exactement ce meme
Python. Cela evite le message « Scapy n'est pas disponible dans CE Python » apres une installation
faite avec un autre interpreteur Python.

V4.0.47 - CALIBRATION RELATIVE A LA FENETRE WOS
- Les 5 points de navigation ne sont plus stockes en coordonnees absolues du bureau Windows.
- Au premier point calibre, le Manager lie automatiquement la fenetre top-level sous le curseur (WOS / Google Play Games).
- Chaque point est stocke relativement au coin haut-gauche de cette fenetre.
- Si la fenetre WOS est deplacee vers un autre ecran, les clics sont recalcules automatiquement.
- Si la fenetre est introuvable ou minimisee, le scan s'arrete au lieu de cliquer ailleurs.
- L'agent visuel capture uniquement la fenetre WOS avec Pillow ImageGrab(all_screens=True), ce qui gere les ecrans places a gauche avec coordonnees negatives.
- Les anciennes calibrations absolues sont volontairement refusees : refaire les 5 points une seule fois.


V4.0.47 - CORRECTION POWER VISUELLE / SEEN_OK
- Crop vision remonte au-dessus du point ville pour inclure toute la pancarte (pseudo, X/Y, puissance).
- SEEN_OK exige maintenant une puissance réellement observée pendant la session courante.
- Une ancienne puissance complète en base n'est plus considérée comme vérifiée.
- Si l'agent valide pseudo + X/Y + puissance et que le WOS ID existe, la puissance courante est remplacée.


V4.0.47 - CALIBRATION VISUELLE PAR CHAMPS
- Ajoute 3 zones calibrables sur une plaque joueur STANDARD : Pseudo, X/Y, Puissance.
- Chaque zone est définie par coin haut-gauche + coin bas-droit, relatifs à la fenêtre WOS.
- L'agent OCR n'analyse plus un grand crop global : il lit séparément les 3 rectangles.
- Une puissance n'est promue que si pseudo + localisation correspondent à la cible Atlas.
- Les scans avec Agent visuel activé exigent désormais les 3 zones calibrées.
- Les captures de chaque champ sont conservées dans le dossier vision de la session.
