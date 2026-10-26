#!/usr/bin/env python3
"""
attacker_log.py - Module partage de journalisation "cote attaquant".

Chaque script d'attaque (evasion1/2/3, attacker_poc.py, inert_poc.py)
importe ce module et appelle log_attempt() a la fin de son execution,
pour enregistrer ce qu'il a techniquement accompli - independamment de
savoir si l'agent EDR l'a detecte ou non (un vrai attaquant n'a
generalement pas cette visibilite ; ici, elle est ajoutee uniquement a
des fins pedagogiques, pour comparer cote a cote la vue attaquant et la
vue defenseur dans deux tableaux de bord separes).

Le journal est ecrit dans ~/attacker_logs/attempts.jsonl (separe du
journal de l'agent EDR, qui reste dans ~/edr_agent_logs/).
"""

import json
import os
import time

LOG_DIR = os.path.expanduser("~/attacker_logs")
os.makedirs(LOG_DIR, exist_ok=True)
ATTEMPTS_FILE = os.path.join(LOG_DIR, "attempts.jsonl")


def log_attempt(technique, mitre_id, target_pid=None, target_process=None,
                 success=True, details=""):
    """Enregistre une tentative d'attaque du point de vue de l'attaquant.

    technique     : nom lisible de la technique (ex: "Injection ptrace")
    mitre_id      : identifiant MITRE ATT&CK correspondant
    target_pid    : PID de la victime, si applicable (None si auto-cible)
    target_process: nom du processus victime, si connu
    success       : le mecanisme technique a-t-il fonctionne (ecriture
                    memoire reussie, mapping executable cree, etc.) -
                    PAS une indication de detection/evasion
    details       : description libre (delai mesure, methode utilisee...)
    """
    entry = {
        "timestamp": time.time(),
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
        "actor_pid": os.getpid(),
        "technique": technique,
        "mitre_id": mitre_id,
        "target_pid": target_pid,
        "target_process": target_process,
        "success": success,
        "details": details,
    }
    with open(ATTEMPTS_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry
