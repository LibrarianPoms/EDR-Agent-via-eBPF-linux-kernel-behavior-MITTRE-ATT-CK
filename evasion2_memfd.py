#!/usr/bin/env python3
"""
EVASION 2 - memfd_create + mmap(PROT_EXEC) direct, sans mprotect
(Version mise a jour Semaine 6 : journalisation cote attaquant ajoutee)
Usage: python3 evasion2_memfd.py
"""

import ctypes
import ctypes.util
import os
import time
from attacker_log import log_attempt

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

MFD_CLOEXEC = 0x0001
PROT_READ, PROT_EXEC = 0x1, 0x4
MAP_SHARED = 0x01

libc.memfd_create.restype = ctypes.c_int
libc.memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, ctypes.c_long,
]

start_time = time.time()
print(f"[EVASION-2] PID actuel : {os.getpid()}")
print("[EVASION-2] Strategie : memfd_create + write() + mmap(PROT_EXEC) direct\n")

print("[EVASION-2] Etape 1/3 : memfd_create() ...")
fd = libc.memfd_create(b"evasion_test", MFD_CLOEXEC)
if fd == -1:
    raise OSError(ctypes.get_errno(), "memfd_create a echoue")
print(f"[EVASION-2] fd obtenu : {fd}")

print("[EVASION-2] Etape 2/3 : write() ...")
payload = b"\x00" * 4096
written = os.write(fd, payload)
print(f"[EVASION-2] {written} octets ecrits")

print("[EVASION-2] Etape 3/3 : mmap(PROT_EXEC) direct ...")
addr = libc.mmap(None, len(payload), PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0)
if addr == -1 or addr is None:
    raise OSError(ctypes.get_errno(), "mmap a echoue")
print(f"[EVASION-2] Mappe en executable a {hex(addr)} - aucun mprotect utilise")

total_delta = time.time() - start_time

print("\n[EVASION-2] Termine. Verifie le terminal de l'agent.")

# --- NOUVEAU : journalisation cote attaquant ---
log_attempt(
    technique="memfd_create + mmap direct - evasion correlation",
    mitre_id="T1055.009",
    target_pid=os.getpid(),
    target_process="soi-meme",
    success=True,
    details=f"Mapping executable cree via memfd_create en {total_delta:.2f}s, sans mprotect",
)

libc.munmap(addr, len(payload))
os.close(fd)
