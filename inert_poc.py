#!/usr/bin/env python3
"""
PoC de test - declenche volontairement le pattern mmap(WRITE) -> mprotect(EXEC)
pour valider que la regle de correlation de l'agent EDR fonctionne.
(Version mise a jour Semaine 6 : journalisation cote attaquant ajoutee)
"""

import ctypes
import ctypes.util
import mmap
import time
import os
from attacker_log import log_attempt

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20

PAGE_SIZE = mmap.PAGESIZE

libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, ctypes.c_long,
]
libc.mprotect.restype = ctypes.c_int
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

print(f"[PoC] PID actuel : {os.getpid()}")
print("[PoC] Etape 1 : mmap avec PROT_READ | PROT_WRITE ...")

addr = libc.mmap(
    None, PAGE_SIZE,
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1, 0,
)
if addr == -1 or addr is None:
    errno = ctypes.get_errno()
    raise OSError(errno, f"mmap a echoue : {ctypes.get_errno()}")

print(f"[PoC] Memoire allouee a l'adresse {hex(addr)}")

buf = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ubyte))
buf[0] = 0x00
print("[PoC] Octet inoffensif ecrit (0x00) - pas de shellcode.")

print(f"[PoC] Pause de 1 seconde (a l'interieur de la fenetre de correlation de {3}s) ...")
time.sleep(1)

print("[PoC] Etape 2 : mprotect vers PROT_EXEC ...")
ret = libc.mprotect(addr, PAGE_SIZE, PROT_EXEC)
if ret != 0:
    errno = ctypes.get_errno()
    raise OSError(errno, f"mprotect a echoue : {errno}")

print("[PoC] mprotect reussi. Le pattern mmap(WRITE) -> mprotect(EXEC) a ete reproduit.")
print("[PoC] AUCUN code n'est execute dans cette region - ceci est purement demonstratif.")
print("[PoC] Verifie le terminal de l'agent EDR : une ligne '** ALERTE **' devrait etre visible.")

# --- NOUVEAU : journalisation cote attaquant ---
log_attempt(
    technique="Auto-modification memoire (mmap+mprotect)",
    mitre_id="T1055",
    target_pid=os.getpid(),
    target_process="soi-meme",
    success=True,
    details="Sequence mmap(WRITE) -> mprotect(EXEC) executee avec succes en ~1s",
)

libc.munmap(addr, PAGE_SIZE)
print("[PoC] Termine.")
