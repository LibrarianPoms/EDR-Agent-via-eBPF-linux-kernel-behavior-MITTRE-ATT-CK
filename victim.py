#!/usr/bin/env python3
"""
Processus "victime" - PARTIE 1 du PoC d'injection cross-processus.
Alloue une petite zone memoire et affiche son PID + l'adresse de cette
zone, puis attend passivement. Le script "attaquant" (attacker_poc.py)
va s'attacher a ce processus via ptrace et y ecrire un octet inoffensif.

Usage: python3 victim.py
(le laisser tourner, puis lancer attacker_poc.py dans un AUTRE terminal
en lui donnant le PID et l'adresse affiches ici)
"""

import ctypes
import ctypes.util
import mmap
import os
import time

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

PROT_READ = 0x1
PROT_WRITE = 0x2
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
PAGE_SIZE = mmap.PAGESIZE

libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, ctypes.c_long,
]

addr = libc.mmap(
    None, PAGE_SIZE, PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
)
if addr == -1 or addr is None:
    raise OSError(ctypes.get_errno(), "mmap a echoue")

# On initialise la zone avec des zeros, pour voir clairement si elle
# a ete modifiee de l'exterieur.
buf = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ubyte))
for i in range(16):
    buf[i] = 0x00

pid = os.getpid()

print("=" * 60)
print("PROCESSUS VICTIME DEMARRE")
print("=" * 60)
print(f"PID de ce processus       : {pid}")
print(f"Adresse memoire ciblable  : {hex(addr)}")
print()
print("Dans un AUTRE terminal, lance :")
print(f"  sudo python3 attacker_poc.py {pid} {hex(addr)}")
print()
print("Ce processus va afficher le contenu de sa memoire toutes les")
print("2 secondes, pour que tu voies le changement en direct.")
print("Ctrl+C pour arreter.")
print("=" * 60)

try:
    while True:
        current = [buf[i] for i in range(8)]
        print(f"[victime] contenu memoire (8 premiers octets) : {current}")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nArret du processus victime.")
