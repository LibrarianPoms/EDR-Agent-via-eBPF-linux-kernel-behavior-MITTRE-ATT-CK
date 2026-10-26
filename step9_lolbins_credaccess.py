#!/usr/bin/env python3
"""
Step 9 - Agent EDR avec detection LOLBins (T1218) et acces aux
identifiants (T1003) - Semaine 6

Ajoute deux nouvelles techniques de detection, distinctes de l'injection
de processus (T1055) deja couverte, afin de satisfaire le critere de
reussite du cahier des charges ("au moins 3 techniques distinctes"):

  T1218 - Abus de LOLBins (System Binary Proxy Execution) :
    Detecte l'execution de binaires legitimes souvent detournes a des
    fins malveillantes (curl, wget, nc, base64, openssl, etc.) lorsque
    leur processus PARENT n'est pas un shell interactif habituel -
    signe qu'ils ont ete lances de facon programmatique/automatisee
    plutot que tapes manuellement par un utilisateur.

  T1003 - Acces aux identifiants (OS Credential Dumping) :
    Detecte toute tentative de lecture des fichiers /etc/shadow ou
    /etc/gshadow (bases de mots de passe systeme). Le filtrage est
    effectue directement dans le noyau (comparaison de chaine exacte)
    afin d'eviter de faire transiter chaque appel openat() du systeme
    (des milliers par seconde) a travers le tampon vers l'espace
    utilisateur.

Usage: sudo python3 step9_lolbins_credaccess.py [--auto-kill] [--verbose]
"""

from bcc import BPF
from bcc.utils import printb
import time
import json
import os
import sys
import signal

AUTO_KILL_ENABLED = "--auto-kill" in sys.argv
VERBOSE = "--verbose" in sys.argv

real_user = os.environ.get("SUDO_USER")
if real_user:
    LOG_DIR = f"/home/{real_user}/edr_agent_logs"
else:
    LOG_DIR = os.path.expanduser("~/edr_agent_logs")

os.makedirs(LOG_DIR, exist_ok=True)

if real_user:
    import pwd
    uid = pwd.getpwnam(real_user).pw_uid
    gid = pwd.getpwnam(real_user).pw_gid
    os.chown(LOG_DIR, uid, gid)

ALERTS_FILE = os.path.join(LOG_DIR, "alerts.jsonl")
STATS_FILE = os.path.join(LOG_DIR, "stats.json")

# ------------------------------------------------------------------
# Programme eBPF (C)
# ------------------------------------------------------------------
bpf_program = """
#include <linux/sched.h>

#define EVENT_EXEC           1
#define EVENT_MMAP           2
#define EVENT_MPROTECT       3
#define EVENT_PTRACE         4
#define EVENT_VM_WRITEV      5
#define EVENT_SENSITIVE_FILE 6

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 event_type;
    long prot_flags;
    long map_flags;
    long ptrace_request;
    long ptrace_target;
    long vm_writev_target;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

static void fill_common(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    fill_common(&data);
    data.event_type = EVENT_EXEC;
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    struct data_t data = {};
    fill_common(&data);
    data.event_type = EVENT_MMAP;
    data.prot_flags = args->prot;
    data.map_flags = args->flags;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    struct data_t data = {};
    fill_common(&data);
    data.event_type = EVENT_MPROTECT;
    data.prot_flags = args->prot;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct data_t data = {};
    fill_common(&data);
    data.event_type = EVENT_PTRACE;
    data.ptrace_request = args->request;
    data.ptrace_target = args->pid;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev) {
    struct data_t data = {};
    fill_common(&data);
    data.event_type = EVENT_VM_WRITEV;
    data.vm_writev_target = args->pid;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// --- NOUVEAU (T1003) : comparaison de chaine exacte, bornee, sans boucle
// non bornee (contrainte du verifieur eBPF - voir cahier des charges 3.2) ---
static inline int path_is_shadow_file(const char *path) {
    // "/etc/shadow" = 11 caracteres + terminateur nul
    const char target[] = "/etc/shadow";
    #pragma unroll
    for (int i = 0; i < sizeof(target); i++) {
        if (path[i] != target[i]) return 0;
    }
    return 1;
}

static inline int path_is_gshadow_file(const char *path) {
    const char target[] = "/etc/gshadow";
    #pragma unroll
    for (int i = 0; i < sizeof(target); i++) {
        if (path[i] != target[i]) return 0;
    }
    return 1;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char path[32] = {};
    bpf_probe_read_user_str(&path, sizeof(path), (void *)args->filename);

    if (path_is_shadow_file(path) || path_is_gshadow_file(path)) {
        struct data_t data = {};
        fill_common(&data);
        data.event_type = EVENT_SENSITIVE_FILE;
        __builtin_memcpy(&data.filename, path, sizeof(path));
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

PROT_READ, PROT_WRITE, PROT_EXEC = 0x1, 0x2, 0x4
MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS = 0x01, 0x02, 0x20
PTRACE_ATTACH, PTRACE_SEIZE = 16, 0x4206
PTRACE_POKETEXT, PTRACE_POKEDATA = 4, 5
PTRACE_SETREGS, PTRACE_CONT, PTRACE_DETACH = 13, 7, 17

PTRACE_NAMES = {
    0: "TRACEME", 1: "PEEKTEXT", 2: "PEEKDATA", 4: "POKETEXT", 5: "POKEDATA",
    7: "CONT", 8: "KILL", 9: "SINGLESTEP", 12: "GETREGS", 13: "SETREGS",
    16: "ATTACH", 17: "DETACH", 0x4200: "SETOPTIONS", 0x4206: "SEIZE",
}

def decode_prot(flags):
    parts = []
    if flags & PROT_READ: parts.append("R")
    if flags & PROT_WRITE: parts.append("W")
    if flags & PROT_EXEC: parts.append("X")
    return "".join(parts) if parts else "NONE"

EVENT_NAMES = {1: "EXEC", 2: "MMAP", 3: "MPROTECT", 4: "PTRACE", 5: "VM_WRITEV", 6: "SENSITIVE_FILE"}

NOISY_PROCESSES = {
    b"gnome-shell", b"Xorg", b"Xwayland", b"firefox", b"firefox-bin",
    b"chrome", b"gnome-terminal-", b"ptyxis-agent", b"gjs", b"mutter",
    b"ibus-daemon", b"gsd-", b"tracker-", b"evolution-", b"pipewire",
    b"wireplumber", b"dpkg", b"apt", b"apt-get", b"apt-check",
    b"unattended-upgr", b"packagekit", b"snapd", b"sh", b"bash",
    b"echo", b"touch", b"cat", b"grep", b"cut", b"awk", b"sed",
    b"cron", b"systemd", b"anacron", b"(systemd-timed)", b"ptyxis",
    b"gdb", b"ldconfig",
}

def is_noisy(comm):
    return any(comm.startswith(prefix) for prefix in NOISY_PROCESSES)

# NOUVEAU : version string (pour comparer un nom resolu via /proc, pas les
# bytes bruts captures par eBPF) - necessaire car certains processus (les
# threads internes de Firefox notamment : "DOM Worker", "StyleThread", etc.)
# renomment leur PROPRE thread via prctl(), ce qui fait que le nom capture
# par la sonde eBPF (bpf_get_current_comm) ne correspond pas au nom du
# PROCESSUS reel, meme si le PID (tgid) est bien le meme.
NOISY_PROCESSES_STR = {p.decode() for p in NOISY_PROCESSES}

def is_noisy_process_by_pid(pid):
    """Resout le VRAI nom du processus via /proc/<pid>/comm (qui reflete le
    thread principal / la commande d'origine, contrairement au nom du
    thread courant capture par eBPF) et verifie s'il est dans la liste de
    bruit connu."""
    real_name = resolve_process_name(pid)
    return any(real_name.startswith(prefix) for prefix in NOISY_PROCESSES_STR)

def is_interesting_despite_noise(event):
    if event.event_type in (2, 3) and (event.prot_flags & PROT_EXEC):
        return True
    if event.event_type in (4, 5, 6):
        return True
    return False

CRITICAL_PROCESSES = {
    "sshd", "ssh-agent", "gpg-agent", "gnome-keyring", "polkitd",
    "systemd", "sudo", "su", "NetworkManager", "dbus-daemon",
    "gdm3", "gdm-password", "accounts-daemon", "cron", "login",
}

def resolve_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except (FileNotFoundError, ProcessLookupError):
        return "inconnu (processus termine ?)"

def compute_severity(target_pid):
    target_name = resolve_process_name(target_pid)
    if target_name in CRITICAL_PROCESSES:
        return "CRITIQUE", target_name
    return "HIGH", target_name

# ------------------------------------------------------------------
# NOUVEAU (T1218) : liste de binaires legitimes frequemment detournes
# (LOLBins / GTFOBins sur Linux). Liste illustrative, non exhaustive.
# ------------------------------------------------------------------
LOLBIN_NAMES = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "base64", "xxd",
    "openssl", "nmap", "certutil",
    # NOTE : python3/perl/php/ruby et awk/find/tar ont ete retires de
    # cette liste. Testes en conditions reelles (bureau GNOME actif), ils
    # generaient un volume important de faux positifs : ces outils sont
    # utilises en permanence par des composants systeme legitimes
    # (ex: xdg-mime invoquant awk pour la detection de type de fichier).
    # Une detection LOLBins fiable sur ces binaires necessiterait une
    # analyse plus fine (ligne de commande complete, chemin d'execution)
    # plutot qu'une simple correspondance de nom - limite documentee
    # dans le rapport final.
}

# Processus parents "normaux" d'ou l'utilisateur lance des commandes
# interactivement. Si le parent n'est PAS dans cette liste, l'execution
# d'un LOLBin est consideree comme potentiellement automatisee/suspecte.
SHELL_PARENTS = {
    "bash", "zsh", "sh", "dash", "fish", "ptyxis-agent",
    "gnome-terminal-", "tmux", "screen", "ssh", "sudo",
}

def basename_of(path_bytes):
    try:
        path_str = path_bytes.decode(errors="replace")
    except Exception:
        return ""
    return path_str.rstrip("\x00").split("/")[-1]

def write_alert(alert):
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def write_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f)

open(ALERTS_FILE, "w").close()

def respond_to_threat(pid):
    if not AUTO_KILL_ENABLED:
        return "NON_APPLIQUE (mode observation seule)"
    try:
        os.kill(pid, signal.SIGKILL)
        return f"PROCESSUS TERMINE (SIGKILL envoye a PID {pid})"
    except ProcessLookupError:
        return "ECHEC (processus deja termine)"
    except PermissionError:
        return "ECHEC (permission refusee)"

CORRELATION_WINDOW_SEC = 3.0
recent_write_mmap = {}

ptrace_state = {}
PTRACE_STATE_MAX_AGE_SEC = 600

# NOUVEAU : deduplication des alertes. BCC peut parfois livrer le meme
# evenement plusieurs fois de suite lors du polling du tampon (variation
# de timing entre coeurs CPU) - ceci evite d'afficher/journaliser la
# meme alerte plusieurs fois pour un seul evenement reel.
recent_alerts = {}  # (pid, technique_id) -> timestamp du dernier affichage
ALERT_DEDUP_WINDOW_SEC = 5.0

def already_alerted_recently(pid, technique_id):
    key = (pid, technique_id)
    now = time.time()
    last = recent_alerts.get(key)
    recent_alerts[key] = now
    return last is not None and (now - last) < ALERT_DEDUP_WINDOW_SEC

alert_count = 0
event_count = 0
suppressed_count = 0
AGENT_START = time.time()

b = BPF(text=bpf_program)

print(f"[+] Logs : {LOG_DIR}")
print(f"[+] Reponse automatisee : {'ACTIVEE' if AUTO_KILL_ENABLED else 'DESACTIVEE (observation seule)'}")
print(f"[+] Mode d'affichage : {'VERBEUX' if VERBOSE else 'ALERTES UNIQUEMENT (--verbose pour tout voir)'}")
print("[+] Techniques couvertes : T1055 (+ sous-techniques), T1218 (LOLBins), T1003 (identifiants)")
print(f"[+] Priorisation : {len(CRITICAL_PROCESSES)} processus critiques\n")
if VERBOSE:
    print(f"{'PID':<8} {'PPID':<8} {'EVENT':<14} {'DETAIL':<24} {'COMM':<16} {'INFO'}")
    print("-" * 110)

def log_alert(technique_id, technique_name, actor_pid, actor_comm, target_pid,
              extra_info, description_fr, response_result, severity_override=None):
    if severity_override:
        severity, target_name = severity_override, resolve_process_name(target_pid)
    else:
        severity, target_name = compute_severity(target_pid)
    alert = {
        "timestamp": time.time(),
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mitre_id": technique_id,
        "mitre_name": technique_name,
        "actor_pid": actor_pid,
        "actor_process": actor_comm,
        "target_pid": target_pid,
        "target_process": target_name,
        "extra_info": extra_info,
        "severity": severity,
        "description_fr": description_fr,
        "response_action": response_result,
    }
    write_alert(alert)
    return alert, severity, target_name

def cleanup_stale_ptrace_state(now):
    stale = [pid for pid, s in ptrace_state.items() if (now - s["attach_time"]) > PTRACE_STATE_MAX_AGE_SEC]
    for pid in stale:
        del ptrace_state[pid]

def print_event(cpu, data, size):
    global alert_count, event_count, suppressed_count

    event = b["events"].event(data)
    event_count += 1

    noisy = is_noisy(event.comm)
    if noisy and not is_interesting_despite_noise(event):
        suppressed_count += 1
        return

    event_name = EVENT_NAMES.get(event.event_type, "?")
    now = time.time()
    info = ""
    detail = "-"
    comm_str = event.comm.decode(errors="replace")

    if event.event_type == 1:
        # --- NOUVEAU (T1218) : detection LOLBins ---
        bname = basename_of(event.filename)
        detail = bname
        if bname in LOLBIN_NAMES:
            parent_name = resolve_process_name(event.ppid)
            if parent_name not in SHELL_PARENTS and not already_alerted_recently(event.pid, "T1218"):
                alert_count += 1
                response = respond_to_threat(event.pid)
                _, severity, _ = log_alert(
                           "T1218", "System Binary Proxy Execution (LOLBins)",
                           event.pid, comm_str, event.pid,
                           f"parent: {parent_name}",
                           f"Le binaire legitime « {bname} » a ete execute (PID {event.pid}) "
                           f"avec pour processus parent « {parent_name} », qui n'est pas un "
                           f"shell interactif habituel - schema typique d'une execution "
                           f"automatisee/programmee plutot qu'une commande utilisateur.",
                           response, severity_override="MEDIUM")
                info = f"** ALERTE [MEDIUM] (LOLBin: {bname}, parent: {parent_name}) ** - Reponse: {response}"

    elif event.event_type == 2:
        detail = decode_prot(event.prot_flags)
        if event.prot_flags & PROT_WRITE:
            recent_write_mmap[event.pid] = now
            info = "mmap WRITE - surveillance activee"

        if (event.prot_flags & PROT_EXEC) and (event.map_flags & MAP_SHARED):
            alert_count += 1
            response = respond_to_threat(event.pid)
            _, severity, target_name = log_alert(
                       "T1055.009", "Process Injection (Proc Memory - memfd/mmap direct)",
                       event.pid, comm_str, event.pid,
                       "mmap(PROT_EXEC | MAP_SHARED)",
                       f"Le processus « {comm_str} » (PID {event.pid}) a mappe de la "
                       f"memoire directement executable via un mapping partage (MAP_SHARED).",
                       response)
            info = f"** ALERTE [{severity}] (mmap EXEC+SHARED) ** cible: {target_name} - Reponse: {response}"

    elif event.event_type == 3:
        detail = decode_prot(event.prot_flags)
        if event.prot_flags & PROT_EXEC:
            last_write = recent_write_mmap.get(event.pid)
            # CORRECTIF : les navigateurs (Firefox, Chrome) et gnome-shell
            # font du JIT (compilation a la volee) en continu, ce qui
            # correspond exactement au pattern mmap(WRITE)->mprotect(EXEC)
            # surveille ici. On garde leur activite VISIBLE (mode verbose)
            # mais on ne declenche plus d'ALERTE pour cette regle precise
            # les concernant - contrairement aux regles cross-processus
            # (ptrace, process_vm_writev), qui elles restent actives pour
            # tout processus, JIT ou non, car jamais legitimes pour un
            # navigateur.
            if last_write and (now - last_write) <= CORRELATION_WINDOW_SEC and not is_noisy_process_by_pid(event.pid):
                alert_count += 1
                delta = now - last_write
                response = respond_to_threat(event.pid)
                _, severity, target_name = log_alert(
                           "T1055", "Process Injection (self-modification)",
                           event.pid, comm_str, event.pid, f"delai {delta:.2f}s",
                           f"Le processus « {comm_str} » (PID {event.pid}) a modifie sa "
                           f"propre memoire pour la rendre executable en {delta:.2f}s.",
                           response)
                info = f"** ALERTE [{severity}] (auto-modif) ** en {delta:.2f}s cible: {target_name} - Reponse: {response}"

    elif event.event_type == 4:
        req = event.ptrace_request
        target = event.ptrace_target
        req_name = PTRACE_NAMES.get(req, str(req))
        detail = f"{req_name} -> PID {target}"

        if req in (PTRACE_ATTACH, PTRACE_SEIZE):
            ptrace_state[event.pid] = {"victim": target, "attach_time": now, "poked": False}
            info = f"Attachement a PID {target} - surveillance activee"

        elif req in (PTRACE_POKETEXT, PTRACE_POKEDATA):
            state = ptrace_state.get(event.pid)
            if state and state["victim"] == target:
                state["poked"] = True
                info = f"Ecriture memoire dans PID {target} apres attachement"

        elif req in (PTRACE_CONT, PTRACE_SETREGS, PTRACE_DETACH):
            state = ptrace_state.get(event.pid)
            if state and state["victim"] == target and state["poked"]:
                alert_count += 1
                total_delta = now - state["attach_time"]
                response = respond_to_threat(event.pid)
                _, severity, target_name = log_alert(
                           "T1055.008", "Process Injection (ptrace, cross-process)",
                           event.pid, comm_str, target, f"duree totale {total_delta:.2f}s",
                           f"Le processus « {comm_str} » (PID {event.pid}) s'est attache "
                           f"au processus PID {target}, y a ecrit des donnees, puis a repris "
                           f"son execution, en {total_delta:.2f}s au total.",
                           response)
                info = f"** ALERTE [{severity}] (INJECTION CROSS-PROCESSUS) ** PID {event.pid} -> PID {target} ({target_name}) - Reponse: {response}"
                del ptrace_state[event.pid]

        cleanup_stale_ptrace_state(now)

    elif event.event_type == 5:
        target = event.vm_writev_target
        detail = f"WRITEV -> PID {target}"
        alert_count += 1
        response = respond_to_threat(event.pid)
        _, severity, target_name = log_alert(
                   "T1055.012", "Process Injection (Process Hollowing / proc_vm_writev)",
                   event.pid, comm_str, target, "appel unique process_vm_writev",
                   f"Le processus « {comm_str} » (PID {event.pid}) a ecrit directement "
                   f"dans la memoire du processus PID {target} via process_vm_writev.",
                   response)
        info = f"** ALERTE [{severity}] (INJECTION via process_vm_writev) ** PID {event.pid} -> PID {target} ({target_name}) - Reponse: {response}"

    elif event.event_type == 6:
        # --- NOUVEAU (T1003) : acces a un fichier d'identifiants sensible ---
        filename_str = event.filename.decode(errors="replace").rstrip("\x00")
        detail = filename_str
        if not already_alerted_recently(event.pid, "T1003"):
            alert_count += 1
            response = respond_to_threat(event.pid)
            _, severity, _ = log_alert(
                       "T1003", "OS Credential Dumping (fichier sensible)",
                       event.pid, comm_str, event.pid,
                       f"fichier: {filename_str}",
                       f"Le processus « {comm_str} » (PID {event.pid}) a tente d'ouvrir "
                       f"le fichier sensible « {filename_str} », contenant potentiellement "
                       f"des hachages de mots de passe systeme.",
                       response, severity_override="CRITIQUE")
            info = f"** ALERTE [CRITIQUE] (ACCES IDENTIFIANTS: {filename_str}) ** - Reponse: {response}"

    is_alert = "ALERTE" in info
    is_critical = "[CRITIQUE]" in info

    if is_alert:
        if is_critical:
            print(f"\n{'#'*90}")
            print("###  PRIORITE CRITIQUE  ###")
            print(f"[ALERTE SECURITE] PID {event.pid} ({comm_str}) -> {info}")
            print(f"{'#'*90}\n")
        else:
            print(f"\n{'='*90}")
            print(f"[ALERTE SECURITE] PID {event.pid} ({comm_str}) -> {info}")
            print(f"{'='*90}\n")
        if VERBOSE:
            printb(b"%-8d %-8d %-14s %-24s %-16s %s" % (
                event.pid, event.ppid, event_name.encode(), detail.encode(),
                event.comm, info.encode(),
            ))
    elif VERBOSE:
        printb(b"%-8d %-8d %-14s %-24s %-16s %s" % (
            event.pid, event.ppid, event_name.encode(), detail.encode(),
            event.comm, info.encode(),
        ))

    if (event_count - suppressed_count) % 20 == 0:
        write_stats({
            "events_total": event_count, "events_filtered": suppressed_count,
            "events_shown": event_count - suppressed_count, "alerts_total": alert_count,
            "agent_start": AGENT_START, "auto_kill_enabled": AUTO_KILL_ENABLED,
            "status": "running",
        })

b["events"].open_perf_buffer(print_event, page_cnt=64)

print("Agent EDR (step 9 - LOLBins + T1003) demarre. Ctrl+C pour arreter.\n")

try:
    while True:
        b.perf_buffer_poll(timeout=1000)
except KeyboardInterrupt:
    pass

write_stats({
    "events_total": event_count, "events_filtered": suppressed_count,
    "events_shown": event_count - suppressed_count, "alerts_total": alert_count,
    "agent_start": AGENT_START, "auto_kill_enabled": AUTO_KILL_ENABLED,
    "status": "stopped",
})

print(f"\n--- Resume de session ---")
print(f"Evenements totaux recus   : {event_count}")
print(f"Evenements filtres (bruit): {suppressed_count}")
print(f"Alertes correlees (total) : {alert_count}")
print(f"Logs JSON ecrits dans     : {ALERTS_FILE}")
