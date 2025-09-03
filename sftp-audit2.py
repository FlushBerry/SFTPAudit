#!/usr/bin/env python3
import os
import sys
import time
import argparse
import paramiko
import logging
import random
import string
import stat

# Désactivation des logs Paramiko
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

# Constantes
PAYLOADS_FILE = 'filename_payloads.txt'
DEFAULT_PAYLOAD_DIR = '/SFTP-AUDIT'
TEST_PAYLOAD = 'TESTED'

# Couleurs ANSI
COLORS = {
    'banner': '\033[94m', 'chroot': '\033[92m', 'read': '\033[96m', 'write': '\033[93m',
    'mkdir': '\033[95m', 'permissions': '\033[32m', 'create_dir': '\033[33m',
    'symlink': '\033[91m', 'proc': '\033[90m', 'ssh_audit': '\033[97m',
    'ssh_simple': '\033[35m', 'race': '\033[31m', 'payload': '\033[36m', 'end': '\033[0m'
}
G = '\033[32m'; R = '\033[31m'; C = '\033[0m'

# Sections disponibles (ordre d'affichage)
SECTION_DEFS = [
    (1, 'Banner SSH'), (2, 'Test Chroot'), (3, 'Symlink'),
    (4, 'Lecture /etc/passwd'), (5, 'Lecture /etc/shadow'), (6, 'Lecture /var/log/auth.log'),
    (7, 'Écriture/suppression fichier test'), (8, 'Test mkdir/rmdir'),
    (9, 'Test Permissions'), (10, 'Création répertoire (mkdir simple)'), (11, 'Accès /proc'),
    (12, 'ssh-audit'), (13, 'SSH Simple Commandes'), (14, 'Test Race Condition'),
    (15, 'Upload Payloads')
]

# Parsing des arguments
def parse_args():
    from argparse import RawDescriptionHelpFormatter
    sec_help = 'Sections disponibles:\n' + '\n'.join(f"  {n}: {name}" for n, name in SECTION_DEFS)
    parser = argparse.ArgumentParser(
        description="Audit SFTP complet avec sections colorées",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=sec_help
    )
    parser.add_argument('--host', required=True, help='Hôte SSH/SFTP')
    parser.add_argument('--port', type=int, default=22, help='Port SSH/SFTP')
    parser.add_argument('--user', required=True, help='Utilisateur SSH valide')
    parser.add_argument('--key', required=True, help='Clé privée SSH (chemin)')
    parser.add_argument('--dir', default=DEFAULT_PAYLOAD_DIR, help='[OBSOLETE] Dossier par défaut pour anciens tests (compat)')
    parser.add_argument('--folder', default=None, help='Dossier distant à tester. Si absent: menu interactif; 0 = tous')
    parser.add_argument('--race-count', type=int, default=300, help="Nombre d'essais race condition")
    parser.add_argument('-p', '--sections', help='Numéros des sections à exécuter, ex: "1,2,10"')
    return parser.parse_args()

# Connexion SSH
def connect_ssh(host, port, user, key_filename=None, **kwargs):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, port=port, username=user,
                key_filename=key_filename, allow_agent=False,
                look_for_keys=False, timeout=5, **kwargs)
    return ssh

# Ouverture SFTP
def open_sftp(ssh):
    return ssh.open_sftp()

# Utils chemin
def join_remote(a, b):
    if a.endswith('/'):
        return a + b.lstrip('/')
    return a + '/' + b.lstrip('/')

def safe_basename(p):
    return p.rstrip('/').split('/')[-1] or '/'

# === Sections ===

# Section 1: Banner SSH
def test_banner(num, ssh):
    print(f"\n{COLORS['banner']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    banner = ssh.get_transport().get_banner()
    print(f"    [{G}+{C}] Banner SSH : {banner}")

# Section 2: Test Chroot
def test_chroot(num, sftp):
    print(f"\n{COLORS['chroot']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        sftp.listdir('..')
        print(f"    [{G}+{C}] list('..') possible → hors chroot")
        return True
    except Exception:
        print(f"    [{G}+{C}] list('..') bloqué → chroot actif")
        return False

# Section 3: Symlink (dans le dossier ciblé) + lecture via le lien si créé
def test_symlink(num, sftp, target, link_parent_dir):
    print(f"\n{COLORS['symlink']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    linkname = join_remote(link_parent_dir, 'audit_symlink')
    try:
        sftp.symlink(target, linkname)
        print(f"    [{G}+{C}] Symlink créé: {linkname} -> {target}")
        # Tente de lire via le lien symbolique
        try:
            with sftp.open(linkname, 'r') as f:
                data = f.read(200)
            preview = data.decode(errors='replace')
            print(f"    [{G}+{C}] Lecture via symlink OK ({len(data)} bytes). Aperçu:\n------\n{preview}\n------")
        except Exception as e_read:
            print(f"    [{R}✗{C}] Lecture via symlink échouée : {e_read}")
        # Supprime le lien
        sftp.remove(linkname)
        print(f"    [{G}+{C}] Symlink supprimé")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec symlink : {e}")

# Sections 4-6: Lecture de fichiers sensibles
def test_read(num, sftp, path):
    print(f"\n{COLORS['read']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        with sftp.open(path, 'r') as f:
            data = f.read(200)
        preview = data.decode(errors='replace')
        print(f"    [{G}+{C}] Lecture réussie {path} ({len(data)} bytes). Aperçu:\n------\n{preview}\n------")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec lecture {path} : {e}")

# Section 7: Écriture / Suppression (dans le dossier ciblé) + vérification contenu
def test_write(num, sftp, target_dir):
    print(f"\n{COLORS['write']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    path = join_remote(target_dir, 'sftp_test.txt')
    try:
        with sftp.open(path, 'w') as f:
            f.write(TEST_PAYLOAD)
        print(f"    [{G}+{C}] Écriture OK : {path}")
        # Vérifie le contenu
        with sftp.open(path, 'r') as f:
            content = f.read().decode(errors='replace')
        print(f"    [{G}+{C}] Contenu lu : {content!r}")
        # Suppression
        sftp.remove(path)
        print(f"    [{G}+{C}] Suppression OK : {path}")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec : {e}")

# Section 8: Test mkdir/rmdir (dans le dossier ciblé)
def test_mkdir_rmdir(num, sftp, base_dir):
    print(f"\n{COLORS['mkdir']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    name = 'audit_' + ''.join(random.choices(string.ascii_lowercase+string.digits, k=6))
    d = join_remote(base_dir, name)
    try:
        sftp.mkdir(d); print(f"    [{G}+{C}] mkdir OK : {d}")
        sftp.rmdir(d); print(f"    [{G}+{C}] rmdir OK : {d}")
    except Exception as e:
        print(f"    [{R}✗{C}] mkdir/rmdir dans {base_dir} : {e}")

# Section 9: Test Permissions (fichiers contiennent TESTED + cat + chmod + stat + delete)
def test_permissions(num, sftp, remote_dir):
    print(f"\n{COLORS['permissions']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    modes = [0o444, 0o555, 0o644, 0o666, 0o755, 0o777]
    # FICHIERS
    for m in modes:
        fname = f"perm_file_{m:o}.txt"
        path = join_remote(remote_dir, fname)
        try:
            with sftp.open(path, 'w') as f:
                f.write(TEST_PAYLOAD)
            # Vérifie contenu
            with sftp.open(path, 'r') as f:
                content = f.read().decode(errors='replace')
            print(f"    [{G}+{C}] {fname} écrit & lu : {content!r}")
            # Test chmod/stat
            sftp.chmod(path, m)
            actual = sftp.stat(path).st_mode & 0o777
            mark = G+'+'+C if actual == m else R+'✗'+C
            print(f"    [{mark}] File {fname}: {oct(m)} --> {oct(actual)}")
            # Cleanup
            sftp.remove(path)
        except Exception as e:
            print(f"    [{R}✗{C}] File {fname} test: {e}")
    # DOSSIERS
    for m in modes:
        dname = f"perm_dir_{m:o}"
        dpath = join_remote(remote_dir, dname)
        try:
            sftp.mkdir(dpath)
            sftp.chmod(dpath, m)
            actual = sftp.stat(dpath).st_mode & 0o777
            mark = G+'+'+C if actual == m else R+'✗'+C
            print(f"    [{mark}] Dir {dname}: {oct(m)} --> {oct(actual)}")
            sftp.rmdir(dpath)
        except Exception as e:
            print(f"    [{R}✗{C}] Dir {dname} test: {e}")

# Section 10: Création répertoire (mkdir simple dans le dossier ciblé)
def test_create_dir(num, sftp, remote_dir):
    print(f"\n{COLORS['create_dir']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    newdir = join_remote(remote_dir, 'audit_newdir')
    try:
        sftp.mkdir(newdir)
        print(f"    [{G}+{C}] Répertoire créé : {newdir}")
        sftp.rmdir(newdir)
        print(f"    [{G}+{C}] Répertoire supprimé : {newdir}")
    except Exception as e:
        print(f"    [{R}✗{C}] mkdir échoué : {e}")

# Section 11: Accès /proc
def test_proc(num, sftp):
    print(f"\n{COLORS['proc']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        count = len([p for p in sftp.listdir('/proc') if p.isdigit()])
        print(f"    [{G}+{C}] /proc listé ({count} PID)")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec /proc : {e}")

# Section 12: ssh-audit
def test_ssh_audit(num, host, port):
    print(f"\n{COLORS['ssh_audit']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    if not os.path.exists('ssh-audit.py'):
        print(f"    [{R}✗{C}] ssh-audit.py non présent")
    else:
        os.system(f"python3 ssh-audit.py {host}:{port}")

# Section 13: SSH Simple Commandes
def test_ssh_simple(num, host, port, user, key_filename):
    print(f"\n{COLORS['ssh_simple']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        ssh = connect_ssh(host, port, user, key_filename=key_filename)
        print(f"    [{G}+{C}] Connexion OK")
        for cmd in ['id', 'uname -a', 'hostname']:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode().strip()
            print(f"    [{G}+{C}] {cmd}: {out}")
        ssh.close()
    except Exception as e:
        print(f"    [{R}✗{C}] SSH simple échec: {e}")

# Section 14: Test Race Condition (inchangé)
def test_race_condition(num, host, port, valid_user, key_path, count):
    print(f"\n{COLORS['race']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    vals = []
    for _ in range(count):
        t0 = time.time()
        try:
            ssh = connect_ssh(host, port, valid_user, key_filename=None)
            ssh.close()
        except Exception:
            vals.append(time.time() - t0)
    avg_val = sum(vals) / len(vals) if vals else 0.0
    print(f"    [{G}+{C}] Valid moyenne: {avg_val:.4f}s")
    inv = []
    for _ in range(count):
        t1 = time.time()
        try:
            ssh = connect_ssh(host, port, 'azertyuazerty', key_filename=None)
            ssh.close()
        except Exception:
            inv.append(time.time() - t1)
    avg_inv = sum(inv) / len(inv) if inv else 0.0
    print(f"    [{G}+{C}] Invalid moyenne: {avg_inv:.4f}s")
    print(f"    [{G}+{C}] Diff temporelle: {abs(avg_inv - avg_val):.4f}s")

# Section 15: Upload Payloads (écrit TESTED + cat + delete)
def test_payload_upload(num, sftp, remote_dir):
    print(f"\n{COLORS['payload']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    if not os.path.isfile(PAYLOADS_FILE):
        print(f"    [{R}✗{C}] Fichier payloads introuvable: {PAYLOADS_FILE}")
        return False
    ok = True
    with open(PAYLOADS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for fn in (l.strip() for l in f if l.strip()):
            path = join_remote(remote_dir, fn)
            try:
                with sftp.open(path, 'w') as wf:
                    wf.write(TEST_PAYLOAD)
                with sftp.open(path, 'r') as rf:
                    content = rf.read().decode(errors='replace')
                print(f"    [{G}+{C}] Upload {fn} → {path} (contenu: {content!r})")
                sftp.remove(path)
                print(f"    [{G}+{C}] Suppression OK : {path}")
            except Exception as e:
                print(f"    [{R}✗{C}] Échec upload {fn}: {e}")
                ok = False
    return ok

# === Découverte d'arborescence ===
def is_dir_attr(attr):
    return stat.S_ISDIR(attr.st_mode)

def is_link_attr(attr):
    return stat.S_ISLNK(attr.st_mode)

def list_dirs_recursive(sftp, root, max_entries=10000):
    """
    Retourne la liste des dossiers sous 'root' (inclus), en DFS.
    Évite les liens symboliques pour prévenir les boucles.
    Limite molle via max_entries.
    """
    dirs = []
    stack = [root]
    visited = set()
    while stack:
        cur = stack.pop()
        if cur in visited:
            continue
        visited.add(cur)
        dirs.append(cur)
        try:
            for entry in sftp.listdir_attr(cur):
                name = entry.filename
                if name in ('.', '..'):
                    continue
                p = join_remote(cur, name)
                if is_link_attr(entry):
                    continue
                if is_dir_attr(entry):
                    stack.append(p)
                    if len(dirs) >= max_entries:
                        print(f"{R}[!] Limite de {max_entries} dossiers atteinte, arrêt de l'exploration.{C}")
                        return dirs
        except Exception:
            continue
    return sorted(set(dirs))

def print_tree(sftp, root, prefix=''):
    try:
        entries = [e for e in sftp.listdir_attr(root) if is_dir_attr(e) and e.filename not in ('.','..')]
    except Exception:
        print(prefix + f"└── {safe_basename(root)}/ [inaccessible]")
        return
    print(prefix + ("" if prefix=="" else "└── ") + f"{safe_basename(root)}/")
    for i, e in enumerate(sorted(entries, key=lambda x: x.filename)):
        sub = join_remote(root, e.filename)
        last = (i == len(entries)-1)
        branch_prefix = prefix + ("    " if last else "│   ")
        print_tree(sftp, sub, branch_prefix)

def choose_folder_interactive(sftp):
    start = sftp.getcwd() or '/'
    print(f"{G}[*]{C} Exploration depuis: {start}")
    print("\nArborescence (dossiers uniquement):\n")
    print_tree(sftp, start)
    print("\nDécouverte exhaustive des dossiers, patientez...\n")
    dirs = list_dirs_recursive(sftp, start)
    if not dirs:
        print(f"{R}[!]{C} Aucun dossier accessible trouvé depuis {start}")
        sys.exit(2)
    print("Dossiers détectés:\n")
    for idx, d in enumerate(dirs, start=1):
        print(f"  {idx:>3}) {d}")
    print("\n  {0:>3}) 0  → Tester TOUS les dossiers ci-dessus")
    while True:
        try:
            choice = input("\nEntrez le numéro du dossier à tester (0 = tous): ").strip()
            sel = int(choice)
            if sel == 0:
                return dirs
            if 1 <= sel <= len(dirs):
                return [dirs[sel-1]]
        except Exception:
            pass
        print(f"{R}[!]{C} Saisie invalide. Réessayez.")

# Main
def main(args):
    all_nums = {n for n, _ in SECTION_DEFS}
    selected = all_nums if not args.sections else {int(x) for x in args.sections.split(',') if x}
    ssh_main = connect_ssh(args.host, args.port, args.user, key_filename=args.key)
    sftp = open_sftp(ssh_main)

    # Choix du (des) dossier(s) à tester
    if args.folder:
        folders_to_test = [args.folder]
    else:
        folders_to_test = choose_folder_interactive(sftp)

    # Tâches "globales" (pas liées au dossier)
    global_tasks = [
        (1, test_banner, [1, ssh_main]),
        (2, test_chroot, [2, sftp]),
        (4, test_read, [4, sftp, '/etc/passwd']),
        (5, test_read, [5, sftp, '/etc/shadow']),
        (6, test_read, [6, sftp, '/var/log/auth.log']),
        (11, test_proc, [11, sftp]),
        (12, test_ssh_audit, [12, args.host, args.port]),
        (13, test_ssh_simple, [13, args.host, args.port, args.user, args.key]),
        (14, test_race_condition, [14, args.host, args.port, args.user, args.key, args.race_count]),
    ]

    # Tâches "par dossier"
    per_folder_tasks = [
        (3, test_symlink),
        (7, test_write),
        (8, test_mkdir_rmdir),
        (9, test_permissions),
        (10, test_create_dir),
        (15, test_payload_upload)
    ]

    # Exécution des tâches globales
    for num, func, fargs in global_tasks:
        if num in selected:
            func(*fargs)

    # Exécution des tâches par dossier
    for folder in folders_to_test:
        print(f"\n{G}=== Tests dossier cible: {folder} ==={C}")
        for num, func in per_folder_tasks:
            if num not in selected:
                continue
            if num == 3:
                func(3, sftp, '/etc/passwd', folder)
            elif num in (7, 8, 9, 10, 15):
                func(num, sftp, folder)

    sftp.close(); ssh_main.close()
    print("\n[*] Audit SFTP terminé")

if __name__ == '__main__':
    args = parse_args()
    main(args)
