#!/usr/bin/env python3
import os
import sys
import time
import argparse
import paramiko
import logging
import random
import string

# Désactivation des logs Paramiko
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

# Constantes
PAYLOADS_FILE = 'filename_payloads.txt'
DEFAULT_PAYLOAD_DIR = '/SFTP-AUDIT'

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
    (7, 'Écriture/suppression /tmp/sftp_test.txt'), (8, 'Test mkdir/rmdir'),
    (9, 'Test Permissions'), (10, 'Création répertoire'), (11, 'Accès /proc'),
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
    parser.add_argument('--key', required=True, help='Clé privée SSH')
    parser.add_argument('--dir', default=DEFAULT_PAYLOAD_DIR, help='Répertoire distant pour upload')
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
    except:
        print(f"    [{G}+{C}] list('..') bloqué → chroot actif")
        return False

# Section 3: Symlink
def test_symlink(num, sftp, target, linkname):
    print(f"\n{COLORS['symlink']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        sftp.symlink(target, linkname)
        print(f"    [{G}+{C}] Symlink créé")
        sftp.remove(linkname)
        print(f"    [{G}+{C}] Symlink supprimé")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec symlink : {e}")

# Sections 4-6: Lecture de fichiers
def test_read(num, sftp, path):
    print(f"\n{COLORS['read']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        data = sftp.open(path, 'r').read(200)
        print(f"    [{G}+{C}] Lecture réussie ({len(data)} bytes)")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec lecture : {e}")

# Section 7: Écriture / Suppression
def test_write(num, sftp, path):
    print(f"\n{COLORS['write']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        sftp.open(path, 'w').write('TEST')
        print(f"    [{G}+{C}] Écriture OK")
        sftp.remove(path)
        print(f"    [{G}+{C}] Suppression OK")
    except Exception as e:
        print(f"    [{R}✗{C}] Échec : {e}")

# Section 8: Test mkdir/rmdir
def test_mkdir_rmdir(num, sftp, base_dir):
    print(f"\n{COLORS['mkdir']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    name = 'audit_' + ''.join(random.choices(string.ascii_lowercase+string.digits, k=6))
    for base in ['/', base_dir.rstrip('/')]:
        d = base.rstrip('/') + '/' + name
        try:
            sftp.mkdir(d); print(f"    [{G}+{C}] mkdir OK : {d}")
            sftp.rmdir(d); print(f"    [{G}+{C}] rmdir OK : {d}")
        except Exception as e:
            print(f"    [{R}✗{C}] {base} test : {e}")

# Section 9: Test Permissions
def test_permissions(num, sftp, remote_dir):
    print(f"\n{COLORS['permissions']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    modes = [0o444, 0o555, 0o644, 0o666, 0o755, 0o777]
    for m in modes:
        fname = f"perm_file_{m:o}.txt"
        path = remote_dir.rstrip('/') + '/' + fname
        try:
            sftp.open(path, 'w').write('x')
            sftp.chmod(path, m)
            actual = sftp.stat(path).st_mode & 0o777
            mark = G+'+'+C if actual == m else R+'✗'+C
            print(f"    [{mark}] File {fname}: {oct(m)} --> {oct(actual)}")
            sftp.remove(path)
        except Exception as e:
            print(f"    [{R}✗{C}] File {fname} test: {e}")
    for m in modes:
        dname = f"perm_dir_{m:o}"
        dpath = remote_dir.rstrip('/') + '/' + dname
        try:
            sftp.mkdir(dpath)
            sftp.chmod(dpath, m)
            actual = sftp.stat(dpath).st_mode & 0o777
            mark = G+'+'+C if actual == m else R+'✗'+C
            print(f"    [{mark}] Dir {dname}: {oct(m)} --> {oct(actual)}")
            sftp.rmdir(dpath)
        except Exception as e:
            print(f"    [{R}✗{C}] Dir {dname} test: {e}")

# Section 10: Création répertoire
def test_create_dir(num, sftp, remote_dir):
    print(f"\n{COLORS['create_dir']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    try:
        sftp.mkdir(remote_dir)
        print(f"    [{G}+{C}] Répertoire '{remote_dir}' créé")
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

# Section 14: Test Race Condition
def test_race_condition(num, host, port, valid_user, key_path, count):
    print(f"\n{COLORS['race']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    vals = []
    for _ in range(count):
        t0 = time.time()
        try:
            ssh = connect_ssh(host, port, valid_user, key_filename=None)
            ssh.close()
        except:
            vals.append(time.time() - t0)
    avg_val = sum(vals) / len(vals) if vals else 0.0
    print(f"    [{G}+{C}] Valid moyenne: {avg_val:.4f}s")
    inv = []
    for _ in range(count):
        t1 = time.time()
        try:
            ssh = connect_ssh(host, port, 'azertyuazerty', key_filename=None)
            ssh.close()
        except:
            inv.append(time.time() - t1)
    avg_inv = sum(inv) / len(inv) if inv else 0.0
    print(f"    [{G}+{C}] Invalid moyenne: {avg_inv:.4f}s")
    print(f"    [{G}+{C}] Diff temporelle: {abs(avg_inv - avg_val):.4f}s")

# Section 15: Upload Payloads
def test_payload_upload(num, sftp, remote_dir):
    print(f"\n{COLORS['payload']}--- Section {num}: {SECTION_DEFS[num-1][1]} ---{COLORS['end']}")
    if not os.path.isfile(PAYLOADS_FILE):
        print(f"    [{R}✗{C}] Payload file introuvable")
        return False
    ok = True
    with open(PAYLOADS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for fn in (l.strip() for l in f if l.strip()):
            path = remote_dir.rstrip('/') + '/' + fn
            try:
                sftp.open(path, 'w').write('testfile')
                print(f"    [{G}+{C}] {fn} uploadé")
            except Exception as e:
                print(f"    [{R}✗{C}] Échec upload {fn}: {e}")
                ok = False
    return ok

# Main
def main(args):
    all_nums = {n for n, _ in SECTION_DEFS}
    selected = all_nums if not args.sections else {int(x) for x in args.sections.split(',') if x}
    ssh_main = connect_ssh(args.host, args.port, args.user, key_filename=args.key)
    sftp = open_sftp(ssh_main)
    tasks = [
        (1, test_banner, [1, ssh_main]),
        (2, test_chroot, [2, sftp]),
        (3, test_symlink, [3, sftp, '/etc/passwd', '/tmp/test_link']),
        (4, test_read, [4, sftp, '/etc/passwd']),
        (5, test_read, [5, sftp, '/etc/shadow']),
        (6, test_read, [6, sftp, '/var/log/auth.log']),
        (7, test_write, [7, sftp, '/tmp/sftp_test.txt']),
        (8, test_mkdir_rmdir, [8, sftp, args.dir]),
        (9, test_permissions, [9, sftp, args.dir]),
        (10, test_create_dir, [10, sftp, args.dir]),
        (11, test_proc, [11, sftp]),
        (12, test_ssh_audit, [12, args.host, args.port]),
        (13, test_ssh_simple, [13, args.host, args.port, args.user, args.key]),
        (14, test_race_condition, [14, args.host, args.port, args.user, args.key, args.race_count]),
        (15, test_payload_upload, [15, sftp, args.dir])
    ]
    for num, func, fargs in tasks:
        if num in selected:
            func(*fargs)
    sftp.close(); ssh_main.close()
    print("\n[*] Audit SFTP terminé")

if __name__ == '__main__':
    args = parse_args()
    main(args)
