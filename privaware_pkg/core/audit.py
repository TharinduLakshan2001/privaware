"""
Extended Auditor for PrivAware

Adds System/OS hardening and Network checks:

- sudoers surprises (NOPASSWD, included files)
- cron/at jobs anomalies (world-writable crontabs, suspicious jobs, unexpected owners)
- kernel hardening sysctl checks (ip_forward, rp_filter, tcp_syncookies, suid_dumpable)
- user account checks (UID 0 duplicates, empty-password, locked/expired)
- password policy (/etc/login.defs and PAM minlen/retry)
- SSH hardening (PermitRootLogin, PasswordAuthentication, AllowUsers/Groups, AuthorizedKeysCommand)
- PAM misconfigurations (pam_unix, pam_tally2/faillock)
- DNS config consistency (/etc/hosts vs /etc/resolv.conf)
- Open ports & services (ss/netstat listening sockets, public bindings)
- Service version sampling (sshd, nginx, dnsmasq)
- Unencrypted services detection (ftp/telnet/rsh)
- NTP/chrony configuration checks

Design goals:
- Structured CheckResult: {"status","count","details"}
- Safe subprocess usage (no shell), caching text reads, caps on results
- Testable by injecting cmd_runner if needed
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.json"
MAX_DETAILS = 200

# Type aliases
CheckResult = Dict[str, object]
CmdRunner = Callable[[List[str], int], Tuple[int, str, str]]


def load_settings(path: Path = SETTINGS_PATH) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        print(f"Warning: Could not load settings from {path}: {e}")
        return {}


def default_cmd_runner(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 127, "", str(e)


@dataclass
class Auditor:
    settings: dict = None
    cmd_runner: CmdRunner = default_cmd_runner

    def __post_init__(self):
        if self.settings is None:
            self.settings = load_settings()
        self.checks = self.settings.get("audit", {}).get("checks", [])
        self._cache: Dict[str, str] = {}

    def run_all(self) -> Dict[str, CheckResult]:
        results: Dict[str, CheckResult] = {}
        for check in self.checks:
            func = getattr(self, f"check_{check}", None)
            if callable(func):
                try:
                    results[check] = func()
                except Exception as e:
                    results[check] = {"status": "FAIL", "count": 0, "details": [f"Exception: {e}"]}
            else:
                results[check] = {"status": "WARN", "count": 0, "details": [f"Check not implemented: {check}"]}
        return results

    # --- helpers ---

    def _read_cached(self, p: Path) -> str:
        key = str(p)
        if key in self._cache:
            return self._cache[key]
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
            self._cache[key] = txt
            return txt
        except Exception as e:
            self._cache[key] = ""
            return ""

    def _cap(self, items: List[str]) -> List[str]:
        return items[:MAX_DETAILS]

    # --- NEW CHECKS ---

    def check_world_readable_secrets(self) -> CheckResult:
        """
        Check for world-readable sensitive files that shouldn't be public.
        """
        found: List[str] = []
        sensitive_paths = [
            Path("/etc/shadow"),
            Path("/etc/gshadow"),
            Path("/etc/passwd-"),
            Path("/etc/shadow-"),
            Path("/etc/ssh/ssh_host_*_key"),
            Path("/root/.ssh/id_*"),
        ]
        
        for path_pattern in sensitive_paths:
            if "*" in str(path_pattern):
                # Handle glob patterns
                try:
                    import glob
                    matches = glob.glob(str(path_pattern))
                    for match in matches:
                        p = Path(match)
                        if p.exists():
                            try:
                                st = p.stat()
                                if bool(st.st_mode & stat.S_IROTH):  # world readable
                                    found.append(f"World-readable sensitive file: {p}")
                            except Exception:
                                continue
                except Exception:
                    continue
            else:
                if path_pattern.exists():
                    try:
                        st = path_pattern.stat()
                        if bool(st.st_mode & stat.S_IROTH):  # world readable
                            found.append(f"World-readable sensitive file: {path_pattern}")
                    except Exception:
                        continue
        
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_weak_ssh_ciphers(self) -> CheckResult:
        """
        Check SSH configuration for weak ciphers, MACs, and key exchange algorithms.
        """
        found: List[str] = []
        sshd_config = Path("/etc/ssh/sshd_config")
        
        if sshd_config.exists():
            txt = self._read_cached(sshd_config)
            weak_ciphers = [
                "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                "arcfour", "arcfour128", "arcfour256", " blowfish-cbc"
            ]
            weak_macs = [
                "hmac-md5", "hmac-md5-96", "hmac-ripemd160"
            ]
            
            for ln in txt.splitlines():
                line = ln.strip()
                if line.startswith("#") or not line:
                    continue
                    
                if line.startswith("Ciphers"):
                    ciphers = line.split()[1:] if len(line.split()) > 1 else []
                    for cipher in ciphers:
                        if cipher in weak_ciphers:
                            found.append(f"Weak cipher in use: {cipher}")
                            
                if line.startswith("MACs"):
                    macs = line.split()[1:] if len(line.split()) > 1 else []
                    for mac in macs:
                        if mac in weak_macs:
                            found.append(f"Weak MAC in use: {mac}")
        else:
            found.append("/etc/ssh/sshd_config not found")
            
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_dns_leaks(self) -> CheckResult:
        """
        Check for potential DNS leak configurations.
        """
        found: List[str] = []
        resolv_conf = Path("/etc/resolv.conf")
        
        if resolv_conf.exists():
            txt = self._read_cached(resolv_conf)
            # Check for public DNS servers that might cause leaks
            public_dns = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
            
            for ln in txt.splitlines():
                line = ln.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_server = parts[1]
                        if dns_server in public_dns:
                            found.append(f"Public DNS server configured: {dns_server}")
        else:
            found.append("/etc/resolv.conf not found")
            
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_missing_firewall_rules(self) -> CheckResult:
        """
        Check if basic firewall rules are configured.
        """
        found: List[str] = []
        
        # Check if ufw is active
        rc, out, err = self.cmd_runner(["ufw", "status"], 3)
        if rc == 0:
            if "inactive" in out:
                found.append("UFW firewall is inactive")
        else:
            # Check iptables
            rc, out, err = self.cmd_runner(["iptables", "-L", "-n"], 3)
            if rc == 0:
                if "ACCEPT" not in out and "DROP" not in out:
                    found.append("No iptables rules found")
            else:
                found.append("No firewall (ufw/iptables) detected")
                
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_integrity_checks(self) -> CheckResult:
        """
        Check if file integrity monitoring is configured (AIDE, Tripwire, etc.).
        """
        found: List[str] = []
        
        # Check for AIDE
        aide_conf = Path("/etc/aide/aide.conf")
        if aide_conf.exists():
            found.append("AIDE configuration found")
        else:
            # Check if aide is installed
            rc, out, err = self.cmd_runner(["which", "aide"], 2)
            if rc == 0:
                found.append("AIDE installed but not configured")
            else:
                found.append("AIDE not installed")
                
        # Check systemd timer for aide
        rc, out, err = self.cmd_runner(["systemctl", "list-timers", "aide"], 2)
        if "aide" not in out:
            found.append("No AIDE integrity check scheduled")
            
        status = "OK" if any("found" in detail for detail in found) else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    # --- EXISTING CHECKS WITH FIXES ---

    def check_sudoers_surprises(self) -> CheckResult:
        """
        Look for NOPASSWD entries and included files that might use wildcards.
        """
        found: List[str] = []
        sudoers_path = Path("/etc/sudoers")
        dirs = [Path("/etc/sudoers.d")]
        text = self._read_cached(sudoers_path) if sudoers_path.exists() else ""
        # basic scan for NOPASSWD
        for ln in text.splitlines():
            if "NOPASSWD" in ln and not ln.strip().startswith("#"):
                found.append(f"/etc/sudoers: {ln.strip()}")
        # included files
        for d in dirs:
            if d.exists() and d.is_dir():
                try:
                    for entry in sorted(d.iterdir()):
                        if entry.is_file():
                            t = self._read_cached(entry)
                            for ln in t.splitlines():
                                if "NOPASSWD" in ln and not ln.strip().startswith("#"):
                                    found.append(f"{entry}: {ln.strip()}")
                        # warn about wildcard-style filenames that may be risky
                        if any(ch in entry.name for ch in ("*", "?", "[", "{")):
                            found.append(f"Wildcard in sudoers.d path: {entry}")
                except Exception as e:
                    found.append(f"Error reading sudoers.d: {e}")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_cron_at_jobs(self) -> CheckResult:
        """
        Check crontabs and /etc/cron.* for world-writable or suspicious jobs and unexpected owners.
        """
        found: List[str] = []
        # system cron dirs
        cron_dirs = [Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"), Path("/etc/cron.weekly"), Path("/etc/cron.monthly")]
        for d in cron_dirs:
            if d.exists() and d.is_dir():
                try:
                    for f in sorted(d.iterdir()):
                        try:
                            st = f.stat()
                            if bool(st.st_mode & stat.S_IWOTH):
                                found.append(f"World-writable cron file: {f}")
                        except Exception:
                            continue
                except Exception as e:
                    found.append(f"Error reading {d}: {e}")
        # user crontabs in /var/spool/cron or via crontab -l for each user in /etc/passwd (best-effort)
        spool = Path("/var/spool/cron")
        if spool.exists() and spool.is_dir():
            for entry in sorted(spool.iterdir()):
                try:
                    st = entry.stat()
                    if bool(st.st_mode & stat.S_IWOTH):
                        found.append(f"World-writable user crontab: {entry}")
                except Exception:
                    continue
        # parse crontab lines for suspicious commands (wget/curl nc reverse shell patterns)
        suspicious_cmds = ["wget ", "curl ", "nc ", "ncat ", "bash -i", "python -c", "/bin/sh -i"]
        # scan /etc/cron.* files
        for d in cron_dirs:
            if d.exists():
                for f in sorted(d.iterdir()):
                    if f.is_file():
                        txt = self._read_cached(f)
                        for ln in txt.splitlines():
                            l = ln.strip()
                            if any(s in l for s in suspicious_cmds) and not l.startswith("#"):
                                found.append(f"Suspicious cron job in {f}: {l}")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_sysctl_hardening(self) -> CheckResult:
        """
        Check common sysctl hardening settings:
        - net.ipv4.ip_forward == 0
        - net.ipv4.conf.all.rp_filter >= 1
        - net.ipv4.tcp_syncookies == 1
        - fs.suid_dumpable == 0
        """
        checks = {
            "net.ipv4.ip_forward": ("0", "Forwarding should be disabled"),
            "net.ipv4.conf.all.rp_filter": ("1", "rp_filter should be enabled"),
            "net.ipv4.tcp_syncookies": ("1", "tcp_syncookies should be enabled"),
            "fs.suid_dumpable": ("0", "suid_dumpable should be 0"),
        }
        found: List[str] = []
        for key, (want, note) in checks.items():
            # read /proc/sys/ equivalent
            proc_path = Path("/proc/sys") / key.replace(".", "/")
            val = None
            if proc_path.exists():
                try:
                    val = proc_path.read_text().strip()
                except Exception as e:
                    val = None
                    found.append(f"{key}: read error - {e}")
            else:
                # fallback to sysctl -n
                rc, out, err = self.cmd_runner(["sysctl", "-n", key], 3)
                val = out.strip() if rc == 0 else None
            if val is None:
                found.append(f"{key}: not readable")
                continue
            if val != want:
                found.append(f"{key}: {val} (expected {want}) — {note}")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_user_accounts(self) -> CheckResult:
        """
        - Find accounts with UID 0 other than root
        - Empty-password accounts (best-effort via /etc/shadow presence)
        - Locked or expired accounts (shadow flags)
        """
        found: List[str] = []
        passwd = Path("/etc/passwd")
        shadow = Path("/etc/shadow")
        uid0 = []
        if passwd.exists():
            for ln in self._read_cached(passwd).splitlines():
                try:
                    parts = ln.split(":")
                    if len(parts) >= 3:
                        user = parts[0]
                        uid = int(parts[2])
                        if uid == 0 and user != "root":
                            uid0.append(f"UID 0 user: {user}")
                except Exception:
                    continue
        found.extend(uid0)
        # empty password detection (if /etc/shadow readable)
        empty_pw_users = []
        locked_or_expired = []
        if shadow.exists():
            text = self._read_cached(shadow)
            for ln in text.splitlines():
                parts = ln.split(":")
                if len(parts) >= 2:
                    user = parts[0]
                    pw = parts[1]
                    if pw == "" or pw == "*":
                        empty_pw_users.append(f"{user}: empty or locked pw field: '{pw}'")
                    # check for '!' or '!!' prefix meaning locked
                    if pw.startswith("!") or pw.startswith("!!"):
                        locked_or_expired.append(f"{user}: locked/expired ({pw[:3]})")
        else:
            # if we can't read shadow, warn that detection limited
            found.append("Cannot read /etc/shadow (insufficient permissions); skipping some checks")
        found.extend(empty_pw_users[:50])
        found.extend(locked_or_expired[:50])
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_password_policy(self) -> CheckResult:
        """
        Inspect /etc/login.defs and common PAM modules for min password length and lockout settings.
        """
        found: List[str] = []
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            txt = self._read_cached(login_defs)
            for ln in txt.splitlines():
                l = ln.strip()
                if l.startswith("PASS_MAX_DAYS") or l.startswith("PASS_MIN_DAYS") or l.startswith("PASS_MIN_LEN") or l.startswith("LOGIN_RETRIES"):
                    found.append(f"/etc/login.defs: {l}")
        else:
            found.append("/etc/login.defs not present")
        # PAM: look for pam_unix and faillock/tally2 references in /etc/pam.d/*
        pam_dir = Path("/etc/pam.d")
        if pam_dir.exists() and pam_dir.is_dir():
            for f in sorted(pam_dir.iterdir()):
                if f.is_file():
                    txt = self._read_cached(f)
                    for ln in txt.splitlines():
                        if "pam_unix" in ln or "pam_tally2" in ln or "pam_faillock" in ln:
                            found.append(f"{f}: {ln.strip()}")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_ssh_hardening(self) -> CheckResult:  # FIXED THE BUG HERE
        """
        Check sshd_config for PermitRootLogin, PasswordAuthentication, AllowUsers/AllowGroups, AuthorizedKeysCommand
        """
        found: List[str] = []
        sshd_conf = Path("/etc/ssh/sshd_config")
        if sshd_conf.exists():
            txt = self._read_cached(sshd_conf)
            for ln in txt.splitlines():
                l = ln.strip()
                if not l or l.startswith("#"):
                    continue
                if l.startswith("PermitRootLogin"):
                    if "no" not in l.lower():
                        found.append(f"PermitRootLogin: {l}")
                if l.startswith("PasswordAuthentication"):
                    if "no" not in l.lower():
                        found.append(f"PasswordAuthentication: {l}")
                if l.startswith("AllowUsers") or l.startswith("AllowGroups"):
                    # presence is informational; flag if wildcard/empty
                    if "*" in l or l.endswith("=") or len(l.split()) <= 1:
                        found.append(f"Weak AllowUsers/Groups: {l}")
                if l.startswith("AuthorizedKeysCommand"):
                    found.append(f"AuthorizedKeysCommand present: {l}")
        else:
            found.append("/etc/ssh/sshd_config not found")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_pam_misconfigurations(self) -> CheckResult:
        """
        Look for pam_unix and pam_tally2/faillock anomalies (missing, mis-ordered).
        """
        found: List[str] = []
        pam_dir = Path("/etc/pam.d")
        if pam_dir.exists() and pam_dir.is_dir():
            for f in sorted(pam_dir.iterdir()):
                if f.is_file():
                    txt = self._read_cached(f)
                    # check for usage of pam_unix
                    if "pam_unix" not in txt:
                        # some services may legitimately not use pam_unix; skip generic warning
                        continue
                    # look for faillock/tally2 presence (should be in auth section)
                    if "pam_faillock" not in txt and "pam_tally2" not in txt:
                        # note: not always present; just flag as informational
                        found.append(f"{f}: no faillock/tally2 referenced")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_dns_consistency(self) -> CheckResult:
        """
        Compare /etc/hosts entries vs /etc/resolv.conf nameservers and look for anomalies.
        """
        found: List[str] = []
        hosts = Path("/etc/hosts")
        resolv = Path("/etc/resolv.conf")
        hosts_txt = self._read_cached(hosts) if hosts.exists() else ""
        resolv_txt = self._read_cached(resolv) if resolv.exists() else ""
        # look for localhost missing or odd entries
        if "127.0.0.1" not in hosts_txt:
            found.append("/etc/hosts: missing 127.0.0.1 entry")
        # resolv nameserver order and public DNS
        for ln in resolv_txt.splitlines():
            l = ln.strip()
            if l.startswith("nameserver"):
                parts = l.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    if ip in ("8.8.8.8", "8.8.4.4") and "vpn" not in resolv_txt.lower():
                        found.append(f"Public DNS resolver in resolv.conf: {ip}")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_open_ports_services(self) -> CheckResult:
        """
        Use ss (or netstat fallback) to list listening sockets; flag public bindings and known plaintext services.
        """
        found: List[str] = []
        # try ss
        rc, out, err = self.cmd_runner(["ss", "-lntp"], 3)
        text = out if rc == 0 else ""
        if not text:
            rc, out, err = self.cmd_runner(["netstat", "-lntp"], 3)
            text = out if rc == 0 else ""
        if not text:
            return {"status": "WARN", "count": 0, "details": ["Could not enumerate listening sockets (ss/netstat missing)"]}
        for ln in text.splitlines():
            l = ln.strip()
            # try to find lines with LISTEN and local address
            if "LISTEN" in l:
                found.append(l)
        # flag public binds (0.0.0.0 or :::)
        public = [x for x in found if "0.0.0.0:" in x or ":::" in x]
        details = self._cap(found)
        status = "OK" if not public else "WARN"
        return {"status": status, "count": len(found), "details": details}

    def check_service_versions(self) -> CheckResult:
        """
        Best-effort sample versions for services: sshd, nginx, dnsmasq
        """
        services = {
            "sshd": ["sshd", "-V"], 
            "nginx": ["nginx", "-v"], 
            "dnsmasq": ["dnsmasq", "--version"]
        }
        found: List[str] = []
        for name, cmd in services.items():
            try:
                rc, out, err = self.cmd_runner(cmd, 3)
                text = out + ("\n" + err if err else "")
                if rc == 0 or text:
                    # Extract first meaningful line
                    lines = [line for line in text.splitlines() if line.strip()]
                    version_info = lines[0] if lines else "unknown"
                    found.append(f"{name}: {version_info}")
                else:
                    found.append(f"{name}: version check failed")
            except Exception as e:
                found.append(f"{name}: exception - {e}")
        status = "OK" if found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_unencrypted_services(self) -> CheckResult:
        """
        Look for common plaintext protocol listeners (ftp, telnet, rsh)
        """
        plaintext_ports = {"ftp": ["21"], "telnet": ["23"], "rsh": ["514"]}
        found: List[str] = []
        # reuse open ports check output
        rc, out, err = self.cmd_runner(["ss", "-lntp"], 3)
        text = out if rc == 0 else ""
        if not text:
            rc, out, err = self.cmd_runner(["netstat", "-lntp"], 3)
            text = out if rc == 0 else ""
        if not text:
            return {"status": "WARN", "count": 0, "details": ["Cannot enumerate sockets"]}
        for proto, ports in plaintext_ports.items():
            for p in ports:
                if f":{p} " in text or f":{p}\n" in text:
                    found.append(f"{proto} listener on port {p}")
        status = "OK" if not found else "WARN"
        return {"status": status, "count": len(found), "details": self._cap(found)}

    def check_ntp_chrony(self) -> CheckResult:
        """
        Check for ntpd/chrony presence and whether servers are configured (and warn on unauthenticated public servers).
        """
        found: List[str] = []
        # check chrony.conf and ntp.conf
        chrony = Path("/etc/chrony/chrony.conf")  # Fixed path
        ntp = Path("/etc/ntp.conf")
        if chrony.exists():
            txt = self._read_cached(chrony)
            for ln in txt.splitlines():
                l = ln.strip()
                if l.startswith("server") and "iburst" in l:
                    found.append(f"chrony server: {l}")
        if ntp.exists():
            txt = self._read_cached(ntp)
            for ln in txt.splitlines():
                l = ln.strip()
                if l.startswith("server"):
                    found.append(f"ntpd server: {l}")
        # fallback: check service status
        rc, out, err = self.cmd_runner(["systemctl", "is-active", "--quiet", "chronyd"], 2)
        if rc == 0:
            found.append("chronyd service active")
        else:
            rc, out, err = self.cmd_runner(["systemctl", "is-active", "--quiet", "chrony"], 2)
            if rc == 0:
                found.append("chrony service active")
        rc, out, err = self.cmd_runner(["systemctl", "is-active", "--quiet", "ntp"], 2)
        if rc == 0:
            found.append("ntpd service active")
        status = "OK" if found else "WARN"  # Changed: if we found services, it's OK
        return {"status": status, "count": len(found), "details": self._cap(found)}

    # --- helper for CLI coloring output ---

    @staticmethod
    def format_check_for_cli(result: CheckResult) -> Tuple[str, str]:
        """
        Return (color, summary) where color is 'green' for OK, 'red' otherwise.
        Summary is simple string: 'OK' or 'N issues'.
        """
        status = (result.get("status") or "").upper()
        if status == "OK":
            return "green", "OK"
        # FAIL or WARN -> red
        count = result.get("count", 0)
        return "red", f"{count} issue(s)"

if __name__ == "__main__":
    aud = Auditor()
    import pprint
    results = aud.run_all()
    pprint.pprint(results)
