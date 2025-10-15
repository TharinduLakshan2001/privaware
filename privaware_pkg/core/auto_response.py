"""
Auto-Response Actions for PrivAware
"""
import subprocess

def kill_process(name):
    subprocess.run(["pkill", "-f", name])

def block_ip(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unmount_usb(dev):
    subprocess.run(["sudo", "umount", f"/dev/disk/by-id/{dev}"])
