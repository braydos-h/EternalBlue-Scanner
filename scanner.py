import socket
import sys

def check_eternalblue_vuln(ip):
    # SMB negotiation request (partial, minimal)
    # This is a simplified version of the SMB negotiation packet used in EternalBlue
    # The actual packet is more complex and includes various dialects and options.
    # For demonstration purposes, this is a minimal packet that may trigger a response from vulnerable systems.
    # In a real-world scenario, you would need to construct a more complete packet.
    # anyway who ill fix this up later😜
    smb_packet = bytes.fromhex(
        "00000090"  # NetBIOS Session Service
        "ff534d42"  # SMB Header: Server Component: SMB
        "72000000"  # SMB Command: Negotiate Protocol
        "00000000"  # NT Status
        "1801"      # Flags
        "0000"      # Flags2
        "00000000"  # Process ID High
        "0000000000000000"  # Signature
        "0000"      # Reserved
        "0000"      # Tree ID
        "0000"      # Process ID
        "0000"      # User ID
        "0000"      # Multiplex ID
        "00"        # Word Count
        "31"        # Byte Count
        "02"        # Dialect Buffer Format
        "4C414E4D414E312E3000"  # LANMAN1.0
        "02"        # Dialect Buffer Format
        "4E54204C4D20302E313200"  # NT LANMAN 0.12
    )

    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 3 second timeout
        s.connect((ip, 445))

        # Send SMB negotiation
        s.send(smb_packet)
        data = s.recv(1024)

        if data[4:8] == b'\xffSMB':
            print(f"[+] {ip} responds like SMB — Possible EternalBlue target.")
        else:
            print(f"[-] {ip} does not look like SMB.")

        s.close()

    except Exception as e:
        print(f"[-] Failed to scan {ip}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    check_eternalblue_vuln(target_ip)
