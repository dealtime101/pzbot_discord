# pz_rcon.py
import socket
import struct
from typing import Tuple

# Source RCON packet types
SERVERDATA_RESPONSE_VALUE = 0
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2  # auth response comes back as type 2 in practice

def _pack_packet(req_id: int, req_type: int, body: str) -> bytes:
    data = body.encode("utf-8") + b"\x00"
    pkt = struct.pack("<ii", req_id, req_type) + data + b"\x00"
    return struct.pack("<i", len(pkt)) + pkt

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading")
        buf += chunk
    return buf

def _recv_packet(sock: socket.socket) -> Tuple[int, int, str]:
    (size,) = struct.unpack("<i", _recv_exact(sock, 4))
    payload = _recv_exact(sock, size)
    req_id, req_type = struct.unpack("<ii", payload[:8])
    body = payload[8:-2]  # strip 2 null terminators
    return req_id, req_type, body.decode("utf-8", errors="replace")

def rcon_exec(host: str, port: int, password: str, command: str, timeout: float = 3.0) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))

    try:
        # Auth
        auth_id = 1
        sock.sendall(_pack_packet(auth_id, SERVERDATA_AUTH, password))

        rid, rtype, body = _recv_packet(sock)
        # Some servers send an empty response first; if so read one more
        if rid != auth_id:
            rid, rtype, body = _recv_packet(sock)

        if rid == -1:
            raise PermissionError("RCON auth failed (bad password)")

        # Exec
        cmd_id = 2
        sock.sendall(_pack_packet(cmd_id, SERVERDATA_EXECCOMMAND, command))

        # Read responses; terminate by sending a dummy "echo" marker technique
        # Many servers chunk responses; we collect until timeout.
        parts = []
        while True:
            try:
                rid, rtype, body = _recv_packet(sock)
                if rid != cmd_id:
                    # ignore unrelated
                    continue
                if body:
                    parts.append(body)
            except socket.timeout:
                break

        return "\n".join(parts).strip()
    finally:
        try:
            sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--cmd", required=True)
    args = ap.parse_args()
    print(rcon_exec(args.host, args.port, args.password, args.cmd))
