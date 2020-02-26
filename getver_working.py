import time
import socket
import struct
import random
import hashlib
def makeMessage_btc(cmd, payload):
    
    # E8F3E1E3
    magic = "F9BEB4D9".decode("hex") # Main network
    command = cmd + (12 - len(cmd)) * "\00"
    length = struct.pack("I", len(payload))
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return magic + command + length + check + payload

def makeMessage_bsv(cmd, payload):
    
    # E8F3E1E3
    magic = "e3e1f3e8".decode("hex") # Main network
    command = cmd + (12 - len(cmd)) * "\00"
    length = struct.pack("I", len(payload))
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return magic + command + length + check + payload


def versionMessage():
    version = struct.pack("i", 60002)
    services = struct.pack("Q", 0)
    timestamp = struct.pack("q", time.time())
    addr_recv = struct.pack("Q", 0)
    addr_recv += struct.pack(">16s", "127.0.0.1")
    addr_recv += struct.pack(">H", 8333)
    addr_from = struct.pack("Q", 0)
    addr_from += struct.pack(">16s", "127.0.0.1")
    addr_from += struct.pack(">H", 8333)
    nonce = struct.pack("Q", random.getrandbits(64))
    user_agent_bytes = struct.pack("B", 0)
    height = struct.pack("i", 0)
    payload = version + services + timestamp + addr_recv + addr_from + nonce +user_agent_bytes + height
    return payload

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("52.15.179.79", 8333))
    sock.send(makeMessage_btc("version", versionMessage()))
    # print "Response version:"
    print sock.recv(1024) # version
    # print "Response verack:"
    # print sock.recv(1024) # verack

    nodes=[
    '206.189.81.233',
    '68.183.207.240',
    '159.65.152.200',
    '157.230.41.128',
    '178.128.232.188',
    '104.248.30.60',
    '139.59.67.18',
    '174.138.5.253',
    '68.183.42.63',
    '167.99.92.186',
    '206.189.104.98',
    '104.248.245.82'
    ]
    print "-"*30 + " BSV " + "-"*30
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((nodes[6], 8333))
    sock.send(makeMessage_bsv("version", versionMessage()))
    print "Response version:"
    print sock.recv(1024) # version
    print "Response verack:"
    print sock.recv(1024) # verack

    print "--- "+"get addr"+" ---" 
    sock.send(makeMessage_bsv("getaddr",""))
    print sock.recv(1024) # version
    print sock.recv(1024) # version
    print sock.recv(1024) # version
    print sock.recv(1024) # version
    print sock.recv(1024) # version

