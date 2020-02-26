import struct
import socket

import utils
import msgUtils


# Name:	seed.bitcoinsv.io
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
if 1==1:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((nodes[0], 8333))

    sock.send(msgUtils.getVersionMsg_mik(nodes[2],"37.47.175.101"))

    while 1:
        if( len(sock.recv(1000)) > 0): # Throw away data
            print 'got packet'
else:
    msgUtils.getVersionMsg_mik(nodes[6],"37.47.175.101")
    
