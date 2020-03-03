import time
import socket
import struct
import random
import hashlib

import binascii

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
    version = struct.pack("i", 70015)
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

def protoconfMessage():
    numberOfFields = struct.pack("B",1)
    maxRecvPayloadLength = struct.pack("BI",254,210241024)
    return numberOfFields+maxRecvPayloadLength

def pingMessage():
    return struct.pack("Q",123)


def get_var_number(resp):
    addr_data = resp[:5]
    # print "******* ADDR: " , resp
    addr_count = 0
    var_number = struct.unpack("B",addr_data[0])[0]
    if( var_number < 0xFD ):
        addr_count = var_number
        whats_left = resp[1:]
    elif( var_number == 0xfd ):
        addr_count = struct.unpack("H",addr_data[1:3])[0]
        whats_left = resp[3:]
    elif( var_number == 0xfe ):
        addr_count = struct.unpack("L",addr_data[1:5])[0]
        whats_left = resp[5:]
    return (addr_count,whats_left)
    
#returns True if whole is collected, False if next transmission must be added to what was returned

#returns retval1 flag if more data needed
#returns message_data - complete or incomplete depending on value of retval1 flag
#returns rest of data - in case more than one message was delivered - it is None if retval1 is True (more data needed) 
#returns flag - if True then discard given message - later do the scanning

def collect_message_from(resp):
    valid_start = False
    msg = resp[4:8]

    #checking if we know how those messages
    if (msg[:3]=="inv"):
        valid_start = True
    elif(msg[:4] == "addr"):
        valid_start = True
    elif(msg[:4]=="pong"):
        valid_start=True
    elif(msg[:4]=="ping"):
        valid_start=True

    ret_val_no_need_to_collect_more = True
    start_with_this_data = None
    if(valid_start == True):
        length_of_payload = struct.unpack("I",resp[4+12:4+12+4])[0]
        if(len(resp)< (4+12+4+4+length_of_payload) ):
            #collect more data to get whole message
            return (True,resp,None,False)
        elif(len(resp)== (4+12+4+4+length_of_payload) ):
            #collected whole message
            ret_val_no_need_to_collect_more = True
            start_with_this_data = None
            return (False,resp,None,False)
        else:
            message1 = resp[:4+12+4+4+length_of_payload]
            message2 = resp[4+12+4+4+length_of_payload:]
            return (False,message1,message2,False)
            #collected more than one message. we need to cut
            # we cut, we process full message.
            # then we return process_message(whats_left)
    else:
        #nonvalid
        print "!!! NONVALID",resp
        return (False,None,None,True)

def process_message(resp):
    msg = resp[4:8]
    if (msg[:3]=="inv"):
        inv_data = resp[4+12+4+4:]
        inv_count,whatsleft = get_var_number(inv_data[:5])
        inv_size = 36*inv_count
        print i," MSG: INV, COUNT: %d"% inv_count
        pass
        # print resp
    elif(msg[:4] == "addr"):
        addr_data = resp[4+12+4+4:]
        addr_count,whatsleft = get_var_number(addr_data[:5])
        print i," ---->>> MSG: ADDR , count: %d "%addr_count
        process_addresses(whatsleft+addr_data[5:],addr_count)
    elif(msg[:4]=="pong"):
        print i," MSG: pong"
        pass
    elif(msg[:4]=="ping"):
        print i," MSG: ping"
        pass
    else:
        print i, " ???",msg
        pass

def process_single_addres(single_address_data):
    t=struct.unpack("I",single_address_data[:4])[0]
    services = struct.unpack("Q",single_address_data[4:4+8])[0]
    address = struct.unpack(">16s",single_address_data[4+8:4+8+16])[0]

    (zeropref1,zeropref2,onepref,ipv4_1,ipv4_2,ipv4_3,ipv4_4)=struct.unpack(">QHHBBBB",single_address_data[4+8:4+8+16])
    port = struct.unpack(">H",single_address_data[-2:])[0]
    
    if(zeropref1==0 and zeropref2==0 and onepref==65535):
        print("ADDRESS %d.%d.%d.%d  port:%d"%(ipv4_1,ipv4_2,ipv4_3,ipv4_4,port))
    else: #ipv6 addres
        print("ADDRESS:" + binascii.hexlify(address[0:2])+":"+binascii.hexlify(address[2:4])+":"+binascii.hexlify(address[4:6])+":"+binascii.hexlify(address[6:8])
        +":"+binascii.hexlify(address[8:10])+":"+binascii.hexlify(address[10:12])+":"+binascii.hexlify(address[12:14])+":"+binascii.hexlify(address[14:16]) +  " port:%d"%port)

def process_addresses(address_data,addr_count):
    if(len(address_data)!= addr_count*(4+8+16+2)):
        print "ERROR"
        return
    
    for i in range(0,addr_count):
        process_single_addres( address_data[i*30:i*30+30])
    
    pass

    
if __name__ == "__main__":
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.connect(("52.15.179.79", 8333))
    # sock.send(makeMessage_btc("version", versionMessage()))
    # print "Response version:"
    # print sock.recv(1024) # version
    # print "Response verack:"
    # print sock.recv(1024) # verack
#testnet-seed.bitcoinsv.io

#nslookpu seed.bitcoinsv.io
# [ res[-1][0] for res in socket.getaddrinfo("seed.bitcoinsv.io",0,0,0,0)]
# [ res[-1][0] for res in socket.getaddrinfo("testnet-seed.bitcoinsv.io",0,0,0,0)]
    nodes=[
    '139.59.67.18',
'157.230.41.128',
'159.65.152.200',
'167.99.92.186',
'174.138.5.253',
'178.128.232.188',
'206.189.81.233',
'206.189.104.98',
'68.183.42.63',
'68.183.207.240',
'104.248.30.60',
'104.248.245.82'
    ]
    print "-"*30 + " BSV " + "-"*30
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((nodes[6], 8333))

    sock.send(makeMessage_bsv("version", versionMessage()))
    print "Response version:"
    print sock.recv(1024) # version
    sock.send(makeMessage_bsv("verack",''))
    print "Response verack2 :",sock.recv(2*1024) # verack

    print "--- sending PROTOCONF"
    # sock.send(makeMessage_bsv("protoconf", protoconfMessage()))
    # sock.send(makeMessage_bsv("version", versionMessage()))
    print "Protoconf response:",sock.recv(1024) # verack
    print "\n"
    print "Protoconf response2:",sock.recv(1024) # verack
    
    print "---- SENDING PING"
    sock.send(makeMessage_bsv("getaddr",''))
    sock.send(makeMessage_bsv("ping",pingMessage()))
    print "ping response:",sock.recv(1024) # verack
    
    print "--- "+"get addr"+" --- BLADA TWARZ" 
    # sock.send(makeMessage_bsv("blada twARZ",''))
    sock.send(makeMessage_bsv("getaddr",''))
    
    i = 0
    state = ''
    inv_data = ''
    addr_data = ''
    resp = ''
    while i<3000:
        if(resp == None):
            resp = ''
        resp += sock.recv(30024) 
        
        (more_data_flag,message1,message2,discad_data_flag) = collect_message_from(resp)
        
        if(discad_data_flag==True):
            resp = ''
            pass
        elif more_data_flag==True:
            resp = message1
        elif more_data_flag==False:
            resp = ''
            process_message(message1)

            while (message2!=None):
                resp = message2
                (more_data_flag,message1,message2,discad_data_flag) = collect_message_from(resp)
                if(discad_data_flag==True):
                    resp = ''
                    break
                elif more_data_flag==True:
                    resp = message1
                    break
                elif more_data_flag==False:
                    process_message(message1)
                    resp = message2

        
        i = i+1
        if(i%10==0):
            print "::: SENDING GETADDR :::"
            sock.send(makeMessage_bsv("getaddr",''))

        if(i%101==0):
            print "::: SENDING PING :::"
            sock.send(makeMessage_bsv("ping",pingMessage()))
    

