#! /usr/bin/env python

from pickle import FALSE, TRUE
import socket
import sys
from telnetlib import DO
import traceback
import threading
import select

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

SOCKET_LIST = []
TO_BE_SENT = []
SENT_BY = {}

PRIVATE_KEYS ={}
PUBLIC_KEYS ={}

def criptografar(msg,  chave_publica: rsa.RSAPublicKey):
    return chave_publica.encrypt(msg, padding.OAEP(
                                         mgf=padding.MGF1(hashes.SHA256()),
                                         algorithm= hashes.SHA256(),
                                         label= None
                                      
                                      ) )
    
def descriptografar(msg, chave_privada: rsa.RSAPrivateKey):
    return chave_privada.decrypt(msg, padding.OAEP(
                                         mgf=padding.MGF1(hashes.SHA256()),
                                         algorithm= hashes.SHA256(),
                                         label= None
                                      
                                      ))  

def assinar(msg, chave_privada: rsa.RSAPrivateKey):
    return chave_privada.sign(msg,padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()), 
                                        salt_length=padding.PSS.MAX_LENGTH ), hashes.SHA256())
    
def verificar(msg,assinatura, chave_publica:rsa.RSAPublicKey):
    try:
        chave_publica.verify(assinatura, msg, padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()), 
                                            salt_length=padding.PSS.MAX_LENGTH )    
                                            , hashes.SHA256())
        return TRUE
    except:
        return FALSE



class Server(threading.Thread):

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.bind(('', 5535))
        self.sock.listen(2)
        SOCKET_LIST.append(self.sock)
        print("Server started on port 5535")

    def run(self):
        while 1:
            read, write, err = select.select(SOCKET_LIST, [], [], 0)
            for sock in read:
                if sock == self.sock : 
                    sockfd, addr = self.sock.accept()
                    print(str(addr))
                    SOCKET_LIST.append(sockfd)
                    print(SOCKET_LIST[len(SOCKET_LIST) - 1])
                else:
                    try:
                        s = sock.recv(2048)
                        if s == '':
                            print(str(sock.getpeername()))
                            continue
                        else:
                            try:
                                #Verificando se a mensagem recebida é chave pública ou privada        
                                if(str(s).startswith("b'-----BEGIN PUBLIC")): 
                             
                                  PUBLIC_KEYS[str(sock.getpeername())] =  load_pem_public_key(s)  
                                
                                elif(str(s).startswith("b'-----BEGIN RSA PRIVATE")):

                                  PRIVATE_KEYS[str(sock.getpeername())] = load_pem_private_key(s, None)
                                else:
                                    #Verifica a autenticidade da mensagem 
                                    assinatura = assinar(s,  PRIVATE_KEYS[str(sock.getpeername())])
                                    
                                    if verificar(s, assinatura, PUBLIC_KEYS[str(sock.getpeername())]) == TRUE:                                 
                                        TO_BE_SENT.append(s)
                                        SENT_BY[s] = (str(sock.getpeername()))  
                                                  
                                    else:
                                        print("Mensagem com autenticidade comprometida!!")    
                            except:
                                traceback.print_exc(file=sys.stdout)
                    except:
                    
                        print(str(sock.getpeername()))


class handle_connections(threading.Thread):
    def run(self):
        while 1:
            read, write, err = select.select([], SOCKET_LIST, [], 0)
            for items in TO_BE_SENT:
                for s in write:
                    try:
                        if (str(s.getpeername()) == SENT_BY[items]):
                            print("Ignoring %s" % (str(s.getpeername())))
                            continue
                        #Descriptografando a mensagem e criptografando novamente com a chave pública do cliente destino    
                        msg_descriptografada = descriptografar(items, PRIVATE_KEYS[SENT_BY[items]])
                        msg = criptografar(msg_descriptografada, PUBLIC_KEYS[str(s.getpeername())])
                        print("Sending to %s" % (str(s.getpeername())))

                        s.send(msg)
                    except:
                        traceback.print_exc(file=sys.stdout)
                TO_BE_SENT.remove(items)
                del (SENT_BY[items])


if __name__ == '__main__':
    srv = Server()
    srv.init()
    srv.start()
    print(SOCKET_LIST)
    handle = handle_connections()
    handle.start()


    
