#! /usr/bin/env python

from email.policy import default
from logging import exception
import socket
import sys
import time
import threading
import select
import traceback

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key



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




class Server(threading.Thread):

    
    def initialise(self, receive,  chave_privada ):
        self.receive = receive
        self.chave_privada = chave_privada
    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(2048)
                    if s != '':
                        chunk =  descriptografar(s,self.chave_privada)
                        print(chunk.decode() + '\n>>')    
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
 

                
    CHAVE_PUBLICA = 0
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)
        # print "Sent\n"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP \n>>")
            port = int(input("Enter the server Destination Port\n>>"))
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        #Geração das chaves
        private_key  = rsa.generate_private_key(public_exponent = 65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        self.CHAVE_PUBLICA =  public_key

        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive,private_key) #Inicializando Server com chave privada
        srv.daemon = True
        print("Starting service")
        srv.start()
        
        #Enviando chave privada  e pública serializada desse cliente
        key_bytes = self.CHAVE_PUBLICA.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.client(host,port, key_bytes) 

        key_bytes = private_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
        self.client(host,port,key_bytes) 
        
        while 1:
            msg = input('\n>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            msg = user_name + ': ' + msg
            try:
                msg = criptografar(msg.encode('UTF-8'),self.CHAVE_PUBLICA) #Enviando mensagem criptografada e convertida em bytes
                data = msg
                self.client(host, port, data)
            except:
                print("Erro no recebimento de mensagem!")

        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
