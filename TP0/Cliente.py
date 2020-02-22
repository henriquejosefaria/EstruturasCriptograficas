# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio, os, socket, base64
from Encdec import Encdec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

conn_port = 8888
max_msg_size = 9999
#communication_key = b'\xdf,Lr>-\x01\x1e]\xc8\xf3\xc6\x88l\x0fj\xc1\xf5\xf75\xbf\x97\x97\x1e\xd8v\xac\x85\x08btL'

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.salt = os.urandom(16)
        self.nonce = os.urandom(16)
        self.wrong=1
        #Invocação da biblioteca de encriptação/desencriptação
        self.encdec = Encdec(self.salt,self.nonce)

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1
        try:
            if len(msg) > 0:
                if self.msg_cnt > 4:
                    dec_msg = self.encdec.decryptEncThenMac(msg)
                    print('Received (%d): %r' % (self.msg_cnt ,dec_msg))
                elif self.msg_cnt == 4:
                    self.msg_cnt = 1
                    # se a mensagem recebida for o mac da chave correta 
                    # o servidor confirmou a correta geração da mesma
                    if msg == self.encdec.mac(self.encdec.key):
                        self.msg_cnt = 4
                else:
                    print("entrei aqui, msg_cnt = ",self.msg_cnt)
                    #print('Received (%d): %r' % (self.msg_cnt,msg))
        except Exception:
            print('Mensagem recebida corrompida')
        
        
        if self.msg_cnt == 1:
            # SALT
            new_msg = self.salt
            encrypted_msg = new_msg
        elif self.msg_cnt == 2:
            # NONCE
            new_msg = self.nonce
            encrypted_msg = new_msg
        elif self.msg_cnt == 3:
            #KEY'S MAC
            new_msg = self.encdec.mac(self.encdec.key)
            encrypted_msg = new_msg
        else:
            print('Input message to send (empty to finish)')
            new_msg = input()
            encrypted_msg = self.encdec.encThenMac(new_msg)
        return encrypted_msg if len(new_msg)>0 else None



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
