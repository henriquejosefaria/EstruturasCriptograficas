# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio, os, socket, base64
from Encdec import Encdec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999
#communication_key = b'\xdf,Lr>-\x01\x1e]\xc8\xf3\xc6\x88l\x0fj\xc1\xf5\xf75\xbf\x97\x97\x1e\xd8v\xac\x85\x08btL'


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        #Invocação da biblioteca de encriptação/desencriptação
        self.encdec = None
        self.salt = None
        self.nonce = None
        self.macVerif = None

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1 
        try:
            if self.msg_cnt == 1:
                #SALT
                self.salt = msg
                new_msg = b"RECEIVED SALT"
            elif self.msg_cnt == 2:
                #NONCE
                self.nonce = msg
                new_msg = b"RECEIVED NONCE"
                self.encdec = Encdec(self.salt,self.nonce)
            elif self.msg_cnt == 3:
                #MAC KEY
                self.macVerif = msg
                self.encdec.verifyMac(self.encdec.key,msg)
                #confirma geração da chave correta
                new_msg = msg
            else:
                txt = self.encdec.decryptEncThenMac(msg)
                print('%d : %r' % (self.id,txt))
                new_msg = self.encdec.encThenMac(txt.upper())  
        except Exception:
            if self.msg_cnt < 4:
                print('Mensagem Corrompida:Mensagem Não Encriptada')
                self.msg_cnt = 0
                new_msg = b' NOT VERIFYED'
            elif self.msg_cnt >= 4:
                print('Mensagem Corrompida: Mensagem Encriptada')
                new_msg = self.encdec.encThenMac('TEXTO CORROMPIDO')
            else:
                new_msg = msg
        return new_msg if len(new_msg)>0 else None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
