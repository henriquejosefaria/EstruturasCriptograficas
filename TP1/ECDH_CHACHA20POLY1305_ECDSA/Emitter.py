import socket
from cryptography.hazmat.primitives.asymmetric import ec
import encChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

class Emitter():
    
    def __init__(self,crypto):
        self.crypto = crypto

    def connect(self,host,port):
        self.crypto.gen_ephemeral_key()
        
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as so:        
                so.connect((host,port))
                print("Starting key Agreement")
                isAgreed = self.crypto.keyAgreementE(so)
                if isAgreed:
                    print("Messaging with encryption")
                    self.crypto.messaging(so)
    
    def run(self):
        self.crypto.setParameters(ec.SECP384R1())
        # voltar a conetar?
        self.connect("localhost",8002)

emitter_private = b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn7V5eN4xEdOQIeoN\nS1L+ktkKXqYamjPeGluQWiunR+ChRANCAARbwEwyxnt6sejaSssI7CzlyqRzpGdn\n31eDm96q+isoHDqtfpdNiYtBws4EY6rk2eDcpibTwozq1rQHuQe0HnC/\n-----END PRIVATE KEY-----\n'
receiver_public = b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuuJ437PQOj5MsLRJxUZi43TMeCju\n9r8V7TEc6u3rAw+/mg1Rf4R1S6JHMxJ+/0WpKuZfeTlCVoSwfhgjRnDeTA==\n-----END PUBLIC KEY-----\n'


enc = encChaCha20Poly1305.encChaCha20Poly1305(encChaCha20Poly1305.decodePublicKey(receiver_public,default_backend()),encChaCha20Poly1305.decodePrivateKey(emitter_private,default_backend()))
emi = Emitter(enc)
emi.run()