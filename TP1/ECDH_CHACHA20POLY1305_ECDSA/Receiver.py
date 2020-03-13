import socket
import encChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

class Receiver():
    
    def __init__(self,port,host,crypto):
        self.port = port
        self.host = host
        self.crypto = crypto
        self.connection = None 

    def connect(self):
        self.crypto.gen_ephemeral_key()

        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as so:
            so.bind((self.host,self.port))
            so.listen()
            connect,adress = so.accept()
            with connect:
                print("Starting key Agreement")
                isAgreed = self.crypto.keyAgreementR(connect)
                if isAgreed:
                    print("Receiving with encryption")
                    self.crypto.receiving(connect)

    def run(self):
        self.crypto.setParameters(b'-----BEGIN DH PARAMETERS-----\nMEYCQQC+ncO/Ujb2mfSmTKNAjEDjAnS42amR2TWreIkMUbQ2QJQqp9ZxH9OS/6ET\nGBfmuEcyew5q4LJgy2D2O7VS4UlzAgEC\n-----END DH PARAMETERS-----\n')
        # voltar a conetar?
        self.connect()
receiver_private =b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8qxS9j0ugWkD63+5\nhjA5y0iPJjMGSzrbswHwNEEqxfShRANCAAS64njfs9A6PkywtEnFRmLjdMx4KO72\nvxXtMRzq7esDD7+aDVF/hHVLokczEn7/Rakq5l95OUJWhLB+GCNGcN5M\n-----END PRIVATE KEY-----\n'
receiver_public = b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuuJ437PQOj5MsLRJxUZi43TMeCju\n9r8V7TEc6u3rAw+/mg1Rf4R1S6JHMxJ+/0WpKuZfeTlCVoSwfhgjRnDeTA==\n-----END PUBLIC KEY-----\n'


enc = encChaCha20Poly1305.encChaCha20Poly1305(encChaCha20Poly1305.decodePublicKey(receiver_public,default_backend()),encChaCha20Poly1305.decodePrivateKey(receiver_private,default_backend()))
rec = Receiver(8001,"localhost",enc)
rec.run()