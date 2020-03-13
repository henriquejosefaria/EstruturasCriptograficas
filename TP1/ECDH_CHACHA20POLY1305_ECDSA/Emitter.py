import socket
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
        self.crypto.setParameters(b'-----BEGIN DH PARAMETERS-----\nMEYCQQC+ncO/Ujb2mfSmTKNAjEDjAnS42amR2TWreIkMUbQ2QJQqp9ZxH9OS/6ET\nGBfmuEcyew5q4LJgy2D2O7VS4UlzAgEC\n-----END DH PARAMETERS-----\n')
        # voltar a conetar?
        self.connect("localhost",8001)

emitter_private = b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn7V5eN4xEdOQIeoN\nS1L+ktkKXqYamjPeGluQWiunR+ChRANCAARbwEwyxnt6sejaSssI7CzlyqRzpGdn\n31eDm96q+isoHDqtfpdNiYtBws4EY6rk2eDcpibTwozq1rQHuQe0HnC/\n-----END PRIVATE KEY-----\n'
emitter_public = b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW8BMMsZ7erHo2krLCOws5cqkc6Rn\nZ99Xg5veqvorKBw6rX6XTYmLQcLOBGOq5Nng3KYm08KM6ta0B7kHtB5wvw==\n-----END PUBLIC KEY-----\n'


enc = encChaCha20Poly1305.encChaCha20Poly1305(encChaCha20Poly1305.decodePublicKey(emitter_public,default_backend()),encChaCha20Poly1305.decodePrivateKey(emitter_private,default_backend()))
emi = Emitter(enc)
emi.run()