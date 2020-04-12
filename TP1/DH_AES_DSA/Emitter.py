import socket
import encAES
from cryptography.hazmat.backends import default_backend

class Emitter():
    
    def __init__(self,crypto):
        self.crypto = crypto

    def connect(self,host,port):
        self.crypto.gen_ephemeral_key()
        
        with  socket.socket(socket.AF_INET,socket.SOCK_STREAM) as so:
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

dsa_private = b'-----BEGIN PRIVATE KEY-----\nMIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBANjO/0RXzN+q/IjzOeLMuZAB61YI\nI2jSDW3s0r653eV51lLarVyqckbq3W39K6XjJkH/LmB1eaX9elJbepGmcFkrsUm1\nG+YvvLknZlOG0C6IsdRXmu7xIpR03xxiXKDlMB0RFVdTJ2WXpYKBe8jGAJjn/Ic+\nfNKN5+DFrK+gF23rAhUApMrMJebIcmQy3uL1QVdW6NmjV+sCgYEAuXzsREwh1696\n4we/j/sdU0es6sThMDwPiDEWo7l89Sy2VD0hG1E3mmprLL5BAReMHHMWa48j4dm6\noikIWNQ4vpl+EGZTtNIPZ5jTVb1VS7InNq4J5pYoNxYUAQP1k5EAU+YvEBUcUEYi\nQCnBo8/38QjuaLLykZMs8VsNCAAQ38EEFgIUA8ckb7C0CpGKtxdy1EK6wrJCzb0=\n-----END PRIVATE KEY-----\n'
dsa_public = b'-----BEGIN PUBLIC KEY-----\nMIIBtjCCASsGByqGSM44BAEwggEeAoGBAJ4f0ZDjyq9CCq+uBpMLlro2BxtV7ZUc\nCeuS9Uv+tHzVIVrDGlduT7Xa7offmD+/M0UOiRMGEzZ2wq2AV9sbpDLC9EhBw0oj\ntp21xXTwRet6ze3Oz5TtX0ZYqt1tOA0/3Rx6Pz3RMyabLkRCJnTlhNs6B6ZrtEPu\n4g/0y7jrdsCjAhUAnFFnH9YWX4Jw85ajimsXU+sZE3ECgYAc6yd9Bsox/69nLZAV\nR8t4izKVh3q6YNUZqQZnxS44patYS7CViLYTXhqjRBiU/R2ArGA09DN9dR2Xo9hQ\n54J2zwk83k0rd11NYi+UF1N7Frn0PeYhe9EmNy+5hasjjcJpF+FJ9BjcctnmY3HM\nXdtYoId7H/rMfZNoUtL8AAHvPAOBhAACgYAqrZs+97ytSf4f+t+qq1tSDZUDYVHp\nNe2XZAB27GR152oPvc+4No4hMA5eAvn4kBOL/3emlz4zG70eOMrJqY7fytewA581\nF/zgsuCLMpQuec5Z5A5OvWGAsEuT3BZ7ttHeCGpbrTnzk2NYTINHYsabJ/451ip4\nNAK54r5hYUOTpg==\n-----END PUBLIC KEY-----\n'

enc = encAES.encAES(encAES.decodePublicKey(dsa_public,default_backend()),encAES.decodePrivateKey(dsa_private,default_backend()))
emi = Emitter(enc)
emi.run()
