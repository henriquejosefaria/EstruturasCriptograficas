import socket
#import encAES
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
        
#dsa_private =b'-----BEGIN PRIVATE KEY-----\nMIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAJ4f0ZDjyq9CCq+uBpMLlro2BxtV\n7ZUcCeuS9Uv+tHzVIVrDGlduT7Xa7offmD+/M0UOiRMGEzZ2wq2AV9sbpDLC9EhB\nw0ojtp21xXTwRet6ze3Oz5TtX0ZYqt1tOA0/3Rx6Pz3RMyabLkRCJnTlhNs6B6Zr\ntEPu4g/0y7jrdsCjAhUAnFFnH9YWX4Jw85ajimsXU+sZE3ECgYAc6yd9Bsox/69n\nLZAVR8t4izKVh3q6YNUZqQZnxS44patYS7CViLYTXhqjRBiU/R2ArGA09DN9dR2X\no9hQ54J2zwk83k0rd11NYi+UF1N7Frn0PeYhe9EmNy+5hasjjcJpF+FJ9Bjcctnm\nY3HMXdtYoId7H/rMfZNoUtL8AAHvPAQWAhR3uVgfzYLCaZH0IjXnx4/5UXlZbg==\n-----END PRIVATE KEY-----\n'
#dsa_public = b'-----BEGIN PUBLIC KEY-----\nMIIBtzCCASwGByqGSM44BAEwggEfAoGBANjO/0RXzN+q/IjzOeLMuZAB61YII2jS\nDW3s0r653eV51lLarVyqckbq3W39K6XjJkH/LmB1eaX9elJbepGmcFkrsUm1G+Yv\nvLknZlOG0C6IsdRXmu7xIpR03xxiXKDlMB0RFVdTJ2WXpYKBe8jGAJjn/Ic+fNKN\n5+DFrK+gF23rAhUApMrMJebIcmQy3uL1QVdW6NmjV+sCgYEAuXzsREwh16964we/\nj/sdU0es6sThMDwPiDEWo7l89Sy2VD0hG1E3mmprLL5BAReMHHMWa48j4dm6oikI\nWNQ4vpl+EGZTtNIPZ5jTVb1VS7InNq4J5pYoNxYUAQP1k5EAU+YvEBUcUEYiQCnB\no8/38QjuaLLykZMs8VsNCAAQ38EDgYQAAoGAVkFf0xs9EA+gS/EowW3k6gkq+wlB\nfMCiNhWXX08zZ21Pxtk0ioDsPxS603GxFsJmc6B2Gm7EfkAS2h1DsyzsdMTgp4JC\ntW2AvDT9b8JZ0aZwkQJ9daOTirXTchoNiU0dOKlgvUFx0bGj1l0/P1pT5fO3A4Ef\n3nyDJ4w5GIjT2DA=\n-----END PUBLIC KEY-----\n'

#enc = encAES.encAES(encAES.decodePublicKey(dsa_public,default_backend()),encAES.decodePrivateKey(dsa_private,default_backend()))
#rec = Receiver(8001,"localhost",enc)
#rec.run()