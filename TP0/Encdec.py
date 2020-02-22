import  os, socket, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

class Encdec:
    MACSIZE = 32;

    def __init__(self,salt,nonce):
        self.backend = default_backend()
        self.salt = salt
        self.nonce = nonce
        #criação chave PBKDF
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length=32,  
            salt= self.salt,
            iterations=100000,
            backend= self.backend
        )
        # Obtenção chave secreta

        byte = 'password'.encode('utf-8')
        # Criação da chave derivada
        partialkey = kdf.derive(byte)
        self.key = base64.urlsafe_b64encode(partialkey)
        (KeyEnc,keyMac) = self.hashKey(self.key)
        self.keyEnc = KeyEnc
        self.keyMac = keyMac


    def encThenMac(self,mensagem):
        msg1 = self.encrypt(mensagem,self.keyEnc)
        msg2 = self.mac(msg1)
        return msg1 + msg2

    def decryptEncThenMac(self, mensagem):
        msg1 = mensagem[:-Encdec.MACSIZE]
        msg2 = mensagem[-Encdec.MACSIZE:]
        self.verifyMac(msg1,msg2)
        decryptMensagem = self.decrypt(msg1,self.keyEnc)
        return decryptMensagem

    # GCM encription (Galois Counter Mode)
    def encrypt(self,mensagem,key):
        msg = mensagem.encode()
        aesgcm = AESGCM(key)
        cy = aesgcm.encrypt(self.nonce,msg,None)
        return self.nonce + cy

    # GCM decription (Galois Counter Mode)
    def decrypt(self,mensagem,key):
        aesgcm = AESGCM(key)
        dec_msg = aesgcm.decrypt(mensagem[:16],mensagem[16:],None)
        return dec_msg.decode()

    # Keys Enc and Mac generation
    def hashKey(self,key):
        m = hashes.Hash(hashes.SHA512(), backend=default_backend())
        m.update(key)
        newKey = m.finalize()
        return newKey[:Encdec.MACSIZE],newKey[Encdec.MACSIZE:]

    # MAC generation
    def mac(self,mensagem):
        h = hmac.HMAC(self.keyMac, hashes.SHA256(), backend=default_backend())
        h.update(mensagem)
        mac = h.finalize()
        return mac

    #verify Message MAC
    def verifyMac(self,mensagem,mac):
        h = hmac.HMAC(self.keyMac, hashes.SHA256(),backend=default_backend())
        h.update(mensagem)
        h.verify(mac)

