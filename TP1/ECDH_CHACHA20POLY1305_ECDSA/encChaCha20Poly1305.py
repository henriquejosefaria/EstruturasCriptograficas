import os
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes,hmac
from cryptography.hazmat.primitives.serialization import Encoding,ParameterFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_parameters,load_pem_public_key,PublicFormat,ParameterFormat
from cryptography.hazmat.primitives.asymmetric import dsa
from chacha20poly1305 import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec


class encChaCha20Poly1305():
	
    RCV_BYTES = 1024
    HMAC_KEY_SIZE = 32
    ENCRYPTION_KEY_SIZE = 32
    
    def __init__(self,dsa_public_key,dsa_private_key):
        self.parameters = None # Parametros para o AES
        self.private_key = None # static chave privada
        self.public_key = None # static chave publica
        self.e_private_key = None # ephemeral chave privada
        self.e_public_key = None # ephemeral chave publica
        self.shared_key = None # chave derivada a partir do segredo partilhado
        self.dsa_private_key = dsa_private_key # Chave privada DSA
        self.dsa_public_key = dsa_public_key # Chave pública DSA do outro
        self.backend = default_backend()


    def gen_key_params(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=512, backend = default_backend())
        self.private_key =  self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
    
    def gen_ephemeral_key(self):
        self.e_private_key = self.parameters.generate_private_key()
        self.e_public_key = self.e_private_key.public_key()

    def setParameters(self, parameters):
        parametersD = decodeParameters(parameters,self.backend)
        if isinstance(parametersD,dh.DHParameters):
            self.parameters = parametersD
            self.private_key = self.parameters.generate_private_key()
            self.public_key = self.private_key.public_key()
            return True
        return False
    
    def generateSharedSecret(self,publicKey,privateKey):
        publicKeyD = decodePublicKey(publicKey,self.backend)
        if isinstance(publicKeyD,dh.DHPublicKey):
            return privateKey.exchange(publicKeyD)
        return None
    
    def generateSharedKey(self,sSharedSecret,eSharedSecret,salt=b"0"):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=(encChaCha20Poly1305.ENCRYPTION_KEY_SIZE + encChaCha20Poly1305.HMAC_KEY_SIZE),salt=salt,iterations=100,backend=self.backend)
        self.shared_key = kdf.derive(sSharedSecret + eSharedSecret)
        sSharedSecret = None
        eSharedSecret = None


    def encrypt(self,msg):
        nonce = os.urandom(12)

    	#cypher generation 
        #key = os.urandom(32)
        cip = ChaCha20Poly1305(self.shared_key[:encChaCha20Poly1305.ENCRYPTION_KEY_SIZE])

    	#encryption ChaCha20Poly1305
        ct = cip.encrypt(nonce, msg)

        ret = {"ct": ct, "nonce": nonce}
        return  pickle.dumps(ret)

    def decrypt(self,ct):
    	#nonce and key retrieval
        ct = pickle.loads(ct)
        nonce = ct["nonce"]
        #key = ct["key"]
 		#cip recreation
        cip = ChaCha20Poly1305(self.shared_key[:encChaCha20Poly1305.ENCRYPTION_KEY_SIZE])

        msg = cip.decrypt(nonce, ct["ct"])
        return msg
    
    def mac(self,msg):
        macer = hmac.HMAC(self.shared_key[encChaCha20Poly1305.ENCRYPTION_KEY_SIZE:encChaCha20Poly1305.HMAC_KEY_SIZE],hashes.SHA256(),backend=self.backend)
        macer.update(msg)
        return macer.finalize()

    def verifyMac(self,msg,mac):
        macer = hmac.HMAC(self.shared_key[encChaCha20Poly1305.ENCRYPTION_KEY_SIZE:encChaCha20Poly1305.HMAC_KEY_SIZE],hashes.SHA256(),backend=self.backend)
        macer.update(msg)
        macer.verify(mac)

    def encryptThenMac(self,msg):
        dump = self.encrypt(msg.encode())
        mac = self.mac(dump)
        return pickle.dumps({"dump": dump,"mac":mac})

    def decryptThenMac(self,ct):
        ct_dump = pickle.loads(ct)
        try:
            self.verifyMac(ct_dump["dump"],ct_dump["mac"])
            return self.decrypt(ct_dump["dump"])
        except InvalidSignature as In:
            print("INVALID")
            return None

    def sign(self,msg):
        return self.dsa_private_key.sign(msg, ec.ECDSA(hashes.SHA256()))

    def verifySign(self,msg,signature):
        self.dsa_public_key.verify(signature,msg,ec.ECDSA(hashes.SHA256()))

    def keyAgreementE(self,connection):
        
        # static
        connection.send(encodePublicKey(self.public_key))
        pk = connection.recv(encChaCha20Poly1305.RCV_BYTES)
        static_shared_secret = self.generateSharedSecret(pk,self.private_key)
        
        # ephemeralcryptography.hazmat.primitives.asymmetric.
        connection.send(encodePublicKey(self.e_public_key))
        e_pk_mac = connection.recv(encChaCha20Poly1305.RCV_BYTES)
        e_pk_mac_load = pickle.loads(e_pk_mac)
        e_shared_secret = self.generateSharedSecret(e_pk_mac_load["e_key"],self.e_private_key)
        
        # shared key
        self.generateSharedKey(static_shared_secret,e_shared_secret)

        #DSA
        
        sign = self.decrypt(e_pk_mac_load["signature"])
        try:
            self.verifySign(pk + encodePublicKey(self.public_key) + e_pk_mac_load["e_key"] + encodePublicKey(self.e_public_key) ,sign)    
        except InvalidSignature as In:
            #connection.send(pickle.dumps({"mac": "mac","signature":"signature"}))
            print("Invalid Signature")
            return False
        
        # test confirmation
        try:
            self.verifyMac(b"KC_1_V" + encodePublicKey(self.e_public_key) + e_pk_mac_load["e_key"],e_pk_mac_load["mac"])
        except InvalidSignature as In:
            #connection.send(pickle.dumps({"mac": "mac","signature":"signature"}))
            print("Key Confirmation Failed")
            return False
        
        # Send mac and sign    
        mac_and_sign = {"mac": self.mac(b"KC_1_U" + encodePublicKey(self.e_public_key) + e_pk_mac_load["e_key"]),"signature": self.encrypt(self.sign( encodePublicKey(self.public_key) + pk + encodePublicKey(self.e_public_key) + e_pk_mac_load["e_key"] )) }
        connection.send(pickle.dumps(mac_and_sign))
         
        e_pk_mac = None
        e_pk_mac_load
        e_shared_secret = None
        static_shared_secret = None
        pk = None

        return True

    def keyAgreementR(self,connection):
        # static
        pk = connection.recv(encChaCha20Poly1305.RCV_BYTES)
        connection.send(encodePublicKey(self.public_key))
        static_shared_secret = self.generateSharedSecret(pk,self.private_key)
        
        # ephemeral
        e_pk = connection.recv(encChaCha20Poly1305.RCV_BYTES)
        e_shared_secret = self.generateSharedSecret(e_pk,self.e_private_key)
        
         # shared key
        self.generateSharedKey(static_shared_secret,e_shared_secret)

        #key confirmation
        key_and_mac_and_sig = pickle.dumps(
            {"e_key": encodePublicKey(self.e_public_key),
            "mac": self.mac(b"KC_1_V" + e_pk + encodePublicKey(self.e_public_key)),
            "signature": self.encrypt(self.sign(encodePublicKey(self.public_key) + pk + encodePublicKey(self.e_public_key) + e_pk))}
            )
        connection.send(key_and_mac_and_sig)
        
        # mac verification
        mac_and_sign = connection.recv(encChaCha20Poly1305.RCV_BYTES)
        mac_and_sign_load = pickle.loads(mac_and_sign)

        sign = self.decrypt(mac_and_sign_load["signature"])
        try:
            self.verifySign(pk + encodePublicKey(self.public_key) + e_pk + encodePublicKey(self.e_public_key) ,sign)    
        except InvalidSignature as In:
            #connection.send(pickle.dumps({"mac": "mac","signature":"signature"}))
            print("Invalid Signature")
            return False

        try:
            self.verifyMac(b"KC_1_U" + e_pk + encodePublicKey(self.e_public_key),mac_and_sign_load["mac"])    
        except InvalidSignature as In:
            print("Key Confirmation Failed")
            return False
        
        
        
        e_pk = None
        e_shared_secret = None
        static_shared_secret = None
        pk = None
        key_and_mac = None

        return True

    def messaging(self,connection):
        print("Now you can send messages")
        while True:
            data = input("---> ")    
            encData = self.encryptThenMac(data)
            connection.send(encData)
            if "Exit" == data:
                break
            
            
    def receiving(self,connection):
        while True:
            try:
                data = connection.recv(encChaCha20Poly1305.RCV_BYTES)  
                dencData = self.decryptThenMac(data)
                print(dencData)
            except EOFError as e:
                print("bye bye")
                break
            

def encodeParameters(parameters):
    return parameters.parameter_bytes(Encoding.PEM,ParameterFormat.PKCS3)

def decodeParameters(parameters,backend):
    return load_pem_parameters(parameters,backend=backend)

def encodePublicKey(publicKey):
    return publicKey.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)

def decodePublicKey(key,backend):
    return load_pem_public_key(key,backend=backend)


def decodePrivateKey(key,backend):
    return load_pem_private_key(key,None,backend=backend)

