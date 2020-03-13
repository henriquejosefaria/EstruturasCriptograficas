from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec

priv_key_ECDSA = ec.generate_private_key(ec.SECP256R1(), default_backend())
priv_key_ECDSA_bytes = priv_key_ECDSA.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())

pub_key_ECDSA = priv_key_ECDSA.public_key()
pub_key_ECDSA_bytes = pub_key_ECDSA.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

print(priv_key_ECDSA_bytes)
print(pub_key_ECDSA_bytes)

