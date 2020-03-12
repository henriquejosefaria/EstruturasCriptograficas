import encAES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PublicFormat

key = encAES.gen_dsa_keys(default_backend())
private_key = key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
public_key = key.public_key()
public_key_done = public_key.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
print(private_key)
print(public_key_done)