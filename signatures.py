#Signatures.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public = private.public_key()
    return private, public

def sign(message, private):
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig

def verify(message, sig, public):
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("error executing verification")
        return False

def printprivatekey(private):
    pr_key = private.private_bytes(
             encoding=serialization.Encoding.PEM,
             format=serialization.PrivateFormat.PKCS8,
             encryption_algorithm=serialization.NoEncryption()
    )
    return pr_key

def 

if __name__ == '__main__':
    pr,pu = generate_keys()
    print(f"Private key is {pr}")
    print(printprivatekey(pr))
    print(f"Public key is {pu}")
    message = b"This is a secret message"
    sig = sign(message, pr)
    print(f"This is the signature: {sig}")
    correct = verify(message, sig, pu)

    if correct:
        print("Success! Good Signature")
    else:
        print ("ERROR! Signature is bad")
