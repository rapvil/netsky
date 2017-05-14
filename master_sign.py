import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html
def generate_RSA(bits=2048):
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    f=open('pubKey.der','w')
    f.write(public_key)
    f.close()

    f=open('privKey.der','w')
    f.write(private_key)
    f.close()

    return

def sign_file(f):
    ##WRONG because the key used is dependant on the keys already existing

    # TODOPart 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    key = RSA.importKey(open('privKey.der').read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(f)
    return (ciphertext)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)