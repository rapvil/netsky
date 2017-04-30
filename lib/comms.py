import struct
import sys
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import HMAC
from dh import create_dh_key, calculate_dh_secret
import time
import re
class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.shared_hash = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()
    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret and convert it to bytes.
            self.shared_hash = bytes.fromhex(calculate_dh_secret(their_public_key, my_private_key))
            print("Shared hash (in bytes): {}".format(self.shared_hash))
        # Our IV is the first 16 bytes of the shared key which is cryptographically secure
        iv = self.shared_hash[:16]
        # Our cipher is AES operating in CFB mode
        self.cipher = AES.new(self.shared_hash, AES.MODE_CFB, iv)
    def send(self, data):
        # If we have a shared_hash then we create a HMAC
        if self.shared_hash is not None:
            hmac = HMAC.new(self.shared_hash, data).hexdigest()
            print("Hex digest of the message is: " + hmac + "\n")
            # Concatenate our hmac with the data to be sent and convert entire message to bytes
            encoded_message = bytes(hmac + data.decode("ascii"), "ascii")
        else:
            encoded_message = data
        if self.cipher:
            encrypted_data = self.cipher.encrypt(encoded_message)
            if self.verbose:
                print("\nOriginal data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}\n".format(len(encrypted_data)))
        else:
            encrypted_data = encoded_message
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)
    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)
        # Decrypt the message
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            if self.verbose:
                print("\nReceiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}\n".format(data))
        else:
            data = encrypted_data
        # Need to check the HMAC is correct
        if self.shared_hash is not None:
            our_hmac = HMAC.new(self.shared_hash)
            # Get their HMAC from the data we received
            their_hmac = data[:our_hmac.digest_size * 2]
            # Get their message from the data we received
            data = data[our_hmac.digest_size * 2:]
            # Now we apply their message to our HMAC
            our_hmac.update(data)
            # If they don't match, message has been tampered with
            if our_hmac.hexdigest() != str(their_hmac, 'ascii'):
                raise RuntimeError("Message has been tampered with! HMAC's do not match.")
        return data
    def close(self):
        self.conn.close()