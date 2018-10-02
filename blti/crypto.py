from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode, b64encode


class aes128cbc(object):

    _key = None
    _iv = None

    def __init__(self, key, iv):
        """
        Advanced Encryption Standard object
        """
        self._bs = 16  # Block size

        if key is None:
            raise ValueError('Missing AES key')
        else:
            self._key = self.str_to_bytes(key)

        if iv is None:
            raise ValueError('Missing AES initialization vector')
        else:
            self._iv = self.str_to_bytes(iv)

    def encrypt(self, msg):
        msg = self._pad(self.str_to_bytes(msg))
        crypt = Cipher(algorithms.AES(self._key), modes.CBC(self._iv),
                       backend=default_backend()).encryptor()
        return b64encode(crypt.update(msg) +
                         crypt.finalize()).decode('utf-8')

    def decrypt(self, msg):
        msg = b64decode(msg)
        crypt = Cipher(algorithms.AES(self._key), modes.CBC(self._iv),
                       backend=default_backend()).decryptor()
        return self._unpad(crypt.update(msg) +
                           crypt.finalize()).decode('utf-8')

    def _pad(self, s):
        return s + (self._bs - len(s) % self._bs) * self.str_to_bytes(chr(
            self._bs - len(s) % self._bs))

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    def str_to_bytes(self, s):
        u_type = type(b''.decode('utf8'))
        if isinstance(s, u_type):
            return s.encode('utf8')
        return s
