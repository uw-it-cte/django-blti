from Crypto.Cipher import AES
from base64 import b64decode, b64encode


class CryptoException(Exception):
    pass


class aes128cbc(object):

    _key = None
    _iv = None

    def __init__(self, key, iv):
        """
        Advanced Encryption Standard object

        Raises CryptoException
        """
        self._bs = 16  # Block size

        if key is None:
            raise CryptoException('Missing AES key')
        else:
            self._key = key

        if iv is None:
            raise CryptoException('Missing AES initialization vector')
        else:
            self._iv = iv

    def encrypt(self, msg):
        try:
            msg = self._pad(self.str_to_bytes(msg))
            crypt = AES.new(self._key, AES.MODE_CBC, self._iv)
            return b64encode(self._iv + crypt.encrypt(msg)).decode('utf-8')
        except Exception as err:
            raise CryptoException('Cannot encrypt message: %s' % err)

    def decrypt(self, msg):
        try:
            msg = b64decode(msg)
            crypt = AES.new(self._key, AES.MODE_CBC, self._iv)
            return self._unpad(crypt.decrypt(msg[self._bs:])).decode('utf-8')
        except Exception as err:
            raise CryptoException('Cannot decrypt message: %s' % err)

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
