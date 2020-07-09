import hashlib
import math

from Crypto.Cipher import AES


class Crypto:
    """"This is a Cryptographic/hash class used to abstract away things."""
    blocksize = 64

    @classmethod
    def decrypt_titlekey(cls, commonkey: bytes, iv: bytes, titlekey: bytes) -> bytes:
        """Decrypts title key from the ticket."""
        return AES.new(key=commonkey, mode=AES.MODE_CBC, iv=iv).decrypt(titlekey)

    @classmethod
    def encrypt_titlekey(cls, commonkey: bytes, iv: bytes, titlekey: bytes) -> bytes:
        """Encrypts title key."""
        return AES.new(key=commonkey, mode=AES.MODE_CBC, iv=iv).encrypt(titlekey)

    @classmethod
    def create_sha1hash_hex(cls, data) -> str:
        return hashlib.sha1(data).hexdigest()

    @classmethod
    def create_sha1hash(cls, data) -> bytes:
        return hashlib.sha1(data).digest()


def convert_size(size: int) -> str:
    if size == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    s = round(size / p, 2)
    return "%s %s" % (s, size_name[i])


def align_pointer(value: int, block: int = 64):
    """Aligns pointer to blocksize

    Args:
        value (int): Length of bytes
        block (int): Block size (Default: 64)

    """
    if value % block != 0:
        return block - (value % block)
    else:
        return 0
