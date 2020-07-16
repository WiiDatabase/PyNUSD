import binascii
import hashlib
import math
from enum import Enum
from typing.io import BinaryIO

from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Protocol.KDF import PBKDF2


class MAXVALUE(Enum):
    UINT16 = 65535
    UINT32 = 4294967295
    UINT64 = 18446744073709551615


class Crypto:
    """"This is a Cryptographic/hash class used to abstract away things."""
    blocksize = 64
    KEYGEN_SECRET = b"\xfd\x04\x01\x05\x06\x0b\x11\x1c\x2d\x49"

    @classmethod
    def derive_decrypted_titlekey(cls, titleid: str, password: str) -> bytes:
        if not isinstance(password, str):
            raise ValueError("Password must be a string.")

        if not isinstance(titleid, str):
            raise ValueError("TitleID must be a string.")

        if len(titleid) != 16:
            raise ValueError("Title ID must be 16 characters long.")

        while titleid[0:2] == "00":
            titleid = titleid[2:]
        if titleid == "":
            raise ValueError("Unexpected TitleID.")

        titleid = binascii.unhexlify(titleid)
        salt = cls.KEYGEN_SECRET + titleid

        key = PBKDF2(password, cls.create_md5hash(salt), dkLen=16, count=20, hmac_hash_module=SHA1)
        return key

    @classmethod
    def derive_decrypted_titlekey_hex(cls, titleid: str, password: str) -> str:
        return binascii.hexlify(cls.derive_decrypted_titlekey(titleid, password)).decode()

    @classmethod
    def decrypt_data(cls, key: bytes, iv: bytes, data: bytes, align_data: bool = True) -> bytes:
        """Decrypts data (aligns to 64 bytes, if needed)."""
        if align_data and (len(data) % cls.blocksize) != 0:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(
                    data + (b"\x00" * (cls.blocksize - (len(data) % cls.blocksize))))
        else:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    @classmethod
    def decrypt_titlekey(cls, commonkey: bytes, iv: bytes, titlekey: bytes) -> bytes:
        """Decrypts title key from the ticket."""
        return AES.new(key=commonkey, mode=AES.MODE_CBC, iv=iv).decrypt(titlekey)

    @classmethod
    def encrypt_titlekey(cls, commonkey: bytes, iv: bytes, titlekey: bytes) -> bytes:
        """Encrypts title key."""
        return AES.new(key=commonkey, mode=AES.MODE_CBC, iv=iv).encrypt(titlekey)

    @classmethod
    def create_md5hash_hex(cls, data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    @classmethod
    def create_md5hash(cls, data: bytes) -> bytes:
        return hashlib.md5(data).digest()

    @classmethod
    def create_sha1hash_hex(cls, data: bytes) -> str:
        return hashlib.sha1(data).hexdigest()

    @classmethod
    def create_sha1hash(cls, data: bytes) -> bytes:
        return hashlib.sha1(data).digest()


def convert_size(size: int) -> str:
    if size == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    s = round(size / p, 2)
    return "%s %s" % (s, size_name[i])


def align_data(data: bytes, blocksize: int = 64):
    if len(data) % blocksize != 0:
        return data + b"\x00" * (64 - (len(data) % 64))
    else:
        return data


def align(value: int, blocksize: int = 64):
    """Aligns value to blocksize

    Args:
        value (int): Length of bytes
        blocksize (int): Block size (Default: 64)

    """
    if value % blocksize != 0:
        return b"\x00" * (64 - (value % 64))
    else:
        return b""


def align_pointer(value: int, block: int = 64) -> int:
    """Aligns pointer to blocksize

    Args:
        value (int): Length of bytes
        block (int): Block size (Default: 64)

    """
    if value % block != 0:
        return block - (value % block)
    else:
        return 0


def align_value(value: int, block: int = 64) -> int:
    if value % block != 0:
        return value + (block - (value % block))
    else:
        return value


def read_in_chunks(file_object: BinaryIO, chunk_size: int = 1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data
