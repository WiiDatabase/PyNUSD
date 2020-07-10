import struct
from enum import Enum
from io import BytesIO
from typing import Optional, Union

from Crypto.PublicKey.RSA import construct as rsa_construct, RsaKey
from Crypto.Signature import PKCS1_v1_5

from WADGEN import Signature, Base, SIGNATURETYPE


class PUBLICKEYTYPE(Enum):
    RSA_4096 = 0
    RSA_2048 = 1
    ECC = 2


class Certificate:
    def __init__(self,
                 f: Optional[BytesIO] = None,
                 sigtype: Optional[SIGNATURETYPE] = None,
                 keytype: Optional[PUBLICKEYTYPE] = None):
        if f and sigtype:
            raise Exception("Signature type is not needed when file is passed.")
        if f and keytype:
            raise Exception("Key type is not needed when file is passed.")
        if not f and not sigtype and not keytype:
            raise Exception("sigtype and keytype must be defined when not creating from file.")

        if f:
            if isinstance(f, BytesIO):
                self.parse(f)
            else:
                raise Exception("Argument must be BytesIO.")
        else:
            self.signature = Signature(sigtype=sigtype)
            self.issuer = b"\x00" * 64
            self.keytype = keytype.value
            self.name = b"\x00" * 64
            self.unknown = b"\x00" * 4
            if self.keytype == 0:  # RSA_4096
                self.modulus = b"\x00" * 512
                self.exponent = 0
                self.padding = b"\x00" * 52
            elif self.keytype == 1:  # RSA_2048
                self.modulus = b"\x00" * 256
                self.exponent = 0
                self.padding = b"\x00" * 52
            elif self.keytype == 2:  # Elliptic Curve
                self.key = b"\x00" * 60
                self.padding = b"\x00" * 60
            else:
                raise Exception("Unknwon key type: {0}".format(self.keytype))

    def parse(self, f: BytesIO):
        self.signature = Signature(f)
        self.issuer = f.read(64)
        self.keytype = struct.unpack(">I", f.read(4))[0]
        self.name = f.read(64)
        self.unknown = f.read(4)
        if self.keytype == 0:  # RSA_4096
            self.modulus = f.read(512)
            self.exponent = struct.unpack(">I", f.read(4))[0]
            self.padding = f.read(52)
        elif self.keytype == 1:  # RSA_2048
            self.modulus = f.read(256)
            self.exponent = struct.unpack(">I", f.read(4))[0]
            self.padding = f.read(52)
        elif self.keytype == 2:  # Elliptic Curve
            self.key = f.read(60)
            self.padding = f.read(60)
        else:
            raise Exception("Unknwon key type: {0}".format(self.keytype))

    def get_signature(self) -> Signature:
        return self.signature

    def get_issuer(self) -> str:
        return self.issuer.rstrip(b"\00").decode().split("-")[-1]

    def get_name(self) -> str:
        return self.name.rstrip(b"\00").decode()

    def get_public_key(self) -> RsaKey:
        if self.keytype == 2:
            # TODO: Construct ECC key? Is this possible? Would be nice.
            raise Exception("Can't create public key from ECC key.")

        return rsa_construct(
                (int.from_bytes(self.modulus, byteorder="big"), self.exponent)
        )

    def get_signer(self) -> PKCS1_v1_5:
        return PKCS1_v1_5.new(self.get_public_key())

    def pack(self, include_signature=True) -> bytes:
        pack = b""
        if include_signature:
            pack += self.signature.pack()
        pack += self.issuer
        pack += struct.pack(">I", self.keytype)
        pack += self.name
        pack += self.unknown
        if self.keytype != 2:  # RSA_4096 and RSA_2048
            pack += self.modulus
            pack += struct.pack(">I", self.exponent)
        else:  # Elliptic Curve
            pack += self.key
        pack += self.padding
        return pack

    def get_key_type(self) -> str:
        # https://www.3dbrew.org/wiki/Certificates#Public_Key
        key_types = [
            "RSA-4096",
            "RSA-2048",
            "Elliptic Curve"
        ]
        try:
            return key_types[self.keytype]
        except IndexError:
            return "Unknown key type"

    def __len__(self):
        return len(self.pack())

    def __repr__(self):
        return "<Certificate(name='{name}', issuer='{issuer}', type='{type}')>".format(
                name=self.get_name(),
                issuer=self.get_issuer(),
                type=self.get_key_type()
        )


class RootKey(Base):
    def __init__(self, f: Union[str, bytes, bytearray, BytesIO, None] = None):
        self.modulus = b"\x00" * 512
        self.exponent = 0

        super().__init__(f)

    def parse(self, f: BytesIO):
        self.modulus = f.read(512)
        self.exponent = struct.unpack(">I", f.read(4))[0]

    def pack(self) -> bytes:
        pack = self.modulus
        pack += struct.pack(">I", self.exponent)
        return pack

    @staticmethod
    def get_name() -> str:
        return "Root"

    @staticmethod
    def get_key_type() -> str:
        return "RSA-4096"

    def get_public_key(self) -> RsaKey:
        return rsa_construct(
                (int.from_bytes(self.modulus, byteorder="big"), self.exponent)
        )

    def get_signer(self) -> PKCS1_v1_5:
        return PKCS1_v1_5.new(self.get_public_key())

    def __repr__(self):
        return "<Nintendo Public Root Key(type='{type}')>".format(
                type=self.get_key_type()
        )

    def __str__(self):
        output = "Nintendo Public Root Key:\n"
        output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())

        return output
