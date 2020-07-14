import struct
from enum import Enum
from io import BytesIO
from typing import Optional


class SIGNATURETYPE(Enum):
    RSA_4096_SHA1 = 0x010000
    RSA_2048_SHA1 = 0x10001
    ECC_SHA1 = 0x010002


class Signature:
    def __init__(self, f: Optional[BytesIO] = None, sigtype: Optional[SIGNATURETYPE] = None):
        if f and sigtype:
            raise Exception("Signature type is not needed when file is passed.")
        if not f and not sigtype:
            raise Exception("sigtype has to be defined when not creating from file.")

        if f:
            if isinstance(f, BytesIO):
                self.parse(f)
            else:
                raise Exception("Argument must be BytesIO.")
        else:
            if not isinstance(sigtype, SIGNATURETYPE):
                raise Exception("Signature type must be from class SIGNATURETYPES.")
            self.type = sigtype.value
            self.data = b"\x00" * self.get_signature_data_size()
            self.padding = b"\x00" * self.get_signature_padding_size()

    def get_signature_data_size(self) -> int:
        # https://www.3dbrew.org/wiki/Title_metadata#Signature_Type
        signature_sizes = {
            SIGNATURETYPE.RSA_4096_SHA1.value: 0x200,
            SIGNATURETYPE.RSA_2048_SHA1.value: 0x100,
            SIGNATURETYPE.ECC_SHA1.value:      0x3C
        }

        try:
            return signature_sizes[self.type]
        except KeyError:
            raise ValueError("Invalid signature type: {0}".format(hex(self.type)))

    def get_signature_padding_size(self) -> int:
        # https://www.3dbrew.org/wiki/Title_metadata#Signature_Type
        signature_sizes = {
            SIGNATURETYPE.RSA_4096_SHA1.value: 0x3C,
            SIGNATURETYPE.RSA_2048_SHA1.value: 0x3C,
            SIGNATURETYPE.ECC_SHA1.value:      0x40
        }

        try:
            return signature_sizes[self.type]
        except KeyError:
            raise ValueError("Invalid signature type: {0}".format(hex(self.type)))

    def parse(self, f: BytesIO):
        self.type = struct.unpack(">I", f.read(4))[0]
        self.data = f.read(self.get_signature_data_size())
        self.padding = f.read(self.get_signature_padding_size())

    def get_signature_type(self) -> str:
        siglength = len(self.data) + len(self.padding)
        if siglength == 0x200 + 0x3C:
            return "RSA-4096 SHA1"
        elif siglength == 0x100 + 0x3C:
            return "RSA-2048 SHA1"
        elif siglength == 0x3C + 0x40:
            return "ECC"
        else:
            return "Unknown"

    def get_data(self) -> bytes:
        return self.data

    def write_data(self, byt: bytes):
        if len(byt) > self.get_signature_data_size():
            raise ValueError("Data is bigger than {0} bytes".format(self.get_signature_data_size()))
        self.data = byt

    def zerofill(self):
        self.data = b"\x00" * self.get_signature_data_size()

    def is_zerofilled(self):
        return self.get_data() == b"\x00" * self.get_signature_data_size()

    def pack(self) -> bytes:
        pack = struct.pack(">I", self.type)
        pack += self.get_data()
        pack += self.padding
        return pack

    def __len__(self):
        return len(self.pack())

    def __repr__(self):
        return "<Signature(type='{type}')>".format(
                type=self.get_signature_type()
        )
