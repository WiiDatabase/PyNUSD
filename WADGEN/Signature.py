import struct
from io import BytesIO
from typing import Optional


class Signature:
    def __init__(self, f: Optional[BytesIO] = None, sigtype: Optional[int] = None):
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
            if not isinstance(sigtype, int):
                raise Exception("Signature type must be an integer.")
            self.type = sigtype
            self.data = b"\x00" * self.get_signature_data_size()
            self.padding = b"\x00" * self.get_signature_padding_size()

    def get_signature_data_size(self) -> int:
        # https://www.3dbrew.org/wiki/Title_metadata#Signature_Type
        signature_type = hex(self.type)
        signature_sizes = {
            "0x10000": 0x200,
            "0x10001": 0x100,
            "0x10002": 0x3C
        }

        try:
            return signature_sizes[signature_type]
        except KeyError:
            raise ValueError("Invalid signature type: {0}".format(signature_type))

    def get_signature_padding_size(self) -> int:
        # https://www.3dbrew.org/wiki/Title_metadata#Signature_Type
        signature_type = hex(self.type)
        signature_sizes = {
            "0x10000": 0x3C,
            "0x10001": 0x3C,
            "0x10002": 0x40
        }

        try:
            return signature_sizes[signature_type]
        except KeyError:
            raise ValueError("Invalid signature type: {0}".format(signature_type))

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
            raise ValueError("Data is bigger than {0} bytes".format(self.get_signature_padding_size()))
        self.data = byt

    def zerofill(self):
        self.data = b"\x00" * self.get_signature_data_size()

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
