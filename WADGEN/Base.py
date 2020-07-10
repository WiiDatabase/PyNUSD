from abc import ABC, abstractmethod
from io import BytesIO
from typing import Union


class Base(ABC):

    def __init__(self, f: Union[str, bytes, bytearray, BytesIO, None] = None):
        super().__init__()
        if f:
            if isinstance(f, str):
                self.parse_file(f)
            elif isinstance(f, bytearray):
                self.parse_bytearray(f)
            elif isinstance(f, bytes):
                self.parse_bytes(f)
            elif isinstance(f, BytesIO):
                self.parse(f)
            else:
                raise Exception("Argument must either be a path to a file, BytesIO, bytes or a bytearray.")

    @abstractmethod
    def parse(self, f: BytesIO):
        pass

    @abstractmethod
    def pack(self) -> bytes:
        pass

    def parse_file(self, filename: str):
        with open(filename, "rb") as file:
            bytesio = BytesIO(file.read())
        self.parse(bytesio)

    def parse_bytearray(self, bytearr: bytearray):
        bytesio = BytesIO(bytearr)
        self.parse(bytesio)

    def parse_bytes(self, byt: bytes):
        bytesio = BytesIO(byt)
        self.parse(bytesio)

    def __len__(self):
        """Normally always without certificates, but with the signature."""
        return len(self.pack())
