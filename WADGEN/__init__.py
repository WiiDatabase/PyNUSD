"""Import order is important!"""
import os

from .Base import *
from .Signature import *
from .Certificate import *

DECRYPTION_KEYS = [
    b"\xEB\xE4\x2A\x22\x5E\x85\x93\xE4\x48\xD9\xC5\x45\x73\x81\xAA\xF7",  # Common Key
    b"\x63\xB8\x2B\xB4\xF4\x61\x4E\x2E\x13\xF2\xFE\xFB\xBA\x4C\x9B\x7E",  # Korean Key
    b"\x30\xbf\xc7\x6e\x7c\x19\xaf\xbb\x23\x16\x33\x30\xce\xd7\xc2\x8d"  # vWii Key
]
DSI_KEY = b"\xAF\x1B\xF5\x16\xA8\x07\xD2\x1A\xEA\x45\x98\x4F\x04\x74\x28\x61"  # DSi Key

if os.path.isfile("root-key"):
    ROOT_KEY = RootKey("root-key")  # https://static.hackmii.com/root-key
else:
    ROOT_KEY = None

from .TMD import *
from .Ticket import *

