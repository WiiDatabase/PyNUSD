"""Import order is important!"""
import os

from .Base import *
from .Signature import *
from .Certificate import *

if os.path.isfile("root-key"):
    ROOT_KEY = RootKey("root-key")  # https://static.hackmii.com/root-key
else:
    ROOT_KEY = None

from .TMD import *
from .Ticket import *
