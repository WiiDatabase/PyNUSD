import binascii
import struct
from enum import Enum
from io import BytesIO
from typing import Union, List

from WADGEN import Base, Signature, Certificate, ROOT_KEY, utils, SIGNATURETYPE, PUBLICKEYTYPE, MAXVALUE


class CKEYTYPE(Enum):
    NORMAL = 0
    KOREA = 1
    VWII = 2


class KEY(Enum):
    COMMON_KEY = b"\xEB\xE4\x2A\x22\x5E\x85\x93\xE4\x48\xD9\xC5\x45\x73\x81\xAA\xF7"
    KOREAN_KEY = b"\x63\xB8\x2B\xB4\xF4\x61\x4E\x2E\x13\xF2\xFE\xFB\xBA\x4C\x9B\x7E"
    VWII_KEY = b"\x30\xbf\xc7\x6e\x7c\x19\xaf\xbb\x23\x16\x33\x30\xce\xd7\xc2\x8d"
    DSI_KEY = b"\xAF\x1B\xF5\x16\xA8\x07\xD2\x1A\xEA\x45\x98\x4F\x04\x74\x28\x61"


class Ticket(Base):
    def __init__(self, f: Union[str, bytes, bytearray, BytesIO, None] = None, has_certificates: bool = True):
        self.signature = Signature(sigtype=SIGNATURETYPE.RSA_2048_SHA1)
        self.issuer = b"\x00" * 64
        self.ecdhdata = b"\x00" * 60
        self.unused1 = b"\x00" * 3
        self.titlekey = b"\x00" * 16
        self.unknown1 = b"\x00"
        self.ticketid = b"\x00" * 8
        self.consoleid = 0
        self.titleid = 0
        self.unknown2 = b"\x00" * 2
        self.titleversion = 0
        self.permitted_titles_mask = 0
        self.permit_mask = 0
        self.export_allowed = False
        self.ckeyindex = CKEYTYPE.NORMAL.value
        self.unknown3 = b"\x00" * 48
        self.content_access_permissions = b"\x00" * 64
        self.padding = 0
        self.limits = b"\x00" * 64
        self.certificates = []
        if has_certificates:
            self.certificates = [Certificate(sigtype=SIGNATURETYPE.RSA_2048_SHA1, keytype=PUBLICKEYTYPE.RSA_2048),
                                 Certificate(sigtype=SIGNATURETYPE.RSA_4096_SHA1, keytype=PUBLICKEYTYPE.RSA_2048)]

        self.has_certificates = has_certificates

        super().__init__(f)

    def parse(self, f: BytesIO):
        self.signature = Signature(f)
        self.issuer = f.read(64)
        self.ecdhdata = f.read(60)
        self.unused1 = f.read(3)
        self.titlekey = f.read(16)
        self.unknown1 = f.read(1)
        self.ticketid = f.read(8)
        self.consoleid = struct.unpack(">L", f.read(4))[0]
        self.titleid = struct.unpack(">Q", f.read(8))[0]
        self.unknown2 = f.read(2)
        self.titleversion = struct.unpack(">H", f.read(2))[0]
        self.permitted_titles_mask = struct.unpack(">L", f.read(4))[0]
        self.permit_mask = struct.unpack(">L", f.read(4))[0]
        self.export_allowed = struct.unpack(">?", f.read(1))[0]
        self.ckeyindex = struct.unpack(">B", f.read(1))[0]
        self.unknown3 = f.read(48)
        self.content_access_permissions = f.read(64)
        self.padding = struct.unpack(">H", f.read(2))[0]
        self.limits = f.read(64)

        self.certificates = []
        if self.has_certificates:
            for i in range(2):
                self.certificates.append(Certificate(f))

    def is_fakesigned(self) -> bool:
        if not self.get_signature().is_zerofilled():
            return False

        sha1hash = utils.Crypto.create_sha1hash_hex(self.pack(include_signature=False))
        if sha1hash.startswith("00"):
            return True

        return False

    def has_valid_signature(self) -> bool:
        if self.is_fakesigned():
            return False

        certificate = self.get_cert_by_name(self.get_issuers()[-1])
        return certificate.verify_signature(self.pack(include_signature=False), self.get_signature())

    def pack(self, include_signature=True, include_certificates=False) -> bytes:
        pack = b""
        if include_signature:
            pack += self.signature.pack()
        pack += self.issuer
        pack += self.ecdhdata
        pack += self.unused1
        pack += self.titlekey
        pack += self.unknown1
        pack += self.ticketid
        pack += struct.pack(">L", self.consoleid)
        pack += struct.pack(">Q", self.titleid)
        pack += self.unknown2
        pack += struct.pack(">H", self.titleversion)
        pack += struct.pack(">L", self.permitted_titles_mask)
        pack += struct.pack(">L", self.permit_mask)
        pack += struct.pack(">?", self.export_allowed)
        pack += struct.pack(">B", self.ckeyindex)
        pack += self.unknown3
        pack += self.content_access_permissions
        pack += struct.pack(">H", self.padding)
        pack += self.limits  # TODO: How to parse this?

        if include_certificates:
            for cert in self.certificates:
                pack += cert.pack()

        return pack

    def dump(self, output, include_signature=True, include_certificates=True) -> str:
        """Dumps the Ticket to output. Replaces {titleid} and {titleversion} if in path.
           Returns the file path.
        """
        output = output.format(titleid=self.get_titleid(), titleversion=self.get_titleversion())
        pack = self.pack(include_signature=include_signature, include_certificates=include_certificates)
        with open(output, "wb") as file:
            file.write(pack)
        return output

    def get_signature(self) -> Signature:
        return self.signature

    def get_certificates(self) -> List[Certificate]:
        return self.certificates

    def get_certificate(self, i: int) -> Certificate:
        return self.get_certificates()[i]

    def get_issuers(self) -> List[str]:
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (XS) signs the Ticket,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.issuer.rstrip(b"\00").decode().split("-")

    def get_titleid(self) -> str:
        return "{:08X}".format(self.titleid).zfill(16).lower()

    def get_titleversion(self) -> int:
        return self.titleversion

    def get_iv(self) -> bytes:
        return struct.pack(">Q", self.titleid) + b"\x00" * 8

    def get_iv_hex(self) -> str:
        return binascii.hexlify(self.get_iv()).decode()

    def get_consoleid(self) -> int:
        return self.consoleid

    def get_cert_by_name(self, name) -> Certificate:
        """Returns certificate by name."""
        for cert in self.get_certificates():
            if cert.get_name() == name:
                return cert
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise LookupError("Certificate '{0}' not found.".format(name))

    def get_decryption_key(self) -> bytes:
        # TODO: Debug (RVT) Tickets
        """Returns the appropiate Common Key"""
        if self.get_titleid().startswith("00030"):
            return KEY.DSI_KEY.value

        ckeyindex = self.get_common_key_index()
        if ckeyindex == 0:
            return KEY.COMMON_KEY.value
        elif ckeyindex == 1:
            return KEY.KOREAN_KEY.value
        elif ckeyindex == 2:
            return KEY.VWII_KEY.value
        else:
            print("WARNING: Unknown Common Key, assuming normal key.")
            return KEY.COMMON_KEY.value

    def get_common_key_index(self) -> int:
        return self.ckeyindex

    def get_common_key_type(self) -> str:
        if self.get_titleid().startswith("00030"):
            return "DSi"
        key_types = [
            "Normal",
            "Korean",
            "Wii U Wii Mode"
        ]
        try:
            return key_types[self.ckeyindex]
        except IndexError:
            return "Unknown"

    def get_encrypted_titlekey(self) -> bytes:
        return self.titlekey

    def get_encrypted_titlekey_hex(self) -> str:
        return binascii.hexlify(self.titlekey).decode()

    def get_decrypted_titlekey(self) -> bytes:
        return utils.Crypto.decrypt_titlekey(
                commonkey=self.get_decryption_key(),
                iv=self.get_iv(),
                titlekey=self.get_encrypted_titlekey()
        )

    def get_decrypted_titlekey_hex(self) -> str:
        return binascii.hexlify(self.get_decrypted_titlekey()).decode()

    def get_signature_hash(self) -> str:
        return utils.Crypto.create_sha1hash_hex(self.pack(include_signature=False))

    def set_titleid(self, tid: str):
        if not isinstance(tid, str):
            raise Exception("String expected.")

        if len(tid) != 16:
            raise ValueError("Title ID must be 16 characters long.")
        val = int(tid, 16)
        self.titleid = val

    def set_titleversion(self, ver: int):
        if not isinstance(ver, int):
            raise Exception("Integer expected.")

        if not 0 <= ver <= MAXVALUE.UINT16.value:
            raise Exception("Invalid title version.")
        self.titleversion = ver

    def set_common_key_index(self, ckeytype: CKEYTYPE):
        if not isinstance(ckeytype, CKEYTYPE):
            raise Exception("CKEYTYPE expected.")

        if not 0 <= ckeytype.value <= 2:
            raise Exception("Invalid Common-Key index!")
        self.ckeyindex = ckeytype.value

    def set_titlekey(self, key: str, encrypted: bool = True):
        """encrypted = False will encrypt the titlekey beforehand."""
        if not isinstance(key, str):
            raise Exception("String expected.")

        if len(key) != 32:
            raise Exception("Key must be 32 characters long.")

        if not encrypted:
            key = utils.Crypto.encrypt_titlekey(
                    self.get_decryption_key(),
                    self.get_iv(),
                    binascii.a2b_hex(key)
            )
        self.titlekey = binascii.a2b_hex(key)

    def fakesign(self):
        """Fakesigns Ticket.
           https://github.com/FIX94/Some-YAWMM-Mod/blob/e2708863036066c2cc8bad1fc142e90fb8a0464d/source/title.c#L22-L48
        """
        oldval = self.padding
        self.signature.zerofill()
        for i in range(65535):  # Max value for unsigned short integer (2 bytes)
            # Modify unused data
            self.padding = i

            # Calculate hash
            sha1hash = utils.Crypto.create_sha1hash_hex(self.pack(include_signature=False))

            # Found valid hash!
            if sha1hash.startswith("00"):
                return

        self.padding = oldval
        raise Exception("Fakesigning failed.")

    def __repr__(self):
        return "<Ticket(titleid='{id}', titleversion='{ver}', commonkey='{ckey}')>".format(
                id=self.get_titleid(),
                ver=self.get_titleversion(),
                ckey=self.get_common_key_type()
        )

    def __str__(self):
        output = "Ticket:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Ticket Title Version: {0}\n".format(self.get_titleversion())
        if self.get_consoleid():
            output += "  Console ID: {0}\n".format(self.get_consoleid())
        output += "\n"
        output += "  Common Key: {0}\n".format(self.get_common_key_type())
        output += "  Initialization vector: {0}\n".format(self.get_iv_hex())
        output += "  Title key (encrypted): {0}\n".format(self.get_encrypted_titlekey_hex())
        output += "  Title key (decrypted): {0}\n".format(self.get_decrypted_titlekey_hex())

        # TODO: Certificates + signing stuff here

        return output
