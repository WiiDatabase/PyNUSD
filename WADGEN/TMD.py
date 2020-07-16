import binascii
import struct
from binascii import hexlify
from enum import Enum
from io import BytesIO
from typing import Union, Optional, List

from WADGEN import Base, utils, Signature, Certificate, ROOT_KEY, SIGNATURETYPE, PUBLICKEYTYPE, RootKey
from WADGEN.utils import MAXVALUE


class CONTENTTYPE(Enum):
    NORMAL = 0x0001
    DLC = 0x4001
    SHARED = 0x8001


class NANDLOADER(Enum):
    TINY_VWII_NAND_LOADER_R2 = "0d946e47249b00f6ad6c0037413d645da1a59f22"
    CUSTOM_NAND_LOADER_V11_MOD = "9d19271538fbbef920a566a855cac71aa3fa4992"
    CUSTOM_NAND_LOADER_V11_MOD_IOS53 = "f6b96dbf81b34500e1f723cab7acf544a40779db"
    CUSTOM_NAND_LOADER_V11_MOD_IOS55 = "25c8b3c3ba6b1f0a27db400a5705652afdc22748"
    CUSTOM_NAND_LOADER_V11_MOD_IOS56 = "7973a2a2123e7e4d716bba4a19855691f5ff458c"


class REGION(Enum):
    JAPAN = 0
    USA = 1
    EUROPE = 2
    FREE = 3
    KOREA = 4


class TMDContent:
    def __init__(self, f: Union[bytes, BytesIO, None] = None):
        self.cid = 0
        self.index = 0
        self.type = CONTENTTYPE.NORMAL.value
        self.size = 0
        self.hash = b"\x00" * 20

        if f:
            if isinstance(f, bytes):
                self.parse_bytes(f)
            elif isinstance(f, BytesIO):
                self.parse(f)
            else:
                raise Exception("Argument must be BytesIO or bytes.")

    def parse(self, f: BytesIO):
        self.cid = struct.unpack(">L", f.read(4))[0]
        self.index = struct.unpack(">H", f.read(2))[0]
        self.type = struct.unpack(">H", f.read(2))[0]
        self.size = struct.unpack(">Q", f.read(8))[0]
        self.hash = f.read(20)

    def parse_bytes(self, byt: bytes):
        bytesio = BytesIO(byt)
        self.parse(bytesio)

    def get_cid(self) -> str:
        return "{:08X}".format(self.cid).lower()

    def get_index(self) -> int:
        return self.index

    def get_iv(self) -> bytes:
        return struct.pack(">H", self.index) + b"\x00" * 14

    def get_type(self) -> str:
        types = {
            CONTENTTYPE.NORMAL.value: "Normal",
            CONTENTTYPE.DLC.value:    "DLC",
            CONTENTTYPE.SHARED.value: "Shared"
        }
        try:
            return types[self.type]
        except KeyError:
            return "Unknown"

    def get_hash(self) -> bytes:
        return self.hash

    def get_hash_hex(self) -> str:
        return hexlify(self.hash).decode()

    def get_loader(self) -> Optional[str]:
        hashes = {
            NANDLOADER.TINY_VWII_NAND_LOADER_R2.value:         "Tiny vWii NAND Loader r2",
            NANDLOADER.CUSTOM_NAND_LOADER_V11_MOD.value:       "Custom NAND Loader v1.1 MOD",
            NANDLOADER.CUSTOM_NAND_LOADER_V11_MOD_IOS53.value: "Custom NAND Loader v1.1 MOD IOS53",
            NANDLOADER.CUSTOM_NAND_LOADER_V11_MOD_IOS55.value: "Custom NAND Loader v1.1 MOD IOS55",
            NANDLOADER.CUSTOM_NAND_LOADER_V11_MOD_IOS56.value: "Custom NAND Loader v1.1 MOD IOS56",
        }
        try:
            return hashes[self.get_hash_hex()]
        except KeyError:
            return None

    def get_size(self) -> int:
        return self.size

    def get_aligned_size(self, blocksize: int = 64) -> int:
        size = self.get_size()
        size += utils.align_pointer(size, blocksize)
        return size

    def get_pretty_size(self) -> str:
        return utils.convert_size(self.size)

    def set_type(self, cnttype: CONTENTTYPE):
        if not isinstance(cnttype, CONTENTTYPE):
            raise Exception("CONTENTTYPE expected.")

        self.type = cnttype.value

    def set_hash(self, sha1hash: Union[str, bytes]):
        if not isinstance(sha1hash, str) and not isinstance(sha1hash, bytes):
            raise Exception("String or bytes expected")

        if isinstance(sha1hash, bytes):
            if len(sha1hash) != 20:
                raise Exception("SHA1 hash must be 20 characters long.")
            self.hash = sha1hash
        else:
            if len(sha1hash) != 40:
                raise Exception("SHA1 hash must be 40 characters long.")
            self.hash = binascii.a2b_hex(sha1hash)

    def set_size(self, size: int):
        if not isinstance(size, int):
            raise Exception("Integer expected.")

        if not 0 <= size <= MAXVALUE.UINT64.value:
            raise Exception("Invalid size.")

        self.size = size

    def pack(self) -> bytes:
        pack = b""
        pack += struct.pack(">L", self.cid)
        pack += struct.pack(">H", self.index)
        pack += struct.pack(">H", self.type)
        pack += struct.pack(">Q", self.size)
        pack += self.hash
        return pack

    def __len__(self):
        return len(self.pack())

    def __repr__(self):
        return "<TMDContent(cid='{cid}', index='{index}')>".format(
                cid=self.get_cid(),
                index=self.get_index(),
        )

    def __str__(self):
        output = "Content:\n"
        output += "   ID         Index   Type     Size       Hash\n"
        output += "   {:s}   {:<7d} {:<8s} {:<11s}".format(
                self.get_cid(),
                self.index,
                self.get_type(),
                self.get_pretty_size()
        )
        output += self.get_hash_hex()
        loader = self.get_loader()
        if loader:
            output += " ({0})".format(loader)
        output += "\n"

        return output


class TMD(Base):
    def __init__(self, f: Union[str, bytes, bytearray, BytesIO, None] = None, has_certificates: bool = True):
        self.signature = Signature(sigtype=SIGNATURETYPE.RSA_2048_SHA1)
        self.issuer = b"\x00" * 64
        self.version = 0
        self.ca_crl_version = 0
        self.signer_crl_version = 0
        self.is_vwii = False
        self.titleid = 0
        self.required_title = 0
        self.type = 1
        self.group_id = 12337  # That's what the forecast channel uses
        self.zero = b"\x00" * 2
        self.region = REGION.JAPAN.value
        self.ratings = b"\x00" * 16
        self.reserved1 = b"\x00" * 12
        self.ipc_mask = b"\x00" * 12
        self.reserved2 = b"\x00" * 18
        self.access_rights = 0
        self.titleversion = 0
        self.contentnum = 0
        self.bootindex = 0
        self.unused = 0
        self.contents = []
        self.certificates = []
        if has_certificates:
            self.certificates = [Certificate(sigtype=SIGNATURETYPE.RSA_2048_SHA1, keytype=PUBLICKEYTYPE.RSA_2048),
                                 Certificate(sigtype=SIGNATURETYPE.RSA_4096_SHA1, keytype=PUBLICKEYTYPE.RSA_2048)]

        self.has_certificates = has_certificates

        super().__init__(f)

    def parse(self, f: BytesIO):
        self.signature = Signature(f)
        self.issuer = f.read(64)
        self.version = struct.unpack(">B", f.read(1))[0]
        self.ca_crl_version = struct.unpack(">B", f.read(1))[0]
        self.signer_crl_version = struct.unpack(">B", f.read(1))[0]
        self.is_vwii = struct.unpack(">?", f.read(1))[0]
        self.required_title = struct.unpack(">Q", f.read(8))[0]
        self.titleid = struct.unpack(">Q", f.read(8))[0]
        self.type = struct.unpack(">L", f.read(4))[0]
        self.group_id = struct.unpack(">H", f.read(2))[0]
        self.zero = f.read(2)
        self.region = struct.unpack(">H", f.read(2))[0]
        self.ratings = f.read(16)  # TODO: How to parse this?
        self.reserved1 = f.read(12)
        self.ipc_mask = f.read(12)
        self.reserved2 = f.read(18)
        self.access_rights = struct.unpack(">L", f.read(4))[0]
        self.titleversion = struct.unpack(">H", f.read(2))[0]
        self.contentnum = struct.unpack(">H", f.read(2))[0]
        self.bootindex = struct.unpack(">H", f.read(2))[0]
        self.unused = struct.unpack(">H", f.read(2))[0]

        self.contents = []
        for i in range(self.get_content_count()):
            self.contents.append(TMDContent(f))

        self.certificates = []
        if self.has_certificates:
            for i in range(2):
                self.certificates.append(Certificate(f))

    def get_signature(self) -> Signature:
        return self.signature

    def get_certificates(self) -> List[Union[Certificate, RootKey]]:
        return self.certificates

    def get_certificate(self, i: int) -> Union[Certificate, RootKey]:
        return self.get_certificates()[i]

    def get_issuers(self) -> List[str]:
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (CP) signs the TMD,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.issuer.rstrip(b"\00").decode().split("-")

    def get_certificate_chain(self) -> List[Union[Certificate, RootKey]]:
        """NOTE: Ignores Root Key if it doesn't exist."""
        certs = []
        for issuer in reversed(self.get_issuers()):
            try:
                certs.append(self.get_cert_by_name(issuer))
            except LookupError as le:
                if issuer == "Root":
                    continue
                raise le
        return certs

    def is_vwii_title(self) -> bool:
        return self.is_vwii

    def is_dsi_title(self) -> bool:
        return self.get_titleid().startswith("00030")

    def get_type(self) -> str:
        # https://dsibrew.org/wiki/Title_list#System_Codes
        if self.is_dsi_title():
            types = {
                "4B": "DSiWare",
                "48": "DSi System / Channel"
            }
            try:
                return types[self.get_titleid()[8:10].upper()]
            except KeyError:
                return "Unknown"
        else:
            # https://wiibrew.org/wiki/Title_metadata#Example_code_application
            types = {
                "00000001": "System",
                "00010000": "Game",
                "00010001": "Channel",
                "00010002": "System Channel",
                "00010004": "Game Channel",
                "00010005": "Downloadable Content",
                "00010008": "Hidden Channel"
            }
            try:
                return types[self.get_titleid()[:8].upper()]
            except KeyError:
                return "Unknown"

    def get_region(self) -> str:
        if self.is_dsi_title():
            # https://dsibrew.org/wiki/Title_list#Region_Codes
            regions = {
                "41": "Free",
                "43": "China",
                "45": "North America",
                "48": "Belgium / Netherlands",
                "4A": "Japan",
                "4B": "Korea",
                "50": "Europe",
                "55": "Australia and New Zealand",
                "56": "Europe"
            }
            try:
                return regions[self.get_titleid()[-2:].upper()]
            except KeyError:
                return "Unknown"
        else:
            regions = [
                "Japan",
                "USA",
                "Europe",
                "Free",
                "Korea"
            ]
            try:
                return regions[self.region]
            except IndexError:
                return "Unknown"

    def get_required_title(self) -> Optional[str]:
        if self.required_title:
            return "{:08X}".format(self.required_title).zfill(16).lower()

    def get_titleid(self) -> str:
        return "{:08X}".format(self.titleid).zfill(16).lower()

    def get_titleversion(self) -> int:
        return self.titleversion

    def get_content_count(self) -> int:
        return self.contentnum

    def get_boot_app(self) -> str:
        if self.bootindex:
            return "{:08X}".format(self.bootindex).lower()

    def get_contents(self) -> List[TMDContent]:
        return self.contents

    def get_content(self, i: int) -> TMDContent:
        return self.get_contents()[i]

    def get_encrypted_content_size(self) -> int:
        size = 0
        for content in self.get_contents():
            size += content.get_aligned_size()
        return size

    def get_decrypted_content_size(self) -> int:
        size = 0
        for content in self.get_contents():
            size += content.get_size()
        return size

    def get_content_record_position_by_cid(self, cid: str) -> int:
        """Returns Content Record position by CID."""
        cid = cid.lower()
        for i, content in enumerate(self.get_contents()):
            if content.get_cid() == cid:
                return i
        raise LookupError("CID {0} not found.".format(cid))

    def get_content_record_by_cid(self, cid: str) -> TMDContent:
        cid = cid.lower()
        for content in self.get_contents():
            if cid == content.get_cid():
                return content
        raise LookupError("CID {0} not found.".format(cid))

    def get_cert_by_name(self, name) -> Certificate:
        """Returns certificate by name."""
        for cert in self.get_certificates():
            if cert.get_name() == name:
                return cert
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise LookupError("Certificate '{0}' not found.".format(name))

    def get_signature_hash(self) -> str:
        return utils.Crypto.create_sha1hash_hex(self.pack(include_signature=False))

    def get_data_size(self) -> int:
        size = 0
        for content in self.get_contents():
            size += content.get_size()
        return size

    def get_pretty_data_size(self) -> str:
        return utils.convert_size(self.get_data_size())

    def derive_decrypted_titlekey(self, password: str) -> bytes:
        return utils.Crypto.derive_decrypted_titlekey(self.get_titleid(), password)

    def derive_decrypted_titlekey_hex(self, password: str) -> str:
        return utils.Crypto.derive_decrypted_titlekey_hex(self.get_titleid(), password)

    def set_certificate_chain(self, certchain: List[Union[Certificate, RootKey]]):
        for item in certchain:
            if not isinstance(item, Certificate) and not isinstance(item, RootKey):
                raise Exception("All items in the list must either be a Certificate or a RootKey.")
        self.certificates = certchain

    def set_titleid(self, tid: str):
        if not isinstance(tid, str):
            raise Exception("String expected.")

        if len(tid) != 16:
            raise ValueError("Title ID must be 16 characters long.")
        val = int(tid, 16)
        self.titleid = val

    def set_required_title(self, tid: str):
        if not isinstance(tid, str):
            raise Exception("String expected.")

        if len(tid) != 16:
            raise ValueError("Title ID must be 16 characters long.")
        val = int(tid, 16)
        self.required_title = val

    def set_titleversion(self, ver: int):
        if not isinstance(ver, int):
            raise Exception("Integer expected.")

        if not 0 <= ver <= MAXVALUE.UINT16.value:
            raise Exception("Invalid title version.")
        self.titleversion = ver

    def set_region(self, region: REGION):
        if self.is_dsi_title():
            raise Exception("The region of DSi titles is determined by their Title ID.")

        if not isinstance(region, REGION):
            raise Exception("REGION expected.")

        self.region = region.value

    def set_vwii(self, is_vwii: bool):
        if not isinstance(is_vwii, bool):
            raise Exception("Boolean expected.")
        self.is_vwii = is_vwii

    def set_access_rights(self, ar: int):
        if not 0 <= ar <= MAXVALUE.UINT32.value:
            raise Exception("Invalid range.")

        self.access_rights = ar

    def fakesign(self):
        """Fakesigns TMD.
           https://github.com/FIX94/Some-YAWMM-Mod/blob/e2708863036066c2cc8bad1fc142e90fb8a0464d/source/title.c#L50-L76
        """
        oldval = self.unused
        self.signature.zerofill()
        for i in range(65535):  # Max value for unsigned short integer (2 bytes)
            # Modify unused data
            self.unused = i

            # Calculate hash
            sha1hash = utils.Crypto.create_sha1hash_hex(self.pack(include_signature=False))

            # Found valid hash!
            if sha1hash.startswith("00"):
                return

        self.unused = oldval
        raise Exception("Fakesigning failed.")

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
            pack = self.get_signature().pack()
        pack += self.issuer
        pack += struct.pack(">B", self.version)
        pack += struct.pack(">B", self.ca_crl_version)
        pack += struct.pack(">B", self.signer_crl_version)
        pack += struct.pack(">?", self.is_vwii)
        pack += struct.pack(">Q", self.required_title)
        pack += struct.pack(">Q", self.titleid)
        pack += struct.pack(">L", self.type)
        pack += struct.pack(">H", self.group_id)
        pack += self.zero
        pack += struct.pack(">H", self.region)
        pack += self.ratings
        pack += self.reserved1
        pack += self.ipc_mask
        pack += self.reserved2
        pack += struct.pack(">L", self.access_rights)
        pack += struct.pack(">H", self.titleversion)
        pack += struct.pack(">H", self.contentnum)
        pack += struct.pack(">H", self.bootindex)
        pack += struct.pack(">H", self.unused)

        for content in self.get_contents():
            pack += content.pack()

        if include_certificates:
            for cert in self.certificates:
                pack += cert.pack()

        return pack

    def dump(self, output, include_signature=True, include_certificates=True) -> str:
        """Dumps the TMD to output. Replaces {titleid} and {titleversion} if in path.
           Returns the file path.
        """
        output = output.format(titleid=self.get_titleid(), titleversion=self.get_titleversion())
        pack = self.pack(include_signature=include_signature, include_certificates=include_certificates)
        with open(output, "wb") as file:
            file.write(pack)
        return output

    def __repr__(self):
        return "<TMD(titleid='{id}', titleversion='{ver}')>".format(
                id=self.get_titleid(),
                ver=self.get_titleversion(),
        )

    def __str__(self):
        output = "TMD:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Title Version: {0}\n".format(self.get_titleversion())
        output += "  Title Type: {0}\n".format(self.get_type())
        if self.get_type() != "System":
            output += "  Region: {0}\n".format(self.get_region())
        if self.get_required_title():
            output += "  Requires: {0}\n".format(self.get_required_title())
        if self.get_boot_app():
            output += "  Boot APP: {0}\n".format(self.get_boot_app())
        output += "  Total data size: {0}\n".format(self.get_pretty_data_size())

        output += "\n"

        output += "  Number of contents: {0}\n".format(self.get_content_count())
        output += "  Contents:\n"
        output += "   ID         Index   Type     Size       Hash\n"
        for content in self.get_contents():
            output += "   {:s}   {:<7d} {:<8s} {:<11s}".format(
                    content.get_cid(),
                    content.get_index(),
                    content.get_type(),
                    content.get_pretty_size()
            )
            output += content.get_hash_hex()
            loader = content.get_loader()
            if loader:
                output += " ({0})".format(loader)
            output += "\n"

        output += "\n  Certificates:\n"

        try:
            certchain = self.get_certificate_chain()
        except LookupError:
            output += "    Could not locate the needed certificates.\n"
            return output

        for num, cert in enumerate(certchain):
            output += "    Signed by {0} ({1}): ".format(cert.get_name(), cert.get_key_type())
            if num == 0:  # First is alwyas the TMD itself
                output += "[{0}] ".format(self.get_signature_hash())
                if self.is_fakesigned():
                    output += "[FAKESIGNED]"
                else:
                    if self.has_valid_signature():
                        output += "[OK]"
                    else:
                        output += "[FAIL]"
                output += "\n"
            else:
                signs_this_certificate = certchain[num - 1]
                output += "[{0}] [{1}]\n".format(signs_this_certificate.get_signature_hash(),
                                                 "OK" if signs_this_certificate.has_valid_signature(cert) else "FAIL")

        return output
