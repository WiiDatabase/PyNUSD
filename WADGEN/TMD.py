import struct
from binascii import hexlify
from io import BytesIO
from typing import Union, Optional, List

from WADGEN import Base, utils, Signature, Certificate, ROOT_KEY, SIGNATURETYPES, PUBLICKEYTYPES


class TMDContent:
    def __init__(self, f: Optional[bytes] = None):
        self.cid = 0
        self.index = 0
        self.type = 1
        self.size = 0
        self.hash = b"\x00" * 20

        if f:
            if isinstance(f, bytes):
                self.parse_bytes(f)
            else:
                raise Exception("Argument must be bytes.")

    def parse(self, f: BytesIO):
        f.seek(0)
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
        # https://github.com/dnasdw/libwiisharp/blob/master/libWiiSharp/TMD.cs#L27-L29
        types = {
            0x0001: "Normal",
            0x4001: "DLC",
            0x8001: "Shared"
        }
        try:
            return types[self.type]
        except KeyError:
            return "Unknown"

    def get_hash_hex(self) -> str:
        return hexlify(self.hash).decode()

    def get_loader(self) -> Optional[str]:
        hashes = {
            "0d946e47249b00f6ad6c0037413d645da1a59f22": "Tiny vWii NAND Loader r2",
            "9d19271538fbbef920a566a855cac71aa3fa4992": "Custom NAND Loader v1.1 MOD",
            "f6b96dbf81b34500e1f723cab7acf544a40779db": "Custom NAND Loader v1.1 MOD IOS53",
            "25c8b3c3ba6b1f0a27db400a5705652afdc22748": "Custom NAND Loader v1.1 MOD IOS55",
            "7973a2a2123e7e4d716bba4a19855691f5ff458c": "Custom NAND Loader v1.1 MOD IOS56",
        }
        try:
            return hashes[self.get_hash_hex()]
        except KeyError:
            return None

    def get_size(self) -> int:
        return self.size

    def get_aligned_size(self) -> int:
        size = self.get_size()
        size += utils.align_pointer(size)
        return size

    def get_pretty_size(self) -> str:
        return utils.convert_size(self.size)

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
    def __init__(self, f: Union[str, bytes, bytearray, None] = None):
        self.signature = Signature(sigtype=SIGNATURETYPES.RSA_2048_SHA1)
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
        self.region = 0
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
        self.certificates = [Certificate(sigtype=SIGNATURETYPES.RSA_2048_SHA1, keytype=PUBLICKEYTYPES.RSA_2048),
                             Certificate(sigtype=SIGNATURETYPES.RSA_4096_SHA1, keytype=PUBLICKEYTYPES.RSA_2048)]

        super().__init__(f)

    def parse(self, f: BytesIO):
        f.seek(0)
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
            self.contents.append(TMDContent(f.read(36)))

        self.certificates = []
        for i in range(2):
            self.certificates.append(Certificate(f))

    def get_signature(self) -> Signature:
        return self.signature

    def get_certificates(self) -> List[Certificate]:
        return self.certificates

    def get_certificate(self, i: int) -> Certificate:
        return self.get_certificates()[i]

    def get_issuers(self) -> List[str]:
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (CP) signs the TMD,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.issuer.rstrip(b"\00").decode().split("-")

    def is_vwii_title(self) -> bool:
        return self.is_vwii

    def get_type(self) -> str:
        # https://dsibrew.org/wiki/Title_list#System_Codes
        if self.get_titleid().startswith("00030"):  # DSi
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
        # TODO: set_region()
        if self.get_titleid().startswith("00030"):  # DSi
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
            # https://github.com/dnasdw/libwiisharp/blob/master/libWiiSharp/TMD.cs#L34-L37
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
        raise ValueError("CID {0} not found.".format(cid))

    def get_content_record_by_cid(self, cid: str) -> TMDContent:
        cid = cid.lower()
        for content in self.get_contents():
            if cid == content.get_cid():
                return content
        raise ValueError("CID {0} not found.".format(cid))

    def get_cert_by_name(self, name) -> Certificate:
        """Returns certificate by name."""
        for cert in self.get_certificates():
            if cert.get_name() == name:
                return cert
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

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

        if not 0 <= ver <= 65535:
            raise Exception("Invalid title version.")
        self.titleversion = ver

    def set_vwii(self, is_vwii: bool):
        if not isinstance(is_vwii, bool):
            raise Exception("Boolean expected.")
        self.is_vwii = is_vwii

    def set_access_rights(self, ar: int):
        if not 0 <= ar <= 4294967295:
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
        """Dumps TMD to output. Replaces {titleid} and {titleversion} if in path.
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

        # TODO: Certificates + signing stuff here

        return output
