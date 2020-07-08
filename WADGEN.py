#!/usr/bin/env python3
import binascii
import os
import struct

from Crypto.PublicKey.RSA import construct
from Crypto.Signature import PKCS1_v1_5
from requests import get, HTTPError

import utils
from Struct import Struct
from utils import CachedProperty

DECRYPTION_KEYS = [
    b"\xEB\xE4\x2A\x22\x5E\x85\x93\xE4\x48\xD9\xC5\x45\x73\x81\xAA\xF7",  # Common Key
    b"\x63\xB8\x2B\xB4\xF4\x61\x4E\x2E\x13\xF2\xFE\xFB\xBA\x4C\x9B\x7E",  # Korean Key
    b"\x30\xbf\xc7\x6e\x7c\x19\xaf\xbb\x23\x16\x33\x30\xce\xd7\xc2\x8d"  # vWii Key
]
DSI_KEY = b"\xAF\x1B\xF5\x16\xA8\x07\xD2\x1A\xEA\x45\x98\x4F\x04\x74\x28\x61"  # DSi Key


class Signature:
    """Represents the Signature
       Reference: https://www.3dbrew.org/wiki/Title_metadata#Signature_Data
    """

    class SignatureRSA2048(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.type = Struct.uint32
            self.data = Struct.string(0x100)
            self.padding = Struct.string(0x3C)

    class SignatureRSA4096(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.type = Struct.uint32
            self.data = Struct.string(0x200)
            self.padding = Struct.string(0x3C)

    class SignatureECC(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.type = Struct.uint32
            self.data = Struct.string(0x3C)
            self.padding = Struct.string(0x40)

    def __init__(self, filebytes):
        signature_type = filebytes[:4]
        self.signature_length = utils.get_sig_size(signature_type)
        if self.signature_length == 0x200 + 0x3C:
            self.signature = self.SignatureRSA4096()
        elif self.signature_length == 0x100 + 0x3C:
            self.signature = self.SignatureRSA2048()
        elif self.signature_length == 0x3C + 0x40:
            self.signature = self.SignatureECC()
        else:
            raise Exception("Unknown signature type {0}".format(signature_type))  # Should never happen
        self.signature = self.signature.unpack(filebytes[:0x04 + self.signature_length])

    def __len__(self):
        return 0x04 + self.signature_length

    def __repr__(self):
        return "{0} Signature Data".format(self.get_signature_type())

    def pack(self):
        return self.signature.pack()

    def get_signature_type(self):
        if self.signature_length == 0x200 + 0x3C:
            return "RSA-4096 SHA1"
        elif self.signature_length == 0x100 + 0x3C:
            return "RSA-2048 SHA1"
        elif self.signature_length == 0x3C + 0x40:
            return "ECC"
        else:
            return "Unknown"


class Certificate:
    """Represents a Certificate
       Reference: https://www.3dbrew.org/wiki/Certificates
    """

    class CertificateStruct(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.issuer = Struct.string(0x40)
            self.key_type = Struct.uint32
            self.name = Struct.string(0x40)
            self.unknown = Struct.uint32

    class PubKeyRSA4096(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.modulus = Struct.string(0x200)
            self.exponent = Struct.uint32
            self.padding = Struct.string(0x34)

    class PubKeyRSA2048(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.modulus = Struct.string(0x100)
            self.exponent = Struct.uint32
            self.padding = Struct.string(0x34)

    class PubKeyECC(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.key = Struct.string(0x3C)
            self.padding = Struct.string(0x3C)

    def __init__(self, filebytes):
        self.signature = Signature(filebytes)
        self.certificate = self.CertificateStruct().unpack(
            filebytes[len(self.signature):
                      len(self.signature) + len(self.CertificateStruct())]
        )
        pubkey_length = utils.get_key_length(self.certificate.key_type)
        if pubkey_length == 0x200 + 0x4 + 0x34:
            self.pubkey_struct = self.PubKeyRSA4096()
        elif pubkey_length == 0x100 + 0x4 + 0x34:
            self.pubkey_struct = self.PubKeyRSA2048()
        elif pubkey_length == 0x3C + 0x3C:
            self.pubkey_struct = self.PubKeyECC()
        else:
            raise Exception("Unknown Public Key type")  # Should never happen
        self.pubkey_struct = self.pubkey_struct.unpack(
            filebytes[len(self.signature) + len(self.certificate):
                      len(self.signature) + len(self.certificate) + pubkey_length]
        )
        if pubkey_length != 0x3C + 0x3C:
            self.pubkey = construct(
                (int.from_bytes(self.pubkey_struct.modulus, byteorder="big"), self.pubkey_struct.exponent)
            )
            self.signer = PKCS1_v1_5.new(self.pubkey)
        else:
            self.pubkey = None
            self.signer = None

    def __len__(self):
        return len(self.signature) + len(self.certificate) + len(self.pubkey_struct)

    def __repr__(self):
        return "{0} issued by {1}".format(self.get_name(), self.get_issuer())

    def __str__(self):
        output = "Certificate:\n"
        output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())
        output += "  Signed by {0} using {1}".format(self.get_issuer(), self.signature.get_signature_type())

        return output

    def pack(self):
        return self.signature.pack() + self.signature_pack()

    def signature_pack(self):
        return self.certificate.pack() + self.pubkey_struct.pack()

    def get_issuer(self):
        return self.certificate.issuer.rstrip(b"\00").decode().split("-")[-1]

    def get_name(self):
        return self.certificate.name.rstrip(b"\00").decode()

    def get_key_type(self):
        # https://www.3dbrew.org/wiki/Certificates#Public_Key
        key_types = [
            "RSA-4096",
            "RSA-2048",
            "Elliptic Curve"
        ]
        try:
            return key_types[self.certificate.key_type]
        except IndexError:
            return "Invalid key type"


class RootCertificate:
    """Represents the Root Certificate
       Reference: https://www.3dbrew.org/wiki/Certificates
    """

    class PubKeyRSA4096(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.modulus = Struct.string(0x200)
            self.exponent = Struct.uint32

    def __init__(self, file):
        if isinstance(file, str):  # Load file
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')
        self.pubkey_struct = self.PubKeyRSA4096().unpack(file)
        self.pubkey = construct(
            (int.from_bytes(self.pubkey_struct.modulus, byteorder="big"), self.pubkey_struct.exponent)
        )
        self.signer = PKCS1_v1_5.new(self.pubkey)

    def __len__(self):
        return len(self.pubkey_struct)

    def __repr__(self):
        return "Wii Root Certificate"

    def __str__(self):
        output = "Certificate:\n"
        output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())

        return output

    def pack(self):
        return self.pubkey_struct.pack()

    @staticmethod
    def get_name():
        return "Root"

    @staticmethod
    def get_key_type():
        return "RSA-4096"


if os.path.isfile("root-key"):
    ROOT_KEY = RootCertificate("root-key")  # https://static.hackmii.com/root-key
else:
    ROOT_KEY = None


class TMD:
    """Represents the Title Metadata
       Reference: https://wiibrew.org/wiki/Title_metadata

    Args:
        file (Union[str, bytes]): Path to TMD or a TMD bytes-object
    """

    class TMDHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.issuer = Struct.string(64)
            self.version = Struct.uint8
            self.ca_crl_version = Struct.uint8
            self.signer_crl_version = Struct.uint8
            self.padding1 = Struct.uint8
            self.system_version = Struct.uint64
            self.titleid = Struct.uint64
            self.type = Struct.uint32
            self.group_id = Struct.uint16
            self.zero = Struct.uint16
            self.region = Struct.uint16
            self.ratings = Struct.string(16)
            self.reserved2 = Struct.string(12)
            self.ipc_mask = Struct.string(12)
            self.reserved3 = Struct.string(18)
            self.access_rights = Struct.uint32
            self.titleversion = Struct.uint16
            self.contentcount = Struct.uint16
            self.bootindex = Struct.uint16
            self.padding2 = Struct.uint16

    class TMDContents(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.cid = Struct.uint32
            self.index = Struct.uint16
            self.type = Struct.uint16
            self.size = Struct.uint64
            self.sha1 = Struct.string(20)

        def get_cid(self):
            return ("%08X" % self.cid).lower()

        def get_iv(self):
            return struct.pack(">H", self.index) + b"\x00" * 14

        def get_type(self):
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

        def get_sha1_hex(self):
            return binascii.hexlify(self.sha1).decode()

        def get_hash_type(self):
            hashes = {
                "0d946e47249b00f6ad6c0037413d645da1a59f22": "Tiny vWii NAND Loader r2",
                "9d19271538fbbef920a566a855cac71aa3fa4992": "Custom NAND Loader v1.1 MOD",
                "f6b96dbf81b34500e1f723cab7acf544a40779db": "Custom NAND Loader v1.1 MOD IOS53",
                "25c8b3c3ba6b1f0a27db400a5705652afdc22748": "Custom NAND Loader v1.1 MOD IOS55",
                "7973a2a2123e7e4d716bba4a19855691f5ff458c": "Custom NAND Loader v1.1 MOD IOS56",
            }
            try:
                return hashes[self.get_sha1_hex()]
            except KeyError:
                return None

        def __repr__(self):
            output = "Content {0}".format(self.get_cid())
            return output

        def __str__(self):
            output = "Content:\n"
            output += "   ID         Index   Type     Size       Hash\n"
            output += "   {:s}   {:<7d} {:<8s} {:<11s}".format(
                self.get_cid(),
                self.index,
                self.get_type(),
                utils.convert_size(self.size)
            )
            output += self.get_sha1_hex()
            if self.get_hash_type():
                output += " ({0})".format(self.get_hash_type())
            output += "\n"

            return output

    def __init__(self, file):
        if isinstance(file, str):  # Load file
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')

        # Signature
        self.signature = Signature(file)
        pos = len(self.signature)

        # Header
        self.hdr = self.TMDHeader().unpack(file[pos:pos + len(self.TMDHeader())])
        pos += len(self.hdr)

        # Content Records
        self.contents = []
        for i in range(self.hdr.contentcount):
            self.contents.append(self.TMDContents().unpack(file[pos:pos + len(self.TMDContents())]))
            pos += len(self.TMDContents())

        # Certificates
        self.certificates = []
        if file[pos:]:
            self.certificates.append(Certificate(file[pos:]))
            pos += len(self.certificates[0])
            self.certificates.append(Certificate(file[pos:]))
        if self.certificates:
            if len(self.certificates) != 2:
                raise Exception("Could not locate all Certs!")

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_required_title(self):
        return "{:08X}".format(self.hdr.system_version).zfill(16).lower()

    def get_boot_index(self):
        return ("%08X" % self.hdr.bootindex).lower()

    def get_issuer(self):
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (CP) signs the TMD,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.hdr.issuer.rstrip(b"\00").decode().split("-")

    def get_content_size(self):
        size = 0
        for content in self.contents:
            size += content.size
            size += utils.align_pointer(content.size)
        return size

    def get_type(self):
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

    def get_region(self):
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
                return regions[self.hdr.region]
            except IndexError:
                return "Unknown"

    def get_cr_index_by_cid(self, cid):
        """Returns Content Record index by CID."""
        for i, content in enumerate(self.contents):
            if content.get_cid() == cid:
                return i
        raise ValueError("CID {0} not found.".format(cid))

    def get_cr_by_cid(self, cid):
        """Returns Content Record by CID."""
        return self.contents[self.get_cr_index_by_cid(cid)]

    def get_cert_by_name(self, name):
        """Returns certificate by name."""
        for i, cert in enumerate(self.certificates):
            if cert.get_name() == name:
                return i
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

    def fakesign(self):
        """Fakesigns TMD.
           https://github.com/FIX94/Some-YAWMM-Mod/blob/e2708863036066c2cc8bad1fc142e90fb8a0464d/source/title.c#L50-L76
        """
        # Fill signature with zeroes
        sigsize = len(self.signature.signature.data)
        self.signature.signature.data = b"\x00" * sigsize

        # Modify content until SHA1 hash starts with 00
        for i in range(65535):  # Max value for unsigned short integer (2 bytes)
            # Modify tmd padding2
            self.hdr.padding2 = i

            # Calculate hash
            sha1hash = utils.Crypto.create_sha1hash_hex(self.signature_pack())

            # Found valid hash!
            if sha1hash.startswith("00"):
                return

        raise Exception("Fakesigning failed.")

    def pack(self):
        """Returns TMD WITHOUT certificates."""
        return self.signature.pack() + self.signature_pack()

    def signature_pack(self):
        """Returns TMD only with body (the part that is signed)."""
        pack = self.hdr.pack()
        for content in self.contents:
            pack += content.pack()
        return pack

    def dump(self, output=None):
        """Dumps TMD to output WITH Certificates. Replaces {titleid} and {titleversion} if in filename.
           Returns raw binary if no output is given, returns the file path else.
        """
        if output:
            output = output.format(titleid=self.get_titleid(), titleversion=self.hdr.titleversion)
        pack = self.pack()
        for cert in self.certificates:
            pack += cert.pack()
        if output:
            with open(output, "wb") as tmd_file:
                tmd_file.write(pack)
                return output
        else:
            return pack

    def __len__(self):
        """Returns length of TMD WITHOUT certificates."""
        size = 0
        for content in self.contents:
            size += len(content)
        return size + len(self.signature) + len(self.hdr)

    def __repr__(self):
        return 'Title {id} v{ver}'.format(
            id=self.get_titleid(),
            ver=self.hdr.titleversion,
        )

    def __str__(self):
        output = "TMD:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Title Version: {0}\n".format(self.hdr.titleversion)
        output += "  Title Type: {0}\n".format(self.get_type())
        if self.get_type() != "System":
            output += "  Region: {0}\n".format(self.get_region())
        if self.hdr.system_version:
            output += "  Requires: {0}\n".format(self.get_required_title())
        if self.hdr.bootindex:
            output += "  Boot APP: {0}\n".format(self.get_boot_index())
        output += "\n"

        output += "  Number of contents: {0}\n".format(self.hdr.contentcount)
        output += "  Contents:\n"
        output += "   ID         Index   Type     Size       Hash\n"
        for content in self.contents:
            output += "   {:s}   {:<7d} {:<8s} {:<11s}".format(
                content.get_cid(),
                content.index,
                content.get_type(),
                utils.convert_size(content.size)
            )
            output += content.get_sha1_hex()
            if content.get_hash_type():
                output += " ({0})".format(content.get_hash_type())
            output += "\n"

        # TODO: Improve this, is a bit complicated to understand and duplicated
        if self.certificates:
            output += "\n"
            output += "  Certificates:\n"
            try:
                signs_tmd = self.get_cert_by_name(self.get_issuer()[-1])  # CP
                signs_cp = self.get_cert_by_name(self.get_issuer()[1])  # CA
            except ValueError:
                output += "   Could not locate the needed certificates.\n"
                return output
            try:
                signs_ca = self.get_cert_by_name(self.get_issuer()[0])  # Root
            except ValueError:
                signs_ca = None

            # Check TMD signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_tmd],
                self.signature_pack(),
                self.signature
            )
            sha1hash = utils.Crypto.create_sha1hash_hex(self.signature_pack())
            output += "    TMD signed by {0} using {1}: {2} ".format(
                "-".join(self.get_issuer()),
                self.certificates[signs_tmd].get_key_type(),
                sha1hash
            )
            if verified:
                output += "[OK]"
            else:
                if sha1hash.startswith("00") and int.from_bytes(self.signature.signature.data, byteorder="big") == 0:
                    output += "[FAKESIGNED]"
                else:
                    output += "[FAIL]"
            output += "\n"

            # Check CP signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_cp],
                self.certificates[signs_tmd].signature_pack(),
                self.certificates[signs_tmd].signature
            )
            sha1hash = utils.Crypto.create_sha1hash_hex(self.certificates[signs_tmd].signature_pack())
            output += "    {0} ({1}) signed by {2} ({3}): {4} ".format(
                self.certificates[signs_tmd].get_name(),
                self.certificates[signs_tmd].get_key_type(),
                self.certificates[signs_tmd].get_issuer(),
                self.certificates[signs_cp].get_key_type(),
                sha1hash
            )
            if verified:
                output += "[OK]"
            else:
                output += "[FAIL]"
            output += "\n"

            # Check Root signature
            if signs_ca:
                verified = utils.Crypto.verify_signature(
                    signs_ca,
                    self.certificates[signs_cp].signature_pack(),
                    self.certificates[signs_cp].signature
                )
                sha1hash = utils.Crypto.create_sha1hash_hex(self.certificates[signs_cp].signature_pack())
                output += "    {0} ({1}) signed by {2} ({3}): {4} ".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer(),
                    ROOT_KEY.get_key_type(),
                    sha1hash
                )
                if verified:
                    output += "[OK]"
                else:
                    output += "[FAIL]"
            else:
                output += "    {0} ({1}) signed by {2}: Please place root-key in the same directory".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer()
                )
            output += "\n"

        return output


class Ticket:
    """Represents the Ticket
       Reference: https://wiibrew.org/wiki/Ticket

    Args:
        file (Union[str, bytes]): Path to Ticket or a Ticket bytes-object
    """

    class TicketHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.issuer = Struct.string(0x40)
            self.ecdhdata = Struct.string(0x3C)
            self.unused1 = Struct.string(0x03)
            self.titlekey = Struct.string(0x10)
            self.unknown1 = Struct.uint8
            self.ticketid = Struct.uint64
            self.consoleid = Struct.uint32
            self.titleid = Struct.uint64
            self.unknown2 = Struct.uint16
            self.titleversion = Struct.uint16
            self.permitted_titles_mask = Struct.uint32
            self.permit_mask = Struct.uint32
            self.export_allowed = Struct.uint8
            self.ckeyindex = Struct.uint8
            self.unknown3 = Struct.string(0x30)
            self.content_access_permissions = Struct.string(0x40)
            self.padding = Struct.uint16
            self.limits = Struct.string(0x40)

    def __init__(self, file):
        if isinstance(file, str):
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')

        # Signature
        self.signature = Signature(file)
        pos = len(self.signature)

        # Header
        self.hdr = self.TicketHeader().unpack(file[pos:pos + 0x210])
        pos += len(self.hdr)
        self.titleiv = struct.pack(">Q", self.hdr.titleid) + b"\x00" * 8

        # Certificates
        self.certificates = []
        if file[pos:]:
            self.certificates.append(Certificate(file[pos:]))
            pos += len(self.certificates[0])
            self.certificates.append(Certificate(file[pos:]))
        if self.certificates:
            if len(self.certificates) != 2:
                raise Exception("Could not locate all Certs!")

        # Decrypt title key
        self.decrypted_titlekey = utils.Crypto.decrypt_titlekey(
            commonkey=self.get_decryption_key(),
            iv=self.titleiv,
            titlekey=self.hdr.titlekey
        )

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_issuer(self):
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (XS) signs the Ticket,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.hdr.issuer.rstrip(b"\00").decode().split("-")

    def get_decryption_key(self):
        # TODO: Debug (RVT) Tickets
        """Returns the appropiate Common Key"""
        if self.get_titleid().startswith("00030"):
            return DSI_KEY
        try:
            return DECRYPTION_KEYS[self.hdr.ckeyindex]
        except IndexError:
            print("WARNING: Unknown Common Key, assuming normal key")
            return DECRYPTION_KEYS[0]

    def get_common_key_type(self):
        if self.get_titleid().startswith("00030"):
            return "DSi"
        key_types = [
            "Normal",
            "Korean",
            "Wii U Wii Mode"
        ]
        try:
            return key_types[self.hdr.ckeyindex]
        except IndexError:
            return "Unknown"

    def get_cert_by_name(self, name):
        """Returns certificate by name."""
        for i, cert in enumerate(self.certificates):
            if cert.get_name() == name:
                return i
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

    def fakesign(self):
        """Fakesigns ticket.
           https://github.com/FIX94/Some-YAWMM-Mod/blob/e2708863036066c2cc8bad1fc142e90fb8a0464d/source/title.c#L22-L48
        """
        # Fill signature with zeroes
        sigsize = len(self.signature.signature.data)
        self.signature.signature.data = b"\x00" * sigsize

        # Modify content until SHA1 hash starts with 00
        for i in range(65535):  # Max value for unsigned short integer (2 bytes)
            # Modify ticket padding
            self.hdr.padding = i

            # Calculate hash
            sha1hash = utils.Crypto.create_sha1hash_hex(self.signature_pack())

            # Found valid hash!
            if sha1hash.startswith("00"):
                return

        raise Exception("Fakesigning failed.")

    def pack(self):
        """Returns ticket WITHOUT certificates"""
        return self.signature.pack() + self.hdr.pack()

    def signature_pack(self):
        """Returns Ticket only with body (the part that is signed)."""
        return self.hdr.pack()

    def dump(self, output=None):
        """Dumps ticket to output WITH Certificates. Replaces {titleid} and {titleversion} if in filename.
           NOTE that the titleversion in the ticket is often wrong!
           Returns raw binary if no output is given, returns the file path else.
        """
        if output:
            output = output.format(titleid=self.get_titleid(), titleversion=self.hdr.titleversion)
        pack = self.pack()
        for cert in self.certificates:
            pack += cert.pack()
        if output:
            with open(output, "wb") as cetk_file:
                cetk_file.write(pack)
                return output
        else:
            return pack

    def __len__(self):
        """Returns length of ticket WITHOUT certificates"""
        return len(self.signature) + len(self.hdr)

    def __repr__(self):
        return 'Ticket for title {id} v{ver}'.format(id=self.get_titleid(), ver=self.hdr.titleversion)

    def __str__(self):
        output = "Ticket:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Ticket Title Version: {0}\n".format(self.hdr.titleversion)
        if self.hdr.consoleid:
            output += "  Console ID: {0}\n".format(self.hdr.consoleid)
        output += "\n"
        output += "  Common Key: {0}\n".format(self.get_common_key_type())
        output += "  Initialization vector: {0}\n".format(binascii.hexlify(self.titleiv).decode())
        output += "  Title key (encrypted): {0}\n".format(binascii.hexlify(self.hdr.titlekey).decode())
        output += "  Title key (decrypted): {0}\n".format(binascii.hexlify(self.decrypted_titlekey).decode())

        # TODO: Improve this, is a bit complicated to understand and duplicated
        if self.certificates:
            output += "\n"
            output += "  Certificates:\n"
            try:
                signs_ticket = self.get_cert_by_name(self.get_issuer()[-1])  # XS
                signs_cp = self.get_cert_by_name(self.get_issuer()[1])  # CA
            except ValueError:
                output += "   Could not locate the needed certificates.\n"
                return output
            try:
                signs_ca = self.get_cert_by_name(self.get_issuer()[0])  # Root
            except ValueError:
                signs_ca = None

            # Check Ticket signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_ticket],
                self.signature_pack(),
                self.signature
            )
            sha1hash = utils.Crypto.create_sha1hash_hex(self.signature_pack())
            output += "    Ticket signed by {0} using {1}: {2} ".format(
                "-".join(self.get_issuer()),
                self.certificates[signs_ticket].get_key_type(),
                sha1hash
            )
            if verified:
                output += "[OK]"
            else:
                if sha1hash.startswith("00") and int.from_bytes(self.signature.signature.data, byteorder="big") == 0:
                    output += "[FAKESIGNED]"
                else:
                    output += "[FAIL]"
            output += "\n"

            # Check XS signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_cp],
                self.certificates[signs_ticket].signature_pack(),
                self.certificates[signs_ticket].signature
            )
            sha1hash = utils.Crypto.create_sha1hash_hex(self.certificates[signs_ticket].signature_pack())
            output += "    {0} ({1}) signed by {2} ({3}): {4} ".format(
                self.certificates[signs_ticket].get_name(),
                self.certificates[signs_ticket].get_key_type(),
                self.certificates[signs_ticket].get_issuer(),
                self.certificates[signs_cp].get_key_type(),
                sha1hash
            )
            if verified:
                output += "[OK]"
            else:
                output += "[FAIL]"
            output += "\n"

            # Check Root signature
            if signs_ca:
                verified = utils.Crypto.verify_signature(
                    signs_ca,
                    self.certificates[signs_cp].signature_pack(),
                    self.certificates[signs_cp].signature
                )
                sha1hash = utils.Crypto.create_sha1hash_hex(self.certificates[signs_cp].signature_pack())
                output += "    {0} ({1}) signed by {2} ({3}): {4} ".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer(),
                    ROOT_KEY.get_key_type(),
                    sha1hash
                )
                if verified:
                    output += "[OK]"
                else:
                    output += "[FAIL]"
            else:
                output += "    {0} ({1}) signed by {2}: Please place root-key in the same directory".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer()
                )
            output += "\n"

        return output


class WAD:
    """Represents a WAD file.
       Reference: https://wiibrew.org/wiki/WAD_files

    Args:
        file (Union[str, bytes]): Path to WAD or a WAD bytes-object
    """

    class WADHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.hdrsize = Struct.uint32
            self.type = Struct.string(0x04)
            self.certchainsize = Struct.uint32
            self.reserved = Struct.uint32
            self.ticketsize = Struct.uint32
            self.tmdsize = Struct.uint32
            self.datasize = Struct.uint32
            self.footersize = Struct.uint32

    def __init__(self, file):
        if isinstance(file, str):
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')

        # Header
        self.hdr = self.WADHeader().unpack(file[:len(self.WADHeader())])
        pos = self.hdr.hdrsize

        # Certificates (always 3)
        # Order is: CA + CP + XS
        # TODO: Check vailidity of certs (+ dev certs)
        pos += utils.align_pointer(pos)
        self.certificates = []
        for i in range(3):
            self.certificates.append(Certificate(file[pos:]))
            pos += len(self.certificates[i])

        # Ticket
        pos += utils.align_pointer(pos)
        self.ticket = Ticket(file[pos:pos + self.hdr.ticketsize])
        self.ticket.certificates.append(self.certificates[2])  # XS
        self.ticket.certificates.append(self.certificates[0])  # CA
        pos += self.hdr.ticketsize

        # TMD
        pos += utils.align_pointer(pos)
        self.tmd = TMD(file[pos:pos + self.hdr.tmdsize])
        self.tmd.certificates.append(self.certificates[1])  # CP
        self.tmd.certificates.append(self.certificates[0])  # CA
        pos += self.hdr.tmdsize

        # Contents
        pos += utils.align_pointer(pos)
        self.contents = []
        for content in self.tmd.contents:
            content_size = content.size
            content_size += utils.align_pointer(content_size, 16)
            self.contents.append(file[pos:pos + content_size])
            pos += content_size
            pos += utils.align_pointer(pos)

        # Footer, if present
        pos += utils.align_pointer(pos)
        if file[pos:]:
            self.footer = file[pos:]
            self.footer = self.footer[:self.hdr.footersize]
        else:
            self.footer = None

    def pack(self):
        """Returns WAD file in binary."""
        # Header
        wad = self.hdr.pack()
        wad += utils.align(len(self.hdr))

        # Certificate Chain
        wad += b"".join([x.pack() for x in self.certificates])
        wad += utils.align(self.hdr.certchainsize)

        # Ticket
        wad += self.ticket.pack()
        wad += utils.align(self.hdr.ticketsize)

        # TMD
        wad += self.tmd.pack()
        wad += utils.align(self.hdr.tmdsize)

        # Contents
        for content in self.contents:
            wad += content
            wad += utils.align(len(content))

        # Footer
        if self.footer:
            wad += self.footer
            wad += utils.align(self.hdr.footersize)
        return wad

    def dump(self, output=None):
        """Dumps WAD to output. Replaces {titleid} and {titleversion} if in filename.
           Returns raw binary if no output is given, returns the file path else.
        """
        if output:
            output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)

        pack = self.pack()

        if output:
            with open(output, "wb") as wad_file:
                wad_file.write(pack)
                return output
        else:
            return pack

    def unpack_file(self, cid, output=None, decrypt=False):
        """"Extracts file from WAD to output directory. Replaces {titleid} and {titleversion} if in folder name.
            Extracts to "extracted_wads/TITLEID/TITLEVER" if no output is given. Pass decrypt=True to decrypt.
        """
        cid = cid.lower()
        num = self.tmd.get_cr_index_by_cid(cid)
        tmdcontent = self.tmd.contents[num]
        content = self.contents[num]

        if output:
            output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)
        else:
            output = os.path.join("extracted_wads", self.tmd.get_titleid(), str(self.tmd.hdr.titleversion))
        if not os.path.isdir(output):
            os.makedirs(output)

        filename = self.tmd.contents[num].get_cid()
        with open(os.path.join(output, filename), "wb") as content_file:
            if decrypt:  # Decrypted Contents
                valid, decdata = utils.Crypto.check_content_hash(tmdcontent, self.ticket, content,
                                                                 return_decdata=True)
                if not valid:
                    print("WARNING: SHA1 Sum mismatch")
                with open(os.path.join(output, filename + ".app"), "wb") as decrypted_content_file:
                    decrypted_content_file.write(decdata)
            content_file.write(content)

    extract_file = unpack_file

    def unpack(self, output=None, decrypt=False):
        """Extracts WAD to output. Replaces {titleid} and {titleversion} if in folder name.
           Extracts to "extracted_wads/TITLEID/TITLEVER" if no output is given. Pass decrypt=True to decrypt contents.
       """
        if output:
            output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)
        else:
            output = os.path.join("extracted_wads", self.tmd.get_titleid(), str(self.tmd.hdr.titleversion))
        if not os.path.isdir(output):
            os.makedirs(output)
        # TMD + Ticket
        self.tmd.dump(os.path.join(output, "tmd"))
        self.ticket.dump(os.path.join(output, "cetk"))

        # Encrypted Contents
        for num, content in enumerate(self.contents):
            filename = self.tmd.contents[num].get_cid()
            with open(os.path.join(output, filename), "wb") as content_file:
                if decrypt:  # Decrypted Contents
                    valid, decdata = utils.Crypto.check_content_hash(self.tmd.contents[num], self.ticket, content,
                                                                     return_decdata=True)
                    if not valid:
                        print("WARNING: SHA1 Sum mismatch for file {0}".format(filename + ".app"))
                    with open(os.path.join(output, filename + ".app"), "wb") as decrypted_content_file:
                        decrypted_content_file.write(decdata)
                content_file.write(content)

        # Footer
        if self.footer:
            with open(os.path.join(output, "footer"), "wb") as footer_file:
                footer_file.write(self.footer)

    extract = unpack

    def __repr__(self):
        return "WAD for Title {titleid} v{titlever}".format(
            titleid=self.tmd.get_titleid(),
            titlever=self.tmd.hdr.titleversion
        )

    def __str__(self):
        output = str(self.tmd) + "\n"
        output += str(self.ticket)

        return output


class WADMaker:
    """Creates a WAD from dir with tmd, cetk and contents
       Reference: https://wiibrew.org/wiki/WAD_files

    Args:
        directory (str): Path to dir with cetk + tmd + contents
        titlever (int): Title Version for TMD (reads tmd.TITLEVER instead of just "tmd")
    """

    class WADHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.hdrsize = Struct.uint32
            self.type = Struct.string(0x04)
            self.certchainsize = Struct.uint32
            self.reserved = Struct.uint32
            self.ticketsize = Struct.uint32
            self.tmdsize = Struct.uint32
            self.datasize = Struct.uint32
            self.footersize = Struct.uint32

    def __init__(self, directory, titlever=None):
        self.directory = directory
        self.ticket = Ticket(os.path.join(self.directory, "cetk"))
        self._titlever = titlever
        if titlever != None:
            self.tmd = TMD(os.path.join(self.directory, "tmd.{0}".format(titlever)))
        else:
            self.tmd = TMD(os.path.join(self.directory, "tmd"))
        try:
            with open(os.path.join(self.directory, "footer"), "rb") as footer_file:
                self.footer = footer_file.read()
        except FileNotFoundError:
            self.footer = b""
        self.contents = []

        # Order of Certs in the WAD: CA Cert, TMD Cert, Cetk Cert (CA + CP + XS)
        # Take the CA cert from ticket (can also be taken from the TMD)
        ca_cert = self.ticket.certificates[1]
        self.correct_cert_order = True
        if ca_cert.get_name() != "CA00000001" and ca_cert.get_name() != "CA00000002":
            self.correct_cert_order = False
            print("WARNING: Second ticket certificate is {0}, but should be CA Cert".format(ca_cert.get_name()))

        tmd_cert = self.tmd.certificates[0]
        if tmd_cert.get_name() != "CP00000004" and tmd_cert.get_name() != "CP00000007":
            self.correct_cert_order = False
            print("WARNING: TMD Certificate is {0}, but should be CP Cert".format(tmd_cert.get_name()))

        cetk_cert = self.ticket.certificates[0]
        if cetk_cert.get_name() != "XS00000003" and cetk_cert.get_name() != "XS00000006":
            self.correct_cert_order = False
            print("WARNING: Ticket Certificate is {0}, but should be XS Cert".format(cetk_cert.get_name()))

        self.certificates = [ca_cert, tmd_cert, cetk_cert]

        # WAD Header
        self.hdr = self.WADHeader()
        self.hdr.hdrsize = len(self.hdr)
        if self.tmd.get_titleid() == "0000000100000001":  # Boot2
            self.hdr.type = b"ib\x00\x00"
        else:
            self.hdr.type = b"Is\x00\x00"
        self.hdr.certchainsize = len(b"".join([x.pack() for x in self.certificates]))
        self.hdr.ticketsize = len(self.ticket)
        self.hdr.tmdsize = len(self.tmd)
        datasize = self.tmd.get_content_size()
        if datasize > 0xFFFFFFFF:
            self.hdr.datasize = 0xFFFFFFFF
        else:
            self.hdr.datasize = datasize
        self.hdr.footersize = len(self.footer)

        # Contents
        for content in self.tmd.contents:
            self.contents.append(open(os.path.join(self.directory, content.get_cid()), 'rb'))

    def encrypt_file(self, cid):
        """Encrypts one app file and updates the TMD."""
        cid = cid.lower()
        encfile = os.path.join(self.directory, cid)
        decfile = encfile + ".app"
        if not os.path.isfile(decfile):
            raise FileNotFoundError("Decrypted APP file does not exist.")

        num = self.tmd.get_cr_index_by_cid(cid)
        tmdcontent = self.tmd.contents[num]

        with open(decfile, "rb") as decrypted_content_file:
            decdata = decrypted_content_file.read()

        # Encrypt data
        encdata = utils.Crypto.encrypt_data(self.ticket.decrypted_titlekey, tmdcontent.get_iv(), decdata)
        with open(encfile, "wb") as encrypted_content_file:
            encrypted_content_file.write(encdata)

        # Update TMD
        newhash = utils.Crypto.create_sha1hash(decdata)
        tmdcontent.size = len(decdata)
        new_datasize = 0
        for content in self.tmd.contents:
            new_datasize += utils.align_pointer(content.size)
        self.hdr.datasize = new_datasize

        if tmdcontent.sha1 != newhash:
            tmdcontent.sha1 = newhash
            self.tmd.fakesign()

        # Dump TMD
        if self._titlever != None:
            self.tmd.dump(os.path.join(self.directory, "tmd.{0}".format(self._titlever)))
        else:
            self.tmd.dump(os.path.join(self.directory, "tmd"))

    def decrypt(self):
        """Decrypts app files"""
        for num, content in enumerate(self.contents):
            tmdcontent = self.tmd.contents[num]
            valid, decdata = utils.Crypto.check_content_hash(tmdcontent, self.ticket, content.read(),
                                                             return_decdata=True)
            with open(os.path.join(self.directory, tmdcontent.get_cid() + ".app"), "wb") as decrypted_content_file:
                if not valid:
                    print("WARNING: SHA1 Sum mismatch for file {0}".format(tmdcontent.get_cid() + ".app"))
                decrypted_content_file.write(decdata)

    def decrypt_file(self, cid):
        """Decrypts one app file. Returns True if the SHA1 Sum matches."""
        cid = cid.lower()
        encfile = os.path.join(self.directory, cid)
        if not os.path.isfile(encfile):
            raise FileNotFoundError("File does not exist.")

        num = self.tmd.get_cr_index_by_cid(cid)
        tmdcontent = self.tmd.contents[num]

        with open(encfile + ".app", "wb") as decrypted_content_file:
            valid, decdata = utils.Crypto.check_content_hash(tmdcontent, self.ticket, self.contents[num].read(),
                                                             return_decdata=True)
            decrypted_content_file.write(decdata)
        if valid:
            return True
        else:
            return False

    def dump(self, output, fixup=False):
        """Dumps WAD to output. Replaces {titleid} and {titleversion} if in filename.
           Passing "fixup=True"  will repair the common-key index and the certificate chain
        """
        if self.ticket.get_titleid().startswith("00030"):
            raise Exception("Can't pack DSi Title as WAD.")

        output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)

        if fixup:
            if self.ticket.hdr.ckeyindex > 2:  # Common key index too high
                print("Fixing Common key index...")
                self.ticket.hdr.ckeyindex = 0
            if not self.correct_cert_order:  # Fixup certificate chain
                print("Fixing Certificate chain...")
                ca_cert = None
                tmd_cert = None
                cetk_cert = None
                for cert in self.tmd.certificates + self.ticket.certificates:
                    if cert.get_name() == "CA00000001" or cert.get_name() == "CA00000002":
                        ca_cert = cert
                    if cert.get_name() == "CP00000004" or cert.get_name() == "CP00000007":
                        tmd_cert = cert
                    if cert.get_name() == "XS00000003" or cert.get_name() != "XS00000006":
                        cetk_cert = cert
                if not ca_cert:
                    raise Exception("ERROR: CA Certificate was not found")
                if not tmd_cert:
                    raise Exception("ERROR: CP Certificate was not found")
                if not cetk_cert:
                    raise Exception("ERROR: XS Certificate was not found")
                self.certificates = [ca_cert, tmd_cert, cetk_cert]
                self.hdr.certchainsize = len(b"".join([x.pack() for x in self.certificates]))

        # Header
        wad = self.hdr.pack()
        wad += utils.align(len(self.hdr))

        # Certificate Chain
        wad += b"".join([x.pack() for x in self.certificates])
        wad += utils.align(self.hdr.certchainsize)

        # Ticket
        wad += self.ticket.pack()
        wad += utils.align(self.hdr.ticketsize)

        # TMD
        wad += self.tmd.pack()
        wad += utils.align(self.hdr.tmdsize)

        # Writing WAD
        with open(output, "wb") as wad_file:
            wad_file.write(wad)
            # Not forgetting Contents!
            for i, content in enumerate(self.contents):
                content_length = 0
                for chunk in utils.read_in_chunks(content):
                    content_length += len(chunk)
                    wad_file.write(chunk)
                wad_file.write(utils.align(content_length))
            # Footer
            if self.footer:
                wad_file.write(self.footer)
                wad_file.write(utils.align(self.hdr.footersize))

    def __del__(self):
        for content in self.contents:
            content.close()

    def __repr__(self):
        return "WAD Maker for Title {titleid} v{titlever}".format(
            titleid=self.tmd.get_titleid(),
            titlever=self.tmd.hdr.titleversion
        )

    def __str__(self):
        output = str(self.tmd) + "\n"
        output += str(self.ticket)

        return output


class NUS:
    """Downloads titles from NUS.

    Args:
        titleid (str): Valid hex Title ID (16 chars)
        titlever (int, optional): Valid Title version. Defaults to latest
        base (str, optional): NUS CDN. Defaults to "nus.cdn.shop.wii.com"
    """

    def __init__(
            self,
            titleid,
            titlever=None,
            base="http://nus.cdn.shop.wii.com/ccs/download"
    ):
        self.url = base + "/" + titleid.lower() + "/"
        self._titlever = titlever

    @CachedProperty
    def tmd(self):
        tmd_url = self.url + "tmd"

        if self._titlever != None:
            tmd_url += ".{0}".format(self._titlever)
        try:
            req = get(tmd_url)
            req.raise_for_status()
        except HTTPError:
            raise HTTPError("Title not found on NUS")

        return TMD(req.content)

    @CachedProperty
    def ticket(self):
        cetk_url = self.url + "cetk"
        try:
            req = get(cetk_url)
            req.raise_for_status()
        except HTTPError:
            return None

        return Ticket(req.content)

    def get_content_urls(self):
        """Returns content urls"""
        urls = []
        for content in self.tmd.contents:
            urls.append(self.url + content.get_cid())
        return urls

    def get_content_url_by_cid(self, cid):
        """Returns content url for content id"""
        for content in self.tmd.contents:
            if content.get_cid() == cid.lower():
                return self.url + content.get_cid()
        raise Exception("Content ID {0} not in TMD.".format(cid))

    def __repr__(self):
        return "Title {id} v{ver} on NUS".format(
            id=self.tmd.get_titleid(),
            ver=self.tmd.hdr.titleversion,
        )

    def __str__(self):
        output = "NUS Content:\n"
        for url in self.get_content_urls():
            output += "  " + url + "\n"

        output += "\n" + str(self.tmd) + "\n"
        if self.ticket:
            output += str(self.ticket)

        return output
