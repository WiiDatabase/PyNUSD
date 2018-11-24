#!/usr/bin/env python3
import binascii
import os
import struct

from Crypto.Cipher import AES
from requests import get, HTTPError

import utils
from Struct import Struct
from utils import CachedProperty

DECRYPTION_KEYS = [
    b"\xEB\xE4\x2A\x22\x5E\x85\x93\xE4\x48\xD9\xC5\x45\x73\x81\xAA\xF7",  # Common Key
    b"\x63\xB8\x2B\xB4\xF4\x61\x4E\x2E\x13\xF2\xFE\xFB\xBA\x4C\x9B\x7E",  # Korean Key
    b"\x30\xbf\xc7\x6e\x7c\x19\xaf\xbb\x23\x16\x33\x30\xce\xd7\xc2\x8d"   # vWii Key
]


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
            return "RSA_4096 SHA1"
        elif self.signature_length == 0x100 + 0x3C:
            return "RSA_2048 SHA1"
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
            self.pubkey = self.PubKeyRSA4096()
        elif pubkey_length == 0x100 + 0x4 + 0x34:
            self.pubkey = self.PubKeyRSA2048()
        elif pubkey_length == 0x3C + 0x3C:
            self.pubkey = self.PubKeyECC()
        else:
            raise Exception("Unknown Public Key type")  # Should never happen
        self.pubkey = self.pubkey.unpack(
            filebytes[len(self.signature) + len(self.certificate):
                      len(self.signature) + len(self.certificate) + pubkey_length]
        )

    def __len__(self):
        return len(self.signature) + len(self.certificate) + len(self.pubkey)

    def __repr__(self):
        return "{0} issued by {1}".format(self.get_name(), self.get_issuer())

    def pack(self):
        return self.signature.pack() + self.certificate.pack() + self.pubkey.pack()

    def get_issuer(self):
        return self.certificate.issuer.rstrip(b"\00").decode().split("-")[-1]

    def get_name(self):
        return self.certificate.name.rstrip(b"\00").decode()


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
            self.padding2 = Struct.string(2)

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

        def __repr__(self):
            output = "Content {0}".format(self.get_cid())
            return output

        def __str__(self):
            output = "Content:\n"
            output += "   ID         Index   Type     Size       Hash\n"
            output += "   {:08X}   {:<7d} {:<8s} {:<11s}".format(
                self.cid,
                self.index,
                self.get_type(),
                utils.convert_size(self.size)
            )
            output += binascii.hexlify(self.sha1).decode() + "\n"

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

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_required_title(self):
        return "{:08X}".format(self.hdr.system_version).zfill(16).lower()

    def get_content_size(self):
        size = 0
        for content in self.contents:
            size += content.size
            size += utils.align_pointer(content.size)
        return size

    def get_type(self):
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
            return types[self.get_titleid()[:8]]
        except KeyError:
            return "Unknown"

    def get_region(self):
        # https://github.com/dnasdw/libwiisharp/blob/master/libWiiSharp/TMD.cs#L34-L37
        regions = [
            "Japan",
            "USA",
            "Europe",
            "Free"
        ]
        try:
            return regions[self.hdr.region]
        except KeyError:
            return "Unknown"

    def pack(self):
        """Returns TMD WITHOUT certificates."""
        pack = self.signature.pack() + self.hdr.pack()
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
        output += "\n"

        output += "  Number of contents: {0}\n".format(self.hdr.contentcount)
        output += "  Contents:\n"
        output += "   ID         Index   Type     Size       Hash\n"
        for content in self.contents:
            output += "   {:08X}   {:<7d} {:<8s} {:<11s}".format(
                content.cid,
                content.index,
                content.get_type(),
                utils.convert_size(content.size)
            )
            output += binascii.hexlify(content.sha1).decode() + "\n"

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

        # Decrypt title key
        self.decrypted_titlekey = AES.new(key=self.get_decryption_key(),
                                          mode=AES.MODE_CBC,
                                          iv=self.titleiv).decrypt(self.hdr.titlekey)

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_decryption_key(self):
        # TODO: Debug (RVT) Tickets
        """Returns the appropiate Common Key"""
        try:
            return DECRYPTION_KEYS[self.hdr.ckeyindex]
        except IndexError:
            print("WARNING: Unknown Common Key, assuming normal key")
            return DECRYPTION_KEYS[0]

    def get_common_key_type(self):
        key_types = [
            "Normal",
            "Korean",
            "Wii U Wii Mode"
        ]
        try:
            return key_types[self.hdr.ckeyindex]
        except IndexError:
            return "Unknown"

    def pack(self):
        """Returns ticket WITHOUT certificates"""
        return self.signature.pack() + self.hdr.pack()

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
        # Order is: CA (Root) + CP + XS
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
        self.ticket.certificates.append(self.certificates[0])  # Root
        pos += self.hdr.ticketsize

        # TMD
        pos += utils.align_pointer(pos)
        self.tmd = TMD(file[pos:pos + self.hdr.tmdsize])
        self.tmd.certificates.append(self.certificates[1])  # CP
        self.tmd.certificates.append(self.certificates[0])  # Root
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

    def unpack(self, output=None, decrypt=False):
        """Extracts WAD to output. Replaces {titleid} and {titleversion} if in foldername.
           Extracts to "extracted_wads/TITLEID/TITLEVER" if no output is given. Pass decrypt=True to decrypt contents.
       """
        if output:
            output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)
        else:
            output = os.path.join("extracted_wads", self.tmd.get_titleid(), str(self.tmd.hdr.titleversion))
        if not os.path.exists(output):
            os.makedirs(output)
        # TMD + Ticket
        self.tmd.dump(os.path.join(output, "tmd"))
        self.ticket.dump(os.path.join(output, "cetk"))

        # Encrypted Contents
        for num, content in enumerate(self.contents):
            filename = self.tmd.contents[num].get_cid()
            with open(os.path.join(output, filename), "wb") as content_file:
                if decrypt:  # Decrypted Contents
                    with open(os.path.join(output, filename + ".app"), "wb") as decrypted_content_file:
                        iv = struct.pack(">H", self.tmd.contents[num].index) + b"\x00" * 14
                        decdata = utils.Crypto.decrypt_data(self.ticket.decrypted_titlekey, iv, content, True)
                        decdata = decdata[:self.tmd.contents[num].size]  # Trim the file to its real size
                        decdata_hash = utils.Crypto.create_sha1hash(decdata)
                        tmd_hash = self.tmd.contents[num].sha1
                        if decdata_hash != tmd_hash:
                            print("WARNING: SHA1 Sum mismatch for file {0}".format(filename + ".app"))
                        decrypted_content_file.write(decdata)
                content_file.write(content)

        # Footer
        if self.footer:
            with open(os.path.join(output, "footer"), "wb") as footer_file:
                footer_file.write(self.footer)

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

    def __init__(self, directory):
        self.ticket = Ticket(os.path.join(directory, "cetk"))
        self.tmd = TMD(os.path.join(directory, "tmd"))
        try:
            with open(os.path.join(directory, "footer"), "rb") as footer_file:
                self.footer = footer_file.read()
        except FileNotFoundError:
            self.footer = b""
        self.contents = []

        # Order of Certs in the WAD: Root Cert, TMD Cert, Cetk Cert (Root + CP + XS)
        # Take the root cert from ticket (can also be taken from the TMD)
        root_cert = self.ticket.certificates[1]
        if root_cert.get_name() != "CA00000001" and root_cert.get_name() != "CA00000002":
            raise Exception("Root Certificate not found")

        tmd_cert = self.tmd.certificates[0]
        if tmd_cert.get_name() != "CP00000004":
            raise Exception("TMD Certificate not found")

        cetk_cert = self.ticket.certificates[0]
        if cetk_cert.get_name() != "XS00000003" and cetk_cert.get_name() != "XS00000006":
            raise Exception("Cetk Certificate not found")

        self.certchain = root_cert.pack() + tmd_cert.pack() + cetk_cert.pack()

        # WAD Header
        self.hdr = self.WADHeader()
        self.hdr.hdrsize = len(self.hdr)
        if self.tmd.get_titleid() == "0000000100000001":  # Boot2
            self.hdr.type = b"ib\x00\x00"
        else:
            self.hdr.type = b"Is\x00\x00"
        self.hdr.certchainsize = len(self.certchain)
        self.hdr.ticketsize = len(self.ticket)
        self.hdr.tmdsize = len(self.tmd)
        self.hdr.datasize = self.tmd.get_content_size()
        self.hdr.footersize = len(self.footer)

        # Contents
        for content in self.tmd.contents:
            self.contents.append(open(os.path.join(directory, content.get_cid()), 'rb'))

    def dump(self, output):
        """Dumps WAD to output. Replaces {titleid} and {titleversion} if in filename."""
        output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)

        # Header
        wad = self.hdr.pack()
        wad += utils.align(len(self.hdr))

        # Certificate Chain
        wad += self.certchain
        wad += utils.align(len(self.certchain))

        # Ticket
        wad += self.ticket.pack()
        wad += utils.align(self.hdr.ticketsize)

        # TMD
        wad += self.tmd.pack()
        wad += utils.align(self.hdr.tmdsize)

        # Writing WAD
        total_content_length = 0
        with open(output, "wb") as wad_file:
            wad_file.write(wad)
            # Not forgetting Contents!
            for i, content in enumerate(self.contents):
                content_length = 0
                for chunk in utils.read_in_chunks(content):
                    content_length += len(chunk)
                    wad_file.write(chunk)
                    wad_file.write(utils.align(content_length))
                total_content_length += content_length
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
