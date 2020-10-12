import os
import struct
from io import BytesIO
from typing import Optional, List

from WADGEN import TMD, Ticket, WAD, WADTYPE, Certificate, ROOT_KEY, utils


class WADMaker:
    def __init__(self, f: str):
        if f and not isinstance(f, str) or not os.path.isdir(f):
            raise Exception("WADs can only be made from a folder.")

        self.header_size = WAD.HEADERSIZE
        self.type = WADTYPE.NORMAL.value
        self.version = 0
        self.certchain_size = 0
        self.reserved = b"\x00" * 4
        self.ticket_size = WAD.TICKETSIZE
        self.tmd_size = 0
        self.data_size = 0
        self.footer_size = 0
        self.padding = b"\x00" * 32

        self.certificates = []
        self.tmd = TMD(has_certificates=False)
        self.ticket = Ticket(has_certificates=False)
        self.footer = None

        self.__folder = f
        self.parse()

    def parse(self):
        certchain_unavailable = True
        if os.path.isfile(os.path.join(self.__folder, "cert.sys")):
            certchain_unavailable = False

        # TMD
        with open(os.path.join(self.__folder, "tmd"), "rb") as tmd_file:
            self.tmd = TMD(tmd_file.read(), has_certificates=certchain_unavailable)

        # Ticket
        with open(os.path.join(self.__folder, "cetk"), "rb") as ticket_file:
            self.ticket = Ticket(ticket_file.read(), has_certificates=certchain_unavailable)

        # Certificates
        if not certchain_unavailable:
            self.certificates = []
            with open(os.path.join(self.__folder, "cert.sys"), "rb") as cert_file:
                certchain = BytesIO(cert_file.read())
                for i in range(3):
                    self.certificates.append(Certificate(certchain))
        else:  # Get Certificates from TMD + Ticket
            self.certificates = []
            # CA first
            try:
                self.certificates.append(self.get_tmd().get_cert_by_name(self.get_tmd().get_issuers()[1]))
            except ValueError:
                self.certificates.append(self.get_ticket().get_cert_by_name(self.get_ticket().get_issuers()[1]))

            # CP from TMD
            self.certificates.append(self.get_tmd().get_cert_by_name(self.get_tmd().get_issuers()[-1]))

            # XS from Ticket
            self.certificates.append(self.get_ticket().get_cert_by_name(self.get_ticket().get_issuers()[-1]))

            # Set certs for TMD
            certchain = []
            for issuer in reversed(self.get_tmd().get_issuers()):
                if issuer == "Root":
                    continue
                try:
                    certchain.append(self.get_cert_by_name(issuer))
                except LookupError:
                    continue
            self.get_tmd().set_certificate_chain(certchain)

            # Set certs for Ticket
            certchain = []
            for issuer in reversed(self.get_ticket().get_issuers()):
                if issuer == "Root":
                    continue
                try:
                    certchain.append(self.get_cert_by_name(issuer))
                except LookupError:
                    continue
            self.get_ticket().set_certificate_chain(certchain)

        # Footer
        if os.path.isfile(os.path.join(self.__folder, "footer")):
            with open(os.path.join(self.__folder, "footer"), "rb") as footer_file:
                self.footer = footer_file.read()

        # Header
        if os.path.isfile(os.path.join(self.__folder, "header")):
            self.parse_header(os.path.join(self.__folder, "header"))
        else:
            if self.get_tmd().get_titleid() != "0000000100000001":  # Boot 2
                self.type = WADTYPE.BOOT2
            self.certchain_size = 0
            for cert in self.get_certificates():
                self.certchain_size += len(cert)
            self.ticket_size = WAD.TICKETSIZE
            self.tmd_size = len(self.get_tmd())
            self.data_size = self.get_tmd().get_aligned_data_size()
            if self.get_data_size() > 0xFFFFFFFF:
                self.data_size = 0xFFFFFFFF
            self.footer_size = len(self.get_footer())

        if self.get_data_size() < 0xFFFFFFFF:
            if self.get_tmd().get_aligned_data_size() != self.get_data_size():
                print("WARNING: Data size in header does not match real data size.")

    def parse_header(self, header_file: str):
        with open(header_file, "rb") as file:
            self.header_size = struct.unpack(">L", file.read(4))[0]
            if self.header_size != WAD.HEADERSIZE:
                raise Exception("Invalid header size.")

            self.type = file.read(2)
            self.version = struct.unpack(">H", file.read(2))[0]
            self.certchain_size = struct.unpack(">L", file.read(4))[0]
            self.reserved = file.read(4)
            self.ticket_size = struct.unpack(">L", file.read(4))[0]
            if self.ticket_size != WAD.TICKETSIZE:
                raise Exception("Invalid ticket size.")

            self.tmd_size = struct.unpack(">L", file.read(4))[0]
            self.data_size = struct.unpack(">L", file.read(4))[0]
            self.footer_size = struct.unpack(">L", file.read(4))[0]
            self.padding = file.read(32)

    def dump(self, output) -> str:
        """Dumps the WAD to output. Replaces {titleid} and {titleversion} if in path.
           Returns the file path.
        """
        output = output.format(titleid=self.get_tmd().get_titleid(), titleversion=self.get_tmd().get_titleversion())
        with open(output, "wb") as file:
            # Header
            file.write(struct.pack(">L", self.get_header_size()))
            file.write(self.type)
            file.write(struct.pack(">H", self.version))
            file.write(struct.pack(">L", self.get_certchain_size()))
            file.write(self.reserved)
            file.write(struct.pack(">L", self.get_ticket_size()))
            file.write(struct.pack(">L", self.get_tmd_size()))
            file.write(struct.pack(">L", self.get_data_size()))
            file.write(struct.pack(">L", self.get_footer_size()))
            file.write(self.padding)
            file.write(utils.align(self.get_header_size()))

            # Certificates
            for cert in self.get_certificates():
                file.write(cert.pack())
            file.write(utils.align(self.get_certchain_size()))

            # Ticket
            file.write(self.get_ticket().pack())
            file.write(utils.align(self.get_ticket_size()))

            # TMD
            file.write(self.get_tmd().pack())
            file.write(utils.align(self.get_tmd_size()))

            # Data
            for content in self.get_tmd().get_contents():
                with open(os.path.join(self.__folder, content.get_cid()), "rb") as content_file:
                    file.write(content_file.read())
                file.write(utils.align(content.get_aligned_size(16)))

            # Footer
            if self.has_footer():
                file.write(self.get_footer())
                file.write(utils.align(self.get_footer_size()))
                if utils.align_pointer(self.get_footer_size()) != 0:
                    # If the footer isn't aligned on 64 bytes, there will be 64 bytes of extra padding
                    file.write(b"\x00" * 64)

        return output

    def get_tmd(self) -> TMD:
        return self.tmd

    def get_ticket(self) -> Ticket:
        return self.ticket

    def get_certificates(self) -> List[Certificate]:
        return self.certificates

    def get_certificate(self, i: int) -> Certificate:
        return self.get_certificates()[i]

    def get_cert_by_name(self, name) -> Certificate:
        """Returns certificate by name."""
        for cert in self.get_certificates():
            if cert.get_name() == name:
                return cert
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

    def get_footer(self) -> Optional[bytes]:
        return self.footer

    def get_header_size(self) -> int:
        return self.header_size

    def get_certchain_size(self) -> int:
        return self.certchain_size

    def get_ticket_size(self) -> int:
        return self.ticket_size

    def get_tmd_size(self) -> int:
        return self.tmd_size

    def get_data_size(self) -> int:
        return self.data_size

    def get_footer_size(self) -> int:
        return self.footer_size

    def has_footer(self) -> bool:
        return self.footer_size > 0

    def update_tmd(self):
        pass

    def __len__(self):
        # NOTE: Many scene WADs are wrongly packed and the returned size won't match the
        # size of the file on disk.
        size = utils.align_value(self.get_header_size()) + utils.align_value(self.get_certchain_size()) \
               + utils.align_value(self.get_ticket_size()) + utils.align_value(self.get_tmd_size()) \
               + utils.align_value(self.get_data_size())
        if self.has_footer():
            size += utils.align_value(self.get_footer_size())
            if utils.align_pointer(self.get_footer_size()) != 0:
                # If the footer isn't aligned on 64 bytes, there will be 64 bytes of extra padding
                size += 64
        return size

    def __repr__(self):
        return "<WADMaker(tmd='{tmd}', ticket='{ticket}')>".format(
                tmd=repr(self.get_tmd()),
                ticket=repr(self.get_ticket())
        )

    def __str__(self):
        output = str(self.get_tmd()) + "\n"
        output += str(self.get_ticket())

        return output
