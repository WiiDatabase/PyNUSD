import os
import struct
from enum import Enum
from io import BytesIO
from typing import Union, List

from WADGEN import Base, Certificate, Ticket, utils, TMD, ROOT_KEY


class WADTYPE(Enum):
    NORMAL = b"Is"
    BOOT2 = b"ib"


class WAD(Base):
    HEADERSIZE = 32
    TICKETSIZE = 676

    def __init__(self, f: Union[str, None] = None):
        if f and not isinstance(f, str):
            raise Exception("WADs can only be loaded from a file.")

        self.header_size = self.HEADERSIZE
        self.type = WADTYPE.NORMAL.value
        self.version = 0
        self.certchain_size = 0
        self.reserved = b"\x00" * 4
        self.ticket_size = self.TICKETSIZE
        self.tmd_size = 0
        self.data_size = 0
        self.footer_size = 0
        self.padding = b"\x00" * 32
        self.certificates = []
        self.ticket = Ticket()
        self.tmd = TMD()
        self.footer = None

        self.__f = f
        self.__footeroffset = None
        self.__dataoffset = None

        super().__init__(f)

    def parse_file(self, filename: str):
        with open(filename, "rb") as file:
            header = BytesIO(file.read(self.HEADERSIZE))
            self.parse_header(header)

            # Certificates
            file.seek(utils.align_pointer(file.tell()), 1)
            self.certificates = []
            certchain = BytesIO(file.read(self.certchain_size))
            for i in range(3):
                self.certificates.append(Certificate(certchain))

            # Ticket
            file.seek(utils.align_pointer(file.tell()), 1)
            ticket = BytesIO(file.read(self.ticket_size))
            self.ticket = Ticket(ticket, has_certificates=False)

            # TMD
            file.seek(utils.align_pointer(file.tell()), 1)
            tmd = BytesIO(file.read(self.tmd_size))
            self.tmd = TMD(tmd, has_certificates=False)

            # Contents would start here
            file.seek(utils.align_pointer(file.tell()), 1)
            self.__dataoffset = file.tell()

            if self.has_footer():
                # Footer
                file.seek(self.data_size, 1)
                file.seek(utils.align_pointer(file.tell()), 1)
                self.__footeroffset = file.tell()
                self.footer = file.read(self.footer_size)
            else:
                self.footer = None

    def parse_header(self, header: BytesIO):
        self.header_size = struct.unpack(">L", header.read(4))[0]
        if self.header_size != self.HEADERSIZE:
            raise Exception("Invalid header size.")

        self.type = header.read(2)
        self.version = struct.unpack(">H", header.read(2))[0]
        self.certchain_size = struct.unpack(">L", header.read(4))[0]
        self.reserved = header.read(4)
        self.ticket_size = struct.unpack(">L", header.read(4))[0]
        if self.ticket_size != self.TICKETSIZE:
            raise Exception("Invalid ticket size.")

        self.tmd_size = struct.unpack(">L", header.read(4))[0]
        self.data_size = struct.unpack(">L", header.read(4))[0]
        self.footer_size = struct.unpack(">L", header.read(4))[0]
        self.padding = header.read(32)

    def parse(self, f: BytesIO) -> NotImplemented:
        return NotImplemented

    def pack(self) -> NotImplemented:
        return NotImplemented

    def dump(self, output) -> str:
        """Dumps the Ticket to output. Replaces {titleid} and {titleversion} if in path.
           Returns the file path.
        """
        output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.get_titleversion())
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
            if self.__f:
                with open(self.__f, "rb") as orig_file:
                    orig_file.seek(self.__dataoffset)

                    if not self.__footeroffset:  # Just read until EOF
                        for chunk in utils.read_in_chunks(orig_file):
                            file.write(chunk)
                    else:  # Read until the footer
                        for chunk in utils.read_in_chunks(orig_file, 64):
                            file.write(chunk)
                            if orig_file.tell() == self.__footeroffset:
                                break
            file.write(utils.align(self.get_data_size()))

            # Footer
            if self.has_footer():
                file.write(self.get_footer())
                file.write(utils.align(self.get_footer_size()))
                if utils.align_pointer(self.get_footer_size()) != 0:
                    # If the footer isn't aligned on 64 bytes, there will be 64 bytes of extra padding
                    file.write(b"\x00" * 64)

        return output

    def unpack(self,
               output=None,
               decrypt=True,
               include_signatures=True,
               include_certificates=True):
        """Extracts WAD to output. Replaces {titleid} and {titleversion} if in folder name.
           Extracts to "extracted_wads/TITLEID/TITLEVER" if no output is given.
       """
        if output:
            output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.get_titleversion())
        else:
            output = os.path.join("extracted_wads", self.tmd.get_titleid(), str(self.tmd.get_titleversion()))

        if not os.path.isdir(output):
            os.makedirs(output)

        with open(os.path.join(output, "header"), "wb") as header_file:
            # Header
            header_file.write(struct.pack(">L", self.get_header_size()))
            header_file.write(self.type)
            header_file.write(struct.pack(">H", self.version))
            header_file.write(struct.pack(">L", self.get_certchain_size()))
            header_file.write(self.reserved)
            header_file.write(struct.pack(">L", self.get_ticket_size()))
            header_file.write(struct.pack(">L", self.get_tmd_size()))
            header_file.write(struct.pack(">L", self.get_data_size()))
            header_file.write(struct.pack(">L", self.get_footer_size()))
            header_file.write(self.padding)

        self.get_tmd().dump(os.path.join(output, "tmd"), include_signature=include_signatures)
        self.get_ticket().dump(os.path.join(output, "cetk"), include_signature=include_signatures)

        certchain = b""
        for cert in self.get_certificates():
            certchain += cert.pack()
        with open(os.path.join(output, "cert.sys"), "wb") as cert_file:
            cert_file.write(certchain)

        # TODO: Data
        print("Dumping data is not implemented yet!")

        if self.has_footer():
            with open(os.path.join(output, "footer"), "wb") as footer_file:
                footer_file.write(self.get_footer())

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

    def get_footer(self) -> bytes:
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
        return "<WAD(tmd='{tmd}', ticket='{ticket}')>".format(
                tmd=repr(self.get_tmd()),
                ticket=repr(self.get_ticket())
        )

    def __str__(self):
        output = str(self.tmd) + "\n"
        output += str(self.ticket)

        return output
