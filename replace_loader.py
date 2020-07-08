#!/usr/bin/env python3
"""
    This script replaces the NAND loader of a WAD. This is perfect for e.g. "Custom NAND loader"
    to fix the blackscreen in NTSC VC games on PAL Wiis.

    Download the Custom NAND Loader from here: https://static.wiidatabase.de/custom-nand-loader-MOD-1.1.zip
    Check which IOS the title needs and if it doesn't have a loader.bin, use the "forceNTSC_loader".
    You can get the required IOS titleid with "WADGEN.WAD("mywad.wad").tmd.get_required_title()".
"""
import os
import os.path
import shutil
from argparse import ArgumentParser

import WADGEN


def main(wadname):
    if not os.path.isfile("loader.bin"):
        print("ERROR: No loader.bin found in current directory!")
        return

    print("Loading Info...")
    wad = WADGEN.WAD(wadname)

    print("Extracting...")
    output_folder = os.path.join("extracted_wads", wad.tmd.get_titleid(), str(wad.tmd.hdr.titleversion))
    wad.unpack(output=output_folder, decrypt=True)

    boot_index = wad.tmd.get_boot_index()
    if not boot_index:
        print("No boot index found - is this a game WAD?")
        return

    boot_index_file = os.path.join(output_folder, boot_index + ".app")
    if not os.path.isfile(boot_index_file):
        print("Boot file {0} not found!".format(boot_index_file))
        return

    print("Replacing loader...")
    shutil.copyfile("loader.bin", boot_index_file)

    print("Reencrypting...")
    wadmaker = WADGEN.WADMaker(output_folder)
    wadmaker.encrypt_file(boot_index)

    print("Saving...")
    newname = "[PATCHED] {0}".format(wadname)
    wadmaker.dump(newname)
    print("=> Saved to {0}".format(newname))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('wadname', type=str, help="WAD name")
    arguments = parser.parse_args()
    main(wadname=arguments.wadname)
