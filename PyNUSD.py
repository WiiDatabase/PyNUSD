#!/usr/bin/env python3
import binascii
import os
import struct
from argparse import ArgumentParser

from requests import get, HTTPError

import WADGEN
import utils

tickettemplate = binascii.a2b_hex(
    "0001000163C7CA3E6D51EF91B637251DF8A1887B12F222400D5DE7F4740343A0069EE091B0442B7E69C52259624D6471ABB421AC1884DF4D9BC516CC6940AA5BED4A653D196880D6E93F16BF3AA818DAF0EAD11D845B072C8AF5130858D08CDD26CDE82813170C18B09EF309CAD298C94B5E17F50E7E9AC9A858D7578E931806CB187EEA9C847D4B417B431C2A4A8D03EB218410D0E9622A3D46CFCD05C56F7113AA392A009034801B4F240F487F4FBF22F9A0CBDAFEF04E3293E4FE616C6BCA7659AE681F57BF7F32ACC5EDC123BA58BD67425EDC1B60B5766A4175A63CCED67C1DB6B1449532F075440C6E6B0DA338C797917AAAD8801BFC3339F09E4DCC2C0F5D8E3D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D434130303030303030312D58533030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041414141414141414141414141414141000000000000000000000000005959595959595959FFFF393900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100017D9D5EBA5281DCA7065D2F0868DB8AC73ACE7EA991F1969FE1D0F2C11FAEC0C3F01ADCB446ADE5CA03B625219462C6E1410DB9E63FDE98D1AF263B4CB28784278272EF27134B87C258D67B62F2B5BF9CB6BA8C89192EC50689AC7424A022094003EE98A4BD2F013B593FE5666CD5EB5AD7A49310F34EFBB43D46CBF1B523CF82F68EB56DB904A7C2A82BE11D78D39BA20D90D30742DB5E7AC1EFF221510962CFA914A880DCF417BA99930AEE08B0B0E51A3E9FAFCDC2D7E3CBA12F3AC00790DE447AC3C538A8679238078BD4C4B245AC2916886D2A0E594EED5CC835698B4D6238DF05724DCCF681808A7074065930BFF8514137E815FABAA172B8E0696C61E4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D43413030303030303031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F1B89FD1AD07A9378A7B100C7DC739BE9EDDB7320089AB25B1F871AF5AA9F4589ED18302328E811A1FEFD009C8063643F854B9E13BBB613A7ACF8714856BA45BAAE7BBC64EB2F75D87EBF267ED0FA441A933665E577D5ADEABFB462E7600CA9CE94DC4CB983992AB7A2FB3A39EA2BF9C53ECD0DCFA6B8B5EB2CBA40FFA4075F8F2B2DE973811872DF5E2A6C38B2FDC8E57DDBD5F46EB27D61952F6AEF862B7EE9AC682A2B19AA9B558FBEBB3892FBD50C9F5DC4A6E9C9BFE458034A942182DDEB75FE0D1B3DF0E97E39980877018C2B283F135757C5A30FC3F3084A49AAAC01EE706694F8E1448DA123ACC4FFA26AA38F7EFBF278F369779775DB7C5ADC78991DCF8438D000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000B3ADB3226B3C3DFF1B4B407716FF4F7AD76486C895AC562D21F10601D4F66428191C07768FDF1AE2CE7B27C90FBC0AD0312578EC0779B657D4372413A7F86F0C14C0EF6E0941ED2B05EC3957360789004A878D2E9DF8C7A5A9F8CAB311B1187957BBF898E2A25402CF5439CF2BBFA0E1F85C066E839AE094CA47E01558F56E6F34E92AA2DC38937E37CD8C5C4DFD2F114FE868C9A8D9FED86E0C2175A2BD7E89B9C7B513F41A7961443910EFF9D7FE572218D56DFB7F497AA4CB90D4F1AEB176E4685DA7944060982F0448401FCFC6BAEBDA1630B473B415233508070A9F4F8978E62CEC5E9246A5A8BDA0857868750C3A112FAF95E838C8990E87B162CD10DAB3319665EF889B541BB336BB67539FAFC2AE2D0A2E75C02374EA4EAC8D99507F59B95377305F2635C608A99093AC8FC6DE23B97AEA70B4C4CF66B30E58320EC5B6720448CE3BB11C531FCB70287CB5C27C674FBBFD8C7FC94220A473231D587E5A1A1A82E37579A1BB826ECE0171C97563474B1D46E679B282376211CDC7002F4687C23C6DC0D5B5786EE1F273FF0192500FF4C7506AEE72B6F43DF608FEA583A1F9860F87AF524454BB47C3060C94E99BF7D632A7C8AB4B4FF535211FC18047BB7AFA5A2BD7B884AD8E564F5B89FF379737F1F5013B1F9EC4186F922AD5C4B3C0D5870B9C04AF1AB5F3BC6D0AF17D4708E443E973F7B7707754BAF3ECD2AC49000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005BFA7D5CB279C9E2EEE121C6EAF44FF639F88F078B4B77ED9F9560B0358281B50E55AB721115A177703C7A30FE3AE9EF1C60BC1D974676B23A68CC04B198525BC968F11DE2DB50E4D9E7F071E562DAE2092233E9D363F61DD7C19FF3A4A91E8F6553D471DD7B84B9F1B8CE7335F0F5540563A1EAB83963E09BE901011F99546361287020E9CC0DAB487F140D6626A1836D27111F2068DE4772149151CF69C61BA60EF9D949A0F71F5499F2D39AD28C7005348293C431FFBD33F6BCA60DC7195EA2BCC56D200BAF6D06D09C41DB8DE9C720154CA4832B69C08C69CD3B073A0063602F462D338061A5EA6C915CD5623579C3EB64CE44EF586D14BAAA8834019B3EEBEED3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")


def main(titleid, titlever=None, pack_as_wad=True, decryptcontents=False, localuse=True, keepcontents=True,
         enc_titlekey=None, onlyticket=False, cdndir=False, base_url="http://nus.cdn.shop.wii.com/ccs/download"):
    if len(titleid) != 16:
        print("Title ID must be 16 characters long.")
        return
    try:
        int(titleid, 16)
    except ValueError:
        print("Title ID must be in hexadecimal.")
        return

    if onlyticket and not enc_titlekey:
        print("Please specify an ecrypted titlekey (--key) for Ticket generation.")
        return

    if enc_titlekey:
        if len(enc_titlekey) != 32:
            print("Encrypted title key must be 32 characters long.")
            return
        try:
            int(enc_titlekey, 16)
        except ValueError:
            print("Title key must be in hexadecimal.")
            return

    if not pack_as_wad and not keepcontents and not decryptcontents:
        print("Running with these settings would produce no output.")
        return

    titleid = titleid.lower()
    nus = WADGEN.NUS(titleid, titlever, base=base_url)

    if onlyticket:
        print("Generating Ticket for Title {0} v{1}".format(titleid, "[Latest]" if titlever == None else titlever))
    else:
        print("Downloading Title {0} v{1}".format(titleid, "[Latest]" if titlever == None else titlever))

    # Download TMD
    print("* Downloading TMD...")
    try:
        tmd = nus.tmd
    except HTTPError:
        print("Title not on NUS!")
        return

    # Parse TMD
    print("* Parsing TMD...")
    total_size = 0
    for content in tmd.contents:
        total_size += content.size
    print("    Title Version: {0}".format(tmd.hdr.titleversion))
    print("    {0} Content{1}: {2}".format(
        len(tmd.contents),
        "s" if len(tmd.contents) > 1 else "",
        utils.convert_size(total_size)
    ))

    if titlever == None:
        titlever = tmd.hdr.titleversion
    else:
        if titlever != tmd.hdr.titleversion:
            print("    WARNING: Title version should be {0} but is {1}".format(titleid, tmd.hdr.titleversion))

    if titleid != tmd.get_titleid():
        print("    WARNING: Title ID should be {0} but is {1} (ignore for vWii)".format(titleid, tmd.get_titleid()))

    if cdndir:
        titlepath = os.path.join("titles", titleid)
    else:
        titlepath = os.path.join("titles", titleid, str(titlever))
    if not os.path.isdir(titlepath):
        os.makedirs(titlepath)
    if not onlyticket:
        if cdndir:
            tmd.dump(os.path.join(titlepath, "tmd.{0}".format(titlever)))
        else:
            tmd.dump(os.path.join(titlepath, "tmd"))

    # Download Ticket
    if enc_titlekey:
        print("* Generating Ticket...")
        cetk = WADGEN.Ticket(tickettemplate)
        cetk.hdr.titleid = tmd.hdr.titleid
        cetk.hdr.titleversion = tmd.hdr.titleversion
        cetk.hdr.titlekey = binascii.a2b_hex(enc_titlekey)
        if tmd.get_region() == "Korea" and not tmd.get_titleid().startswith("00030"):  # Korea + not DSi
            cetk.hdr.ckeyindex = 1  # Korean common-key index
        cetk.dump(os.path.join(titlepath, "cetk"))
        if localuse:  # We need to set Title IV and decrypt the titlekey for verifying
            cetk.titleiv = struct.pack(">Q", cetk.hdr.titleid) + b"\x00" * 8
            cetk.decrypted_titlekey = utils.Crypto.decrypt_titlekey(
                commonkey=cetk.get_decryption_key(),
                iv=cetk.titleiv,
                titlekey=cetk.hdr.titlekey
            )

        if onlyticket:
            print("Finished.")
            return
    else:
        print("* Downloading Ticket...")
        cetk = nus.ticket
        if not cetk:
            if pack_as_wad:
                print("    Ticket unavailable, can't pack nor verify.")
                pack_as_wad = False
            else:
                print("    Ticket unavailable, can't verify download.")
        else:
            cetk.dump(os.path.join(titlepath, "cetk"))

    if decryptcontents and not keepcontents and not cetk:
        print("Aborted, because contents should be deleted and decrypting is not possible.")
        return

    # Download Contents
    print("* Downloading Contents...")
    for i, content_url in enumerate(nus.get_content_urls()):
        print("    Content #{0} of #{1}: {2} ({3})".format(
            i + 1,
            tmd.hdr.contentcount,
            tmd.contents[i].get_cid(),
            utils.convert_size(tmd.contents[i].size))
        )
        content_path = os.path.join(titlepath, tmd.contents[i].get_cid())

        # Local Use
        if localuse and cetk:
            if os.path.isfile(content_path):
                with open(content_path, "rb") as content_file:
                    valid, decdata = utils.Crypto.check_content_hash(tmd.contents[i], cetk, content_file.read(),
                                                                     return_decdata=True)
                    if valid:
                        print("      Content exists and has been verified!")
                        if decryptcontents:
                            print("      Decrypting...")
                            with open(content_path + ".app", "wb") as decrypted_content_file:
                                decrypted_content_file.write(decdata)
                        continue  # Go on with the next content
                    else:
                        print("      Content exists, but hash check failed - redownloading...")

        req = get(content_url)
        if req.status_code != 200:
            print("      Failed to download content")
            return

        # Verify after download
        if cetk:
            valid, decdata = utils.Crypto.check_content_hash(tmd.contents[i], cetk, req.content, return_decdata=True)
            if not valid:
                print("      Hash check failed.")
                return
            if decryptcontents:
                print("      Decrypting...")
                with open(content_path + ".app", "wb") as decrypted_content_file:
                    decrypted_content_file.write(decdata)

        with open(content_path, 'wb') as content_file:
            content_file.write(req.content)

    # Pack as WAD
    if pack_as_wad:
        if not cetk.get_titleid().startswith("00030"):
            print("* Creating WAD...")
            wad_path = os.path.join(titlepath, "{0}-v{1}.wad".format(titleid, titlever))
            if cdndir:
                WADGEN.WADMaker(titlepath, titlever=titlever).dump(wad_path)
            else:
                WADGEN.WADMaker(titlepath).dump(wad_path)
            if not os.path.isfile(wad_path):
                print("    WAD creation failed.")
            else:
                print("    WAD creation successful: {0}".format(wad_path))
    else:
        print("Finished.")

    if not keepcontents:
        if cdndir:
            os.remove(os.path.join(titlepath, "tmd.{0}".format(titlever)))
        else:
            os.remove(os.path.join(titlepath, "tmd"))
        try:
            os.remove(os.path.join(titlepath, "cetk"))
        except FileNotFoundError:
            pass
        for content in tmd.contents:
            os.remove(os.path.join(titlepath, content.get_cid()))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('titleid', type=str, help="Title ID")
    parser.add_argument('titleversion', type=int, default=None, nargs="?", help="Title version (default: Latest)")
    parser.add_argument(
        '--nopack',
        action='store_false',
        default=True,
        dest='pack_as_wad',
        help='Do not generate WAD'
    )
    parser.add_argument(
        '--decrypt',
        action='store_true',
        default=False,
        dest='decryptcontents',
        help='Create decrypted contents (*.app)'
    )
    parser.add_argument(
        '--deletecontents',
        action='store_false',
        default=True,
        dest='keepcontents',
        help='Do not keep contents'
    )
    parser.add_argument(
        '--nolocaluse',
        action='store_false',
        default=True,
        dest='localuse',
        help='Don\'t use local files (SHA1 sum verifying)'
    )
    parser.add_argument(
        '--key',
        default=None,
        type=str,
        dest='encrypted_key',
        help='Encrypted title key for Ticket generation'
    )
    parser.add_argument(
        '--onlyticket',
        action='store_true',
        default=False,
        dest='onlyticket',
        help='Only create the ticket, don\'t store anything'
    )
    parser.add_argument(
        '--cdn',
        action='store_true',
        default=False,
        dest='cdndir',
        help='Store contents like on CDN (without version directory)'
    )
    parser.add_argument(
        '--base',
        default="http://nus.cdn.shop.wii.com/ccs/download",
        type=str,
        dest='base_url',
        help='Base URL for CDN download'
    )
    arguments = parser.parse_args()
    main(
        titleid=arguments.titleid,
        titlever=arguments.titleversion,
        pack_as_wad=arguments.pack_as_wad,
        keepcontents=arguments.keepcontents,
        decryptcontents=arguments.decryptcontents,
        localuse=arguments.localuse,
        enc_titlekey=arguments.encrypted_key,
        onlyticket=arguments.onlyticket,
        cdndir=arguments.cdndir,
        base_url=arguments.base_url
    )
