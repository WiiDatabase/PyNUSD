import WADGEN


# Used TMD is IOS58
class TestTMD:
    def test_creation(self):
        obj = WADGEN.TMD()
        assert obj.get_titleid() == "0000000000000000"
        assert obj.get_titleversion() == 0

    def test_file(self):
        obj = WADGEN.TMD("tests/data/tmd")
        assert obj.get_titleid() == "000000010000003a"
        assert obj.get_titleversion() == 6176
        assert obj.get_issuers() == ["Root", "CA00000001", "CP00000004"]
        assert not obj.is_vwii_title()
        assert obj.get_type() == "System"
        assert obj.get_region() == "Japan"
        assert not obj.get_required_title()
        assert obj.get_content_count() == 19
        assert obj.get_boot_app() == "00000012"
        assert len(obj.get_contents()) == obj.get_content_count()
        assert obj.get_encrypted_content_size() == 1987136
        assert obj.get_decrypted_content_size() == 1986724
        assert obj.get_content_record_position_by_cid("0000000a") == 10
        assert obj.get_content_record_by_cid("0000000a").get_cid() == "0000000a"
        assert obj.get_cert_by_name("CA00000001").get_name() == "CA00000001"
        assert len(obj.get_certificates()) == 2

    def test_fakesign(self):
        obj = WADGEN.TMD("tests/data/tmd")
        obj.fakesign()
        sha1hash = WADGEN.utils.Crypto.create_sha1hash_hex(obj.pack(include_signature=False))
        assert sha1hash.startswith("00")
        assert obj.unused != 0

    def test_dumpload(self):
        obj = WADGEN.TMD("tests/data/tmd")
        dump = obj.pack(include_signature=True, include_certificates=True)
        sha1hash = WADGEN.utils.Crypto.create_sha1hash_hex(dump)

        newobj = WADGEN.TMD(dump)
        newdump = newobj.pack(include_signature=True, include_certificates=True)
        sha1hash_new = WADGEN.utils.Crypto.create_sha1hash_hex(newdump)

        assert sha1hash == sha1hash_new
