# Tests for the Matter protocol dissector
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Matter protocol dissector tests

Tests for:
1. TLV dissector: UTF-8 strings, float/double, tag forms 2-7, recursion guard
2. Protocol dissection: opcode name resolution, protocol ID names,
   message extensions, application payload TLV parsing, return value fix
"""

import struct
import subprocess

import pytest


def _make_matter_packet(proto_id=0x0000, opcode=0x01, sec_flags=0x00,
                        exch_flags=0x05, tlv_bytes=b'', ext_data=None):
    """Build an unsecured Matter packet with the given parameters."""
    header = bytes([
        0x00,                       # message flags
        0x00, 0x00,                 # session ID (unsecured)
        sec_flags,                  # security flags
        0x01, 0x00, 0x00, 0x00,    # message counter
    ])
    if ext_data is not None:
        ext_len = len(ext_data)
        header += struct.pack('<H', ext_len) + ext_data
    exchange = bytes([
        exch_flags,                 # exchange flags
        opcode,                     # opcode
        0x00, 0x00,                 # exchange ID
    ]) + struct.pack('<H', proto_id)  # protocol ID
    return header + exchange + tlv_bytes


# Default header for simple TLV-only tests
_MATTER_HEADER = _make_matter_packet()


def _tshark_fields(cmd_tshark, cmd_text2pcap, test_env, result_file, packet_bytes, fields):
    """Write a raw packet to pcap and extract field values via tshark."""
    hex_dump = "000000 " + " ".join(f"{b:02x}" for b in packet_bytes)

    text_file = result_file('matter_test.txt')
    pcap_file = result_file('matter_test.pcapng')

    with open(text_file, 'w') as f:
        f.write(hex_dump + "\n")

    subprocess.check_call(
        (cmd_text2pcap, '-u', '1234,5678', text_file, pcap_file),
        env=test_env,
    )

    args = [cmd_tshark, '-r', pcap_file, '-d', 'udp.port==1234,matter', '-T', 'fields']
    for field in fields:
        args.extend(['-e', field])

    result = subprocess.run(
        args, capture_output=True, check=True, encoding='utf-8', env=test_env,
    )

    values = result.stdout.strip().split('\t')
    if len(values) == 1 and values[0] == '':
        values = [''] * len(fields)
    return dict(zip(fields, values))


def _tshark_tlv_fields(cmd_tshark, cmd_text2pcap, test_env, result_file, tlv_bytes, fields):
    """Wrap TLV bytes in an unsecured Matter packet and extract field values via tshark."""
    packet = _MATTER_HEADER + tlv_bytes
    return _tshark_fields(cmd_tshark, cmd_text2pcap, test_env, result_file, packet, fields)


def _tshark_exitcode(cmd_tshark, cmd_text2pcap, test_env, result_file, packet_bytes):
    """Write a raw packet to pcap and return tshark's exit code."""
    hex_dump = "000000 " + " ".join(f"{b:02x}" for b in packet_bytes)

    text_file = result_file('matter_test.txt')
    pcap_file = result_file('matter_test.pcapng')

    with open(text_file, 'w') as f:
        f.write(hex_dump + "\n")

    subprocess.check_call(
        (cmd_text2pcap, '-u', '1234,5678', text_file, pcap_file),
        env=test_env,
    )

    result = subprocess.run(
        (cmd_tshark, '-r', pcap_file, '-d', 'udp.port==1234,matter'),
        capture_output=True, encoding='utf-8', env=test_env,
    )
    return result.returncode


def _tshark_tlv_exitcode(cmd_tshark, cmd_text2pcap, test_env, result_file, tlv_bytes):
    """Wrap TLV bytes in an unsecured Matter packet and return tshark's exit code."""
    packet = _MATTER_HEADER + tlv_bytes
    return _tshark_exitcode(cmd_tshark, cmd_text2pcap, test_env, result_file, packet)


class TestMatterTlv:
    """Tests for Matter TLV dissector improvements."""

    # ── UTF-8 string support (element types 0x0C–0x0F) ───────────────

    def test_utf8_string_1byte_length(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UTF-8 string with 1-byte length prefix."""
        # Control 0x0C = anonymous + UTF-8 string (1-byte length)
        tlv = bytes([0x0C, 0x05]) + b"Hello"
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_string'])
        assert result['matter.tlv.value_string'] == 'Hello'

    def test_utf8_string_empty(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UTF-8 string with zero length."""
        tlv = bytes([0x0C, 0x00])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_string'])
        assert result['matter.tlv.value_string'] == ''

    def test_utf8_string_unicode(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UTF-8 string with multi-byte Unicode characters."""
        text = "caf\u00e9"
        encoded = text.encode('utf-8')
        tlv = bytes([0x0C, len(encoded)]) + encoded
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_string'])
        assert result['matter.tlv.value_string'] == text

    def test_utf8_string_with_context_tag(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UTF-8 string with context-specific tag."""
        # Control 0x2C = context tag (form 1) + UTF-8 string (1-byte length)
        # Tag number: 5
        tlv = bytes([0x2C, 0x05, 0x03]) + b"abc"
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_string', 'matter.tlv.tag'])
        assert result['matter.tlv.value_string'] == 'abc'
        assert result['matter.tlv.tag'] == '0x00000005'

    # ── Float and double support (element types 0x0A, 0x0B) ──────────

    def test_float_pi(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """IEEE 754 single-precision float: pi."""
        # Control 0x0A = anonymous + float
        tlv = bytes([0x0A]) + struct.pack('<f', 3.14159274)
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_float'])
        assert float(result['matter.tlv.value_float']) == pytest.approx(3.14159274, rel=1e-6)

    def test_float_zero(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """IEEE 754 float zero."""
        tlv = bytes([0x0A]) + struct.pack('<f', 0.0)
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_float'])
        assert float(result['matter.tlv.value_float']) == 0.0

    def test_float_negative(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """IEEE 754 float with negative value."""
        tlv = bytes([0x0A]) + struct.pack('<f', -1.5)
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_float'])
        assert float(result['matter.tlv.value_float']) == -1.5

    def test_double_pi(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """IEEE 754 double-precision float: pi."""
        # Control 0x0B = anonymous + double
        tlv = bytes([0x0B]) + struct.pack('<d', 3.14159265358979)
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_double'])
        assert float(result['matter.tlv.value_double']) == pytest.approx(3.14159265358979, rel=1e-6)

    def test_double_large(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """IEEE 754 double with large value."""
        tlv = bytes([0x0B]) + struct.pack('<d', 1.23456789e+100)
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_double'])
        assert float(result['matter.tlv.value_double']) == pytest.approx(1.23456789e+100, rel=1e-6)

    def test_double_negative(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """IEEE 754 double with negative value."""
        tlv = bytes([0x0B]) + struct.pack('<d', -273.15)
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_double'])
        assert float(result['matter.tlv.value_double']) == pytest.approx(-273.15, rel=1e-6)

    # ── Tag form 2: Common profile, 2-byte tag ───────────────────────

    def test_tag_form2_common_profile_16bit(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Tag form 2: Common profile, 2-byte tag number."""
        # Control 0x44 = tag form 2 (010) + uint8 (00100)
        # Tag: 0x1234 (LE: 34 12), Value: 42
        tlv = bytes([0x44, 0x34, 0x12, 0x2A])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.tag', 'matter.tlv.tag_number', 'matter.tlv.value_uint'])
        assert result['matter.tlv.control.tag'] == '0x02'
        assert result['matter.tlv.tag_number'] == '4660'
        assert result['matter.tlv.value_uint'] == '42'

    # ── Tag form 3: Common profile, 4-byte tag ───────────────────────

    def test_tag_form3_common_profile_32bit(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Tag form 3: Common profile, 4-byte tag number."""
        # Control 0x64 = tag form 3 (011) + uint8 (00100)
        # Tag: 0x00012345 (LE: 45 23 01 00), Value: 99
        tlv = bytes([0x64, 0x45, 0x23, 0x01, 0x00, 0x63])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.tag', 'matter.tlv.tag_number32', 'matter.tlv.value_uint'])
        assert result['matter.tlv.control.tag'] == '0x03'
        assert result['matter.tlv.tag_number32'] == '74565'
        assert result['matter.tlv.value_uint'] == '99'

    # ── Tag form 4: Implicit profile, 2-byte tag ─────────────────────

    def test_tag_form4_implicit_profile_16bit(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Tag form 4: Implicit profile, 2-byte tag number."""
        # Control 0x84 = tag form 4 (100) + uint8 (00100)
        # Tag: 0x0042 (LE: 42 00), Value: 7
        tlv = bytes([0x84, 0x42, 0x00, 0x07])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.tag', 'matter.tlv.tag_number', 'matter.tlv.value_uint'])
        assert result['matter.tlv.control.tag'] == '0x04'
        assert result['matter.tlv.tag_number'] == '66'
        assert result['matter.tlv.value_uint'] == '7'

    # ── Tag form 5: Implicit profile, 4-byte tag ─────────────────────

    def test_tag_form5_implicit_profile_32bit(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Tag form 5: Implicit profile, 4-byte tag number."""
        # Control 0xA4 = tag form 5 (101) + uint8 (00100)
        # Tag: 0x00ABCDEF (LE: EF CD AB 00), Value: 1
        tlv = bytes([0xA4, 0xEF, 0xCD, 0xAB, 0x00, 0x01])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.tag', 'matter.tlv.tag_number32', 'matter.tlv.value_uint'])
        assert result['matter.tlv.control.tag'] == '0x05'
        assert result['matter.tlv.tag_number32'] == '11259375'
        assert result['matter.tlv.value_uint'] == '1'

    # ── Tag form 6: Fully-qualified, 6-byte tag ──────────────────────

    def test_tag_form6_fully_qualified_16bit(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Tag form 6: Fully-qualified tag (vendor + profile + 2-byte tag)."""
        # Control 0xC4 = tag form 6 (110) + uint8 (00100)
        # Vendor: 1, Profile: 2, Tag: 3, Value: 42
        tlv = bytes([0xC4, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x2A])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.tag', 'matter.tlv.tag_vendor',
                   'matter.tlv.tag_profile', 'matter.tlv.tag_number', 'matter.tlv.value_uint'])
        assert result['matter.tlv.control.tag'] == '0x06'
        assert result['matter.tlv.tag_vendor'] == '0x0001'
        assert result['matter.tlv.tag_profile'] == '0x0002'
        assert result['matter.tlv.tag_number'] == '3'
        assert result['matter.tlv.value_uint'] == '42'

    # ── Tag form 7: Fully-qualified, 8-byte tag ──────────────────────

    def test_tag_form7_fully_qualified_32bit(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Tag form 7: Fully-qualified tag (vendor + profile + 4-byte tag)."""
        # Control 0xE4 = tag form 7 (111) + uint8 (00100)
        # Vendor: 1, Profile: 2, Tag: 0x00010003 (LE: 03 00 01 00), Value: 42
        tlv = bytes([0xE4, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x2A])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.tag', 'matter.tlv.tag_vendor',
                   'matter.tlv.tag_profile', 'matter.tlv.tag_number32', 'matter.tlv.value_uint'])
        assert result['matter.tlv.control.tag'] == '0x07'
        assert result['matter.tlv.tag_vendor'] == '0x0001'
        assert result['matter.tlv.tag_profile'] == '0x0002'
        assert result['matter.tlv.tag_number32'] == '65539'
        assert result['matter.tlv.value_uint'] == '42'

    # ── Recursion depth guard ─────────────────────────────────────────

    def test_recursion_guard_deep_nesting(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """200 nested structures must not crash tshark."""
        depth = 200
        tlv = bytes([0x15] * depth + [0x18] * depth)
        rc = _tshark_tlv_exitcode(
            cmd_tshark, cmd_text2pcap, test_env, result_file, tlv)
        assert rc == 0

    def test_recursion_guard_nested_with_data(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Nested structures with a leaf value should parse correctly."""
        # Structure { Structure { uint8 = 42 } }
        tlv = bytes([
            0x15,               # structure open
            0x15,               # nested structure open
            0x04, 0x2A,         # anonymous uint8 = 42
            0x18,               # end of container (inner)
            0x18,               # end of container (outer)
        ])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_uint'])
        assert result['matter.tlv.value_uint'] == '42'


class TestMatterProtocol:
    """Tests for Matter protocol dissection enhancements."""

    # ── Protocol ID and opcode name resolution ────────────────────────

    def test_secure_channel_opcode_named(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Secure Channel known opcode shows name in info column."""
        # Protocol 0x0000 (Secure Channel), opcode 0x20 (MRP Standalone Acknowledgement)
        pkt = _make_matter_packet(proto_id=0x0000, opcode=0x20)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Secure Channel: MRP Standalone Acknowledgement' in result['_ws.col.info']

    def test_secure_channel_sigma1(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Secure Channel CASE Sigma1 opcode."""
        pkt = _make_matter_packet(proto_id=0x0000, opcode=0x60)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Secure Channel: CASE Sigma1' in result['_ws.col.info']

    def test_im_read_request(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Interaction Model ReadRequest opcode."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x02)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Interaction Model: ReadRequest' in result['_ws.col.info']

    def test_im_subscribe_request(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Interaction Model SubscribeRequest opcode."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x03)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Interaction Model: SubscribeRequest' in result['_ws.col.info']

    def test_im_invoke_request(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Interaction Model InvokeRequest opcode."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x08)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Interaction Model: InvokeRequest' in result['_ws.col.info']

    def test_bdx_send_init(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """BDX SendInit opcode."""
        pkt = _make_matter_packet(proto_id=0x0002, opcode=0x01)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'BDX (Bulk Data Exchange): SendInit' in result['_ws.col.info']

    def test_udc_identification(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UDC IdentificationDeclaration opcode."""
        pkt = _make_matter_packet(proto_id=0x0003, opcode=0x00)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'User Directed Commissioning: IdentificationDeclaration' in result['_ws.col.info']

    def test_unknown_protocol_shows_opcode_hex(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Unknown protocol ID falls back to hex opcode display."""
        pkt = _make_matter_packet(proto_id=0x00FF, opcode=0xAB)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Unknown: Opcode=0xab' in result['_ws.col.info']

    def test_unknown_opcode_in_known_protocol(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Known protocol with unrecognized opcode falls back to hex."""
        # Secure Channel with opcode 0xFF (not in lookup table)
        pkt = _make_matter_packet(proto_id=0x0000, opcode=0xFF)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Secure Channel: Opcode=0xff' in result['_ws.col.info']

    def test_protocol_id_value_string(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Protocol ID field uses value_string for name resolution."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x05)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['matter.payload.protocol_id'])
        # FT_UINT16 BASE_HEX with VALS — shown as "0x0001"
        assert result['matter.payload.protocol_id'] == '0x0001'

    # ── Application payload TLV dissection ────────────────────────────

    def test_application_payload_tlv(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Application payload is parsed as TLV."""
        tlv = bytes([0x04, 0x2A])  # anonymous uint8 = 42
        pkt = _make_matter_packet(tlv_bytes=tlv)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['matter.tlv.value_uint'])
        assert result['matter.tlv.value_uint'] == '42'

    # ── Message Extensions ────────────────────────────────────────────

    def test_message_extensions(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Message extensions are parsed when has_extensions flag is set."""
        # sec_flags=0x20 sets SECURITY_FLAG_HAS_EXTENSIONS
        pkt = _make_matter_packet(sec_flags=0x20, ext_data=bytes([0xAA, 0xBB, 0xCC]))
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['matter.message.ext_length', 'matter.message.ext_data'])
        assert result['matter.message.ext_length'] == '3'
        assert result['matter.message.ext_data'] == 'aabbcc'

    def test_message_extensions_empty(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Message extensions with zero-length data."""
        pkt = _make_matter_packet(sec_flags=0x20, ext_data=b'')
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['matter.message.ext_length'])
        assert result['matter.message.ext_length'] == '0'

    def test_no_extensions_flag(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Without extensions flag, ext fields are absent."""
        pkt = _make_matter_packet(sec_flags=0x00)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['matter.message.ext_length'])
        assert result['matter.message.ext_length'] == ''

    # ── Return value fix ──────────────────────────────────────────────

    def test_dissect_returns_full_length(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """dissect_matter() consumes the full packet (no leftover Data protocol)."""
        tlv = bytes([0x04, 0x2A])
        pkt = _make_matter_packet(tlv_bytes=tlv)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['frame.protocols'])
        protocols = result['frame.protocols']
        assert 'matter' in protocols
        # "data" protocol would appear if dissect_matter() didn't consume all bytes
        assert ':data' not in protocols
