# Tests for the Matter protocol dissector
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Matter protocol dissector tests

Tests for:
1. TLV dissector: UTF-8 strings, float/double, tag forms 2-7, recursion guard
2. Protocol dissection: opcode name resolution, protocol ID names,
   message extensions, application payload TLV parsing, return value fix
3. Heuristic UDP dissector and default port 5540
4. CASE/PASE session decryption via UAT preferences
"""

import struct
import subprocess

import pytest


def _make_matter_packet(proto_id=0x0000, opcode=0x01, sec_flags=0x00,
                        exch_flags=0x05, tlv_bytes=b'', ext_data=None,
                        session_id=0, counter=1, msg_flags=None,
                        source_node_id=None, dest_node_id=None,
                        dest_group_id=None, exchange_id=0, ack_counter=None):
    """Build an unsecured Matter packet with the given parameters."""
    # Build message flags
    if msg_flags is not None:
        mf = msg_flags
    else:
        mf = 0x00
        if source_node_id is not None:
            mf |= 0x04  # S flag
        if dest_node_id is not None:
            mf |= 0x01  # DSIZ = 01 (node64)
        elif dest_group_id is not None:
            mf |= 0x02  # DSIZ = 10 (group)

    sec = sec_flags & 0xFF
    if ext_data is not None:
        sec |= 0x20  # has_extensions

    header = struct.pack('<B', mf)
    header += struct.pack('<H', session_id)
    header += struct.pack('<B', sec)
    header += struct.pack('<I', counter)

    if source_node_id is not None:
        header += struct.pack('<Q', source_node_id)
    if dest_node_id is not None:
        header += struct.pack('<Q', dest_node_id)
    elif dest_group_id is not None:
        header += struct.pack('<H', dest_group_id)

    if ext_data is not None:
        header += struct.pack('<H', len(ext_data)) + ext_data

    # Build exchange header
    ef = exch_flags
    if ack_counter is not None:
        ef |= 0x02  # ACK flag
    exchange = bytes([ef, opcode])
    exchange += struct.pack('<H', exchange_id)
    exchange += struct.pack('<H', proto_id)
    if ack_counter is not None:
        exchange += struct.pack('<I', ack_counter)

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

    # ── Additional TLV element types ──────────────────────────────────

    def test_tlv_signed_int_negative(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """TLV signed 8-bit integer, context-specific tag, value -1."""
        # control=0x20 (context tag, type=int8), tag=0x05, value=0xFF (-1)
        tlv = bytes([0x20, 0x05, 0xFF])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_int'])
        assert result['matter.tlv.value_int'] == '-1'

    def test_tlv_octet_string(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """TLV octet string, context-specific tag."""
        # control=0x30 (context tag, type=octet string 1-byte len)
        # tag=0x03, length=0x03, data=0xDE 0xAD 0xFF
        tlv = bytes([0x30, 0x03, 0x03, 0xDE, 0xAD, 0xFF])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.value_bytes', 'matter.tlv.length'])
        assert result['matter.tlv.value_bytes'] == 'deadff'
        assert result['matter.tlv.length'] == '3'

    def test_tlv_boolean_true(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """TLV boolean true (element type 0x09)."""
        # control=0x29 (context tag, type=bool true), tag=0x03
        tlv = bytes([0x29, 0x03])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.element'])
        assert result['matter.tlv.control.element'] == '0x09'

    def test_tlv_null(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """TLV null value (element type 0x14)."""
        # control=0x34 (context tag, type=null), tag=0x10
        tlv = bytes([0x34, 0x10])
        result = _tshark_tlv_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            tlv, ['matter.tlv.control.element'])
        assert result['matter.tlv.control.element'] == '0x14'


class TestMatterProtocol:
    """Tests for Matter protocol dissection enhancements."""

    # ── Basic message header parsing ──────────────────────────────────

    def test_minimal_unsecured_header(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Minimal unsecured message: no source, no dest, session 0."""
        pkt = _make_matter_packet(session_id=0, counter=42)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt,
            ['matter.message.version',
             'matter.message.session_id',
             'matter.message.counter',
             'matter.message.dsiz',
             'matter.message.has_source_id'])
        assert result['matter.message.version'] == '0'
        assert result['matter.message.session_id'] == '0x0000'
        assert result['matter.message.counter'] == '42'
        assert result['matter.message.dsiz'] == '0'
        assert result['matter.message.has_source_id'] in ('False', '0')

    def test_source_and_dest_node_ids(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Message with both source and destination node IDs."""
        pkt = _make_matter_packet(
            session_id=0, counter=400,
            source_node_id=1, dest_node_id=2,
            proto_id=0x0001, opcode=0x01)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt,
            ['matter.message.has_source_id',
             'matter.message.dsiz',
             'matter.message.src_id',
             'matter.message.dest_node_id'])
        assert result['matter.message.has_source_id'] in ('True', '1')
        assert result['matter.message.dsiz'] == '1'
        assert result['matter.message.src_id'] != ''
        assert result['matter.message.dest_node_id'] != ''

    def test_control_flag(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Control flag (0x40) in security flags byte."""
        pkt = _make_matter_packet(session_id=0, counter=500, sec_flags=0x40)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt,
            ['matter.message.is_control',
             'matter.message.has_privacy',
             'matter.message.session_type'])
        assert result['matter.message.is_control'] in ('True', '1')
        assert result['matter.message.has_privacy'] in ('False', '0')
        assert result['matter.message.session_type'] == '0x00'

    def test_exchange_header_fields(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Exchange flags, opcode, exchange ID and protocol ID are decoded."""
        pkt = _make_matter_packet(
            session_id=0, counter=600,
            exch_flags=0x05,   # initiator + reliability
            opcode=0x30,       # Sigma1
            exchange_id=0xBEEF,
            proto_id=0x0000)   # Secure Channel
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt,
            ['matter.payload.exchange_flags',
             'matter.payload.initiator',
             'matter.payload.reliability',
             'matter.payload.protocol_opcode',
             'matter.payload.exchange_id',
             'matter.payload.protocol_id'])
        assert result['matter.payload.exchange_flags'] == '0x05'
        assert result['matter.payload.initiator'] in ('True', '1')
        assert result['matter.payload.reliability'] in ('True', '1')
        assert result['matter.payload.protocol_opcode'] == '0x30'
        assert result['matter.payload.exchange_id'] == '0xbeef'
        assert result['matter.payload.protocol_id'] == '0x0000'

    def test_ack_counter(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Acknowledged message counter field when ACK flag set."""
        pkt = _make_matter_packet(
            session_id=0, counter=700,
            exch_flags=0x01, opcode=0x05,
            exchange_id=0x0001, proto_id=0x0001,
            ack_counter=999)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt,
            ['matter.payload.ack_msg',
             'matter.payload.ack_counter'])
        assert result['matter.payload.ack_msg'] in ('True', '1')
        assert result['matter.payload.ack_counter'] == '999'

    def test_rejects_short_packet(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Packets shorter than 8 bytes should not be decoded as Matter."""
        short_pkt = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])  # 7 bytes
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file, short_pkt,
            ['matter.message.counter'])
        assert result['matter.message.counter'] == ''

    # ── Protocol ID and opcode name resolution ────────────────────────

    def test_secure_channel_opcode_named(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Secure Channel known opcode shows name in info column."""
        # Protocol 0x0000 (Secure Channel), opcode 0x20 (MRP Standalone Acknowledgement)
        pkt = _make_matter_packet(proto_id=0x0000, opcode=0x20)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'MRP Standalone Acknowledgement' in result['_ws.col.info']

    def test_secure_channel_sigma1(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Secure Channel CASE Sigma1 opcode."""
        pkt = _make_matter_packet(proto_id=0x0000, opcode=0x60)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'CASE Sigma1' in result['_ws.col.info']

    def test_im_read_request(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Interaction Model ReadRequest opcode."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x02)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'ReadRequest' in result['_ws.col.info']

    def test_im_subscribe_request(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Interaction Model SubscribeRequest opcode."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x03)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'SubscribeRequest' in result['_ws.col.info']

    def test_im_invoke_request(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Interaction Model InvokeRequest opcode."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x08)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'InvokeRequest' in result['_ws.col.info']

    def test_bdx_send_init(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """BDX SendInit opcode."""
        pkt = _make_matter_packet(proto_id=0x0002, opcode=0x01)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'SendInit' in result['_ws.col.info']

    def test_udc_identification(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UDC IdentificationDeclaration opcode."""
        pkt = _make_matter_packet(proto_id=0x0003, opcode=0x00)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'IdentificationDeclaration' in result['_ws.col.info']

    def test_unknown_protocol_shows_opcode_hex(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Unknown protocol ID falls back to hex opcode display."""
        pkt = _make_matter_packet(proto_id=0x00FF, opcode=0xAB)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Unknown: Opcode 0xab' in result['_ws.col.info']

    def test_unknown_opcode_in_known_protocol(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Known protocol with unrecognized opcode falls back to hex."""
        # Secure Channel with opcode 0xFF (not in lookup table)
        pkt = _make_matter_packet(proto_id=0x0000, opcode=0xFF)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert 'Secure Channel: Opcode 0xff' in result['_ws.col.info']

    def test_info_column_shows_cluster_name(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Info column appends cluster name when TLV contains a Cluster field."""
        # ReadRequest (proto=0x0001, opcode=0x02) with TLV:
        # Structure { tag0: Array [ Structure { tag3: uint8(6) } ] }
        # Tag 3 in ATTRIBUTE_PATH context = "Cluster", value 6 = OnOff
        tlv = bytes.fromhex('15 36 00 15 24 03 06 18 18 18'.replace(' ', ''))
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x02, tlv_bytes=tlv)
        result = _tshark_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['_ws.col.info'])
        assert result['_ws.col.info'] == 'ReadRequest (OnOff)'

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


# ─── Helpers for heuristic / default-port tests ──────────────────────


def _tshark_heur_fields(cmd_tshark, cmd_text2pcap, test_env, result_file,
                        packet_bytes, fields, src_port=1234, dst_port=5678):
    """Write a raw packet to pcap and extract field values via tshark.

    Unlike _tshark_fields this does NOT use ``-d udp.port==...,matter``,
    so the dissector is only invoked via port-based registration (5540) or
    the heuristic dissector.
    """
    hex_dump = "000000 " + " ".join(f"{b:02x}" for b in packet_bytes)

    text_file = result_file('matter_heur_test.txt')
    pcap_file = result_file('matter_heur_test.pcapng')

    with open(text_file, 'w') as f:
        f.write(hex_dump + "\n")

    subprocess.check_call(
        (cmd_text2pcap, '-u', f'{src_port},{dst_port}', text_file, pcap_file),
        env=test_env,
    )

    args = [cmd_tshark, '-r', pcap_file, '-T', 'fields']
    for field in fields:
        args.extend(['-e', field])

    result = subprocess.run(
        args, capture_output=True, check=True, encoding='utf-8', env=test_env,
    )

    values = result.stdout.strip().split('\t')
    if len(values) == 1 and values[0] == '':
        values = [''] * len(fields)
    return dict(zip(fields, values))


def _heur_is_matter(cmd_tshark, cmd_text2pcap, test_env, result_file,
                    packet_bytes, src_port=1234, dst_port=5678):
    """Return True if tshark recognises *packet_bytes* as Matter.

    Uses a non-standard port pair and no decode-as override so that
    recognition depends entirely on the heuristic (or default port).
    """
    result = _tshark_heur_fields(
        cmd_tshark, cmd_text2pcap, test_env, result_file,
        packet_bytes, ['frame.protocols'], src_port=src_port, dst_port=dst_port)
    return 'matter' in result.get('frame.protocols', '')


class TestMatterHeuristic:
    """Tests for default port registration and heuristic UDP dissector (MR3)."""

    # ── Default port 5540 ─────────────────────────────────────────────

    def test_default_port_5540(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Traffic to port 5540 is auto-dissected as Matter without decode-as."""
        pkt = _make_matter_packet()
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, dst_port=5540)

    def test_default_port_5540_fields(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Fields are properly decoded on the default port."""
        pkt = _make_matter_packet(proto_id=0x0001, opcode=0x01)
        result = _tshark_heur_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            pkt, ['matter.payload.protocol_id'], dst_port=5540)
        assert result['matter.payload.protocol_id'] == '0x0001'

    # ── Heuristic: positive matches ───────────────────────────────────

    def test_heur_unsecured_proto_secure_channel(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches unsecured session with Secure Channel protocol (0x0000)."""
        pkt = _make_matter_packet(proto_id=0x0000)
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_unsecured_proto_im(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches unsecured session with Interaction Model protocol (0x0001)."""
        pkt = _make_matter_packet(proto_id=0x0001)
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_unsecured_proto_bdx(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches unsecured session with BDX protocol (0x0002)."""
        pkt = _make_matter_packet(proto_id=0x0002)
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_unsecured_proto_udc(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches unsecured session with UDC protocol (0x0003)."""
        pkt = _make_matter_packet(proto_id=0x0003)
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_with_source_node_id(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches when source node ID is present (has_source flag)."""
        # message_flags bit 2 = has_source, adds 8 bytes for source node ID
        header = bytes([
            0x04,                       # message flags: has_source=1, dsiz=0
            0x00, 0x00,                 # session ID (unsecured)
            0x00,                       # security flags
            0x01, 0x00, 0x00, 0x00,    # message counter
            0x01, 0x02, 0x03, 0x04,    # source node ID (8 bytes)
            0x05, 0x06, 0x07, 0x08,
        ])
        exchange = bytes([
            0x05,                       # exchange flags (initiator + reliable)
            0x01,                       # opcode
            0x00, 0x00,                 # exchange ID
        ]) + struct.pack('<H', 0x0000)  # protocol ID: Secure Channel
        pkt = header + exchange
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_with_dsiz_group(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches with DSIZ=1 (16-bit group destination)."""
        header = bytes([
            0x01,                       # message flags: dsiz=1 (group)
            0x00, 0x00,                 # session ID (unsecured)
            0x00,                       # security flags
            0x01, 0x00, 0x00, 0x00,    # message counter
            0x00, 0x01,                 # 16-bit group ID
        ])
        exchange = bytes([
            0x05, 0x01, 0x00, 0x00,
        ]) + struct.pack('<H', 0x0001)
        pkt = header + exchange
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_with_dsiz_node64(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Heuristic matches with DSIZ=3 (64-bit node destination)."""
        header = bytes([
            0x03,                       # message flags: dsiz=3 (64-bit node)
            0x00, 0x00,                 # session ID (unsecured)
            0x00,                       # security flags
            0x01, 0x00, 0x00, 0x00,    # message counter
        ]) + bytes(8)                   # 64-bit destination node ID
        exchange = bytes([
            0x05, 0x01, 0x00, 0x00,
        ]) + struct.pack('<H', 0x0000)
        pkt = header + exchange
        assert _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    # ── Heuristic: rejection cases ────────────────────────────────────

    def test_heur_rejects_too_short(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Packets shorter than 8 bytes are not claimed."""
        pkt = bytes(7)  # too short
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_rejects_bad_version(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Non-zero version field (bits 4-7) causes rejection."""
        pkt = bytearray(_make_matter_packet())
        pkt[0] = 0x10  # version=1 in bits 4-7
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, bytes(pkt))

    def test_heur_rejects_reserved_msg_flag(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Reserved bit 3 of message flags causes rejection."""
        pkt = bytearray(_make_matter_packet())
        pkt[0] = 0x08  # reserved bit 3
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, bytes(pkt))

    def test_heur_rejects_bad_session_type(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Session type > 1 causes rejection."""
        pkt = bytearray(_make_matter_packet())
        pkt[3] = 0x02  # session_type = 2 (invalid)
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, bytes(pkt))

    def test_heur_rejects_reserved_security_bits(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Reserved bits 2-4 of security flags cause rejection."""
        pkt = bytearray(_make_matter_packet())
        pkt[3] = 0x04  # bit 2 set (reserved)
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, bytes(pkt))

    def test_heur_rejects_secured_session(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Secured sessions (non-zero session_id) are not claimed heuristically."""
        pkt = bytearray(_make_matter_packet())
        pkt[1] = 0x01  # session_id = 1 (non-zero → secured)
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, bytes(pkt))

    def test_heur_rejects_unknown_proto_id(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Protocol ID > 3 causes rejection."""
        pkt = _make_matter_packet(proto_id=0x0004)
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_rejects_truncated_exchange(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Packet with valid header but truncated exchange header is rejected."""
        # Just the 8-byte message header, no exchange header at all
        pkt = bytes([
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ])
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)

    def test_heur_rejects_dsiz_length_mismatch(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Packet too short for the declared DSIZ is rejected."""
        # dsiz=3 (64-bit node) requires 8+8=16 bytes minimum header,
        # but we only provide 10 bytes
        pkt = bytes([
            0x03,                       # dsiz=3
            0x00, 0x00,                 # session ID
            0x00,                       # security flags
            0x01, 0x00, 0x00, 0x00,    # counter
            0x00, 0x00,                 # only 2 bytes of dest (need 8)
        ])
        assert not _heur_is_matter(
            cmd_tshark, cmd_text2pcap, test_env, result_file, pkt)


# ─── Helpers for decryption tests ─────────────────────────────────────
#
# Pre-computed AES-128-CCM encrypted Matter packets.
#
# All packets were encrypted with:
#   KEY = 000102030405060708090a0b0c0d0e0f (16 bytes)
#   tag_length = 16 (MATTER_MIC_LEN)
#   nonce = security_flags(1) || counter(4 LE) || source_node_id(8 LE)
#   AAD = raw message header bytes
#
# Plaintext is an exchange header: flags(1)+opcode(1)+exchange_id(2)+proto_id(2)
# optionally followed by TLV application data.

# session_id=0x002A, counter=1, proto_id=0x0001, opcode=0x01
_ENC_PKT_BASIC = bytes.fromhex(
    '002a0000010000003c468e1c9ba587642a6965cc57585f48c5b011ea8d94')

# same as BASIC but plaintext also has TLV uint8=42 (0x04 0x2A)
_ENC_PKT_TLV = bytes.fromhex(
    '002a0000010000003c468e1c9ba5383e0b1b6b7c9b70b357a04e3baf53a89077')

# session_id=0x002A, has_source=1, source_node_id=0xAABBCCDD11223344
_ENC_PKT_SRC_NODE = bytes.fromhex(
    '042a00000100000044332211ddccbbaa'
    '8ed07003d46214f8d0214cf152369bd3a0c01c606a91')

# session_id=100 (0x0064), counter=1, proto_id=0x0001, opcode=0x01
_ENC_PKT_SID100 = bytes.fromhex(
    '00640000010000003c468e1c9ba53d8d3edc8dd4af9279737599d7f3b58a')

# session_id=0x002A, has_source=1, source_node_id=0x1122334455667788
_ENC_PKT_INIT_NID = bytes.fromhex(
    '042a000001000000887766554433221'
    '1c2fcebdb5a590629801'
    '9c7b893662a56a7918f6a5f42')

_ENC_KEY_HEX = '000102030405060708090a0b0c0d0e0f'
_ENC_SESSION_ID = 0x002A


def _tshark_decrypt_fields(cmd_tshark, cmd_text2pcap, test_env, result_file,
                           packet_bytes, fields,
                           uat_entries=None, dst_port=5540):
    """Write encrypted packet to pcap and extract fields via tshark with decryption.

    Decryption keys are provided via uat_entries: a list of UAT row dicts
    with keys: initiator_node_id, responder_node_id, i2r_key, r2i_key
    """
    hex_dump = "000000 " + " ".join(f"{b:02x}" for b in packet_bytes)

    text_file = result_file('matter_decrypt_test.txt')
    pcap_file = result_file('matter_decrypt_test.pcapng')

    with open(text_file, 'w') as f:
        f.write(hex_dump + "\n")

    subprocess.check_call(
        (cmd_text2pcap, '-u', f'1234,{dst_port}', text_file, pcap_file),
        env=test_env,
    )

    args = [cmd_tshark, '-r', pcap_file, '-T', 'fields']
    for field in fields:
        args.extend(['-e', field])

    if uat_entries:
        for entry in uat_entries:
            init_nid = entry.get('initiator_node_id', '')
            resp_nid = entry.get('responder_node_id', '')
            i2r = entry.get('i2r_key', '')
            r2i = entry.get('r2i_key', '')
            uat_row = f'"{init_nid}","{resp_nid}","{i2r}","{r2i}"'
            args.extend(['-o', f'uat:matter_session_keys:{uat_row}'])

    result = subprocess.run(
        args, capture_output=True, check=True, encoding='utf-8', env=test_env,
    )

    values = result.stdout.strip().split('\t')
    if len(values) == 1 and values[0] == '':
        values = [''] * len(fields)
    return dict(zip(fields, values))


class TestMatterDecryption:
    """Tests for CASE/PASE session decryption (MR4)."""

    # ── UAT decryption ────────────────────────────────────────────────

    def test_decrypt_via_uat_i2r_key(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Decryption using I2R key from UAT succeeds."""
        uat = [{'i2r_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['_ws.col.Info'], uat_entries=uat)
        assert result['_ws.col.Info'] == 'StatusResponse'

    def test_decrypt_via_uat_r2i_key(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Decryption using R2I key from UAT succeeds."""
        uat = [{'r2i_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['_ws.col.Info'], uat_entries=uat)
        assert result['_ws.col.Info'] == 'StatusResponse'

    def test_decrypt_uat_with_node_ids(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """UAT with node IDs constructs correct nonce for decryption."""
        uat = [{'initiator_node_id': '0x1122334455667788',
                'i2r_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_INIT_NID, ['_ws.col.Info'], uat_entries=uat)
        assert result['_ws.col.Info'] == 'StatusResponse'

    def test_decrypt_uat_tries_both_keys(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """When both I2R and R2I are provided, the correct one is found."""
        uat = [{'i2r_key': '00' * 16,  # wrong key
                'r2i_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['_ws.col.Info'], uat_entries=uat)
        assert result['_ws.col.Info'] == 'StatusResponse'

    def test_decrypt_shows_protocol_id(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """After decryption, the exchange header protocol ID is decoded."""
        uat = [{'i2r_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['matter.payload.protocol_id'], uat_entries=uat)
        assert result['matter.payload.protocol_id'] == '0x0001'

    def test_decrypt_different_session_ids(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Keys are tried against all sessions regardless of session ID."""
        uat = [{'i2r_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_SID100, ['_ws.col.Info'], uat_entries=uat)
        assert result['_ws.col.Info'] == 'StatusResponse'

    # ── Expert info / failure cases ───────────────────────────────────

    def test_no_key_expert_info(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Without any key, expert info 'no_key' is present."""
        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['matter.decryption.no_key'])
        assert result['matter.decryption.no_key'] != ''

    def test_wrong_key_expert_info(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """With a wrong key, expert info 'failed' is present."""
        uat = [{'i2r_key': 'ff' * 16}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['matter.decryption.failed'], uat_entries=uat)
        assert result['matter.decryption.failed'] != ''

    def test_no_decrypted_col_without_key(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Without decryption, Info column shows session info, not opcode name."""
        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['_ws.col.Info'])
        assert 'Unicast Session' in result['_ws.col.Info']

    def test_mic_field_always_present(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """MIC field is shown for encrypted packets regardless of decryption."""
        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_BASIC, ['matter.payload.mic'])
        assert result['matter.payload.mic'] != ''

    # ── Decrypted payload TLV parsing ─────────────────────────────────

    def test_decrypt_tlv_in_payload(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """After decryption, TLV data in the payload is parsed."""
        uat = [{'i2r_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_TLV, ['matter.tlv.value_uint'], uat_entries=uat)
        assert result['matter.tlv.value_uint'] == '42'

    def test_decrypt_with_source_node_in_nonce(self, cmd_tshark, cmd_text2pcap, test_env, result_file):
        """Decryption works when source node ID is part of the nonce."""
        uat = [{'i2r_key': _ENC_KEY_HEX}]

        result = _tshark_decrypt_fields(
            cmd_tshark, cmd_text2pcap, test_env, result_file,
            _ENC_PKT_SRC_NODE, ['_ws.col.Info'], uat_entries=uat)
        assert result['_ws.col.Info'] == 'StatusResponse'
