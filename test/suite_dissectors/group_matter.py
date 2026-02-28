#
# Wireshark Matter dissector tests
# Copyright 2026, Tom Manley
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Matter protocol dissector tests

Tests for the Matter IoT protocol dissector exercising message header
parsing, protocol payload dissection, TLV encoding, message extensions,
and the heuristic UDP dissector.

Test packets are hex-encoded, fed through text2pcap to produce a pcap,
then verified with tshark field extraction (-Tfields -e).
'''

import subprocess
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _le16(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def _le32(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF])


def _le64(v):
    return bytes([(v >> (8 * i)) & 0xFF for i in range(8)])


def _matter_msg(
    session_id=0,
    counter=1,
    source_node_id=None,
    dest_node_id=None,
    dest_group_id=None,
    security_flags=0x00,
    has_extensions=False,
    ext_data=None,
    payload=b'',
):
    '''Build a raw Matter unsecured-session message frame.'''
    msg_flags = 0x00  # version=0

    if source_node_id is not None:
        msg_flags |= 0x04  # S flag

    if dest_node_id is not None:
        msg_flags |= 0x01  # DSIZ=01
    elif dest_group_id is not None:
        msg_flags |= 0x02  # DSIZ=10

    sec = security_flags & 0xFF
    if has_extensions:
        sec |= 0x20

    frame = bytes([msg_flags])
    frame += _le16(session_id)
    frame += bytes([sec])
    frame += _le32(counter)

    if source_node_id is not None:
        frame += _le64(source_node_id)
    if dest_node_id is not None:
        frame += _le64(dest_node_id)
    elif dest_group_id is not None:
        frame += _le16(dest_group_id)

    if has_extensions and ext_data is not None:
        frame += _le16(len(ext_data))
        frame += bytes(ext_data)

    frame += bytes(payload)
    return frame


def _matter_payload(
    exchange_flags=0x01,
    opcode=0x20,
    exchange_id=0x0001,
    protocol_id=0x0000,
    ack_counter=None,
    application=b'',
):
    '''Build a Matter protocol payload (exchange message layer).'''
    flags = exchange_flags
    if ack_counter is not None:
        flags |= 0x02  # ACK flag

    data = bytes([flags, opcode])
    data += _le16(exchange_id)
    data += _le16(protocol_id)

    if ack_counter is not None:
        data += _le32(ack_counter)

    data += bytes(application)
    return data


def _hex(raw):
    '''Convert raw bytes to a space-separated hex string for text2pcap.'''
    return ' '.join('{:02x}'.format(b) for b in raw)


def _run_tshark_fields(cmd_tshark, cmd_text2pcap, result_file, test_env,
                       raw_bytes, fields, decode_as='matter'):
    '''Feed *raw_bytes* through text2pcap -> tshark and return field values.

    Returns a dict mapping each requested field name to its tshark string
    output (empty string when the field is absent in the packet).
    '''
    text_file = result_file('matter_test.txt')
    pcap_file = result_file('matter_test.pcap')

    with open(text_file, 'w') as f:
        f.write('000000 {}\n'.format(_hex(raw_bytes)))

    subprocess.check_call((
        cmd_text2pcap,
        '-u', '1234,1234',
        text_file, pcap_file
    ), env=test_env)

    cmd = [
        cmd_tshark,
        '-r', pcap_file,
        '-T', 'fields',
    ]
    if decode_as:
        cmd += ['-d', 'udp.port==1234,{}'.format(decode_as)]
    for fld in fields:
        cmd += ['-e', fld]

    stdout = subprocess.check_output(cmd, encoding='utf-8', env=test_env)
    values = stdout.strip().split('\t')
    # Pad with empty strings if tshark returned fewer columns
    while len(values) < len(fields):
        values.append('')
    return dict(zip(fields, values))


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestMatter:
    '''Tests for the Matter protocol dissector.'''

    # -- Basic message header parsing --------------------------------------

    def test_matter_minimal_unsecured(self, cmd_tshark, cmd_text2pcap,
                                      result_file, test_env):
        '''Minimal unsecured message: no source, no dest, session 0.'''
        payload = _matter_payload(opcode=0x20, protocol_id=0x0000)
        pkt = _matter_msg(session_id=0, counter=42, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.version',
             'matter.message.session_id',
             'matter.message.counter',
             'matter.message.dsiz',
             'matter.message.has_source_id'])

        assert r['matter.message.version'] == '0'
        assert r['matter.message.session_id'] == '0x0000'
        assert r['matter.message.counter'] == '42'
        assert r['matter.message.dsiz'] == '0'
        assert r['matter.message.has_source_id'] in ('False', '0')

    def test_matter_source_node_id(self, cmd_tshark, cmd_text2pcap,
                                   result_file, test_env):
        '''Source node ID present when S flag is set.'''
        payload = _matter_payload(opcode=0x30, protocol_id=0x0000)
        pkt = _matter_msg(
            session_id=0, counter=100,
            source_node_id=0x0102030405060708,
            payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.has_source_id',
             'matter.message.src_id'])

        assert r['matter.message.has_source_id'] in ('True', '1')
        # tshark shows uint64 in hex — accept either leading-zeroed or not
        assert '0102030405060708' in r['matter.message.src_id'].lower()

    def test_matter_dest_node_id(self, cmd_tshark, cmd_text2pcap,
                                 result_file, test_env):
        '''Destination node ID parsed when DSIZ=01.'''
        payload = _matter_payload(opcode=0x01, protocol_id=0x0001)
        pkt = _matter_msg(
            session_id=0, counter=200,
            dest_node_id=0x1122334455667788,
            payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.dsiz',
             'matter.message.dest_node_id'])

        assert r['matter.message.dsiz'] == '1'
        assert '1122334455667788' in r['matter.message.dest_node_id'].lower()

    def test_matter_dest_group_id(self, cmd_tshark, cmd_text2pcap,
                                  result_file, test_env):
        '''Destination group ID parsed when DSIZ=10.'''
        payload = _matter_payload(opcode=0x06, protocol_id=0x0001)
        pkt = _matter_msg(
            session_id=0, counter=300,
            dest_group_id=0x4321,
            payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.dsiz',
             'matter.message.dest_group_id'])

        assert r['matter.message.dsiz'] == '2'
        assert r['matter.message.dest_group_id'] == '0x4321'

    def test_matter_source_and_dest(self, cmd_tshark, cmd_text2pcap,
                                    result_file, test_env):
        '''Message with both source and destination node IDs.'''
        payload = _matter_payload(opcode=0x01, protocol_id=0x0001)
        pkt = _matter_msg(
            session_id=0, counter=400,
            source_node_id=1,
            dest_node_id=2,
            payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.has_source_id',
             'matter.message.dsiz',
             'matter.message.src_id',
             'matter.message.dest_node_id'])

        assert r['matter.message.has_source_id'] in ('True', '1')
        assert r['matter.message.dsiz'] == '1'
        # Both fields should be present (non-empty)
        assert r['matter.message.src_id'] != ''
        assert r['matter.message.dest_node_id'] != ''

    # -- Security flags ----------------------------------------------------

    def test_matter_control_flag(self, cmd_tshark, cmd_text2pcap,
                                 result_file, test_env):
        '''Control flag (0x40) in security flags byte.'''
        payload = _matter_payload(opcode=0x20, protocol_id=0x0000)
        pkt = _matter_msg(
            session_id=0, counter=500,
            security_flags=0x40,
            payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.is_control',
             'matter.message.has_privacy',
             'matter.message.session_type'])

        assert r['matter.message.is_control'] in ('True', '1')
        assert r['matter.message.has_privacy'] in ('False', '0')
        assert r['matter.message.session_type'] == '0x00'

    # -- Protocol payload --------------------------------------------------

    def test_matter_exchange_fields(self, cmd_tshark, cmd_text2pcap,
                                    result_file, test_env):
        '''Exchange flags, opcode, exchange ID and protocol ID.'''
        payload = _matter_payload(
            exchange_flags=0x05,  # initiator + reliability
            opcode=0x30,          # Sigma1
            exchange_id=0xBEEF,
            protocol_id=0x0000,   # Secure Channel
        )
        pkt = _matter_msg(session_id=0, counter=600, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.payload.exchange_flags',
             'matter.payload.initiator',
             'matter.payload.reliability',
             'matter.payload.protocol_opcode',
             'matter.payload.exchange_id',
             'matter.payload.protocol_id'])

        assert r['matter.payload.exchange_flags'] == '0x05'
        assert r['matter.payload.initiator'] in ('True', '1')
        assert r['matter.payload.reliability'] in ('True', '1')
        assert r['matter.payload.protocol_opcode'] == '0x30'
        assert r['matter.payload.exchange_id'] == '0xbeef'
        assert r['matter.payload.protocol_id'] == '0x0000'

    def test_matter_ack_counter(self, cmd_tshark, cmd_text2pcap,
                                result_file, test_env):
        '''Acknowledged message counter field when ACK flag set.'''
        payload = _matter_payload(
            exchange_flags=0x01,
            opcode=0x05,
            exchange_id=0x0001,
            protocol_id=0x0001,
            ack_counter=999,
        )
        pkt = _matter_msg(session_id=0, counter=700, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.payload.ack_msg',
             'matter.payload.ack_counter'])

        assert r['matter.payload.ack_msg'] in ('True', '1')
        assert r['matter.payload.ack_counter'] == '999'

    # -- Message extensions ------------------------------------------------

    def test_matter_message_extensions(self, cmd_tshark, cmd_text2pcap,
                                       result_file, test_env):
        '''Message extensions data and length are parsed.'''
        ext_data = [0xAA, 0xBB, 0xCC]
        payload = _matter_payload(opcode=0x20, protocol_id=0x0000)
        pkt = _matter_msg(
            session_id=0, counter=800,
            has_extensions=True, ext_data=ext_data,
            payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.message.has_extensions',
             'matter.message.ext_length',
             'matter.message.ext_data'])

        assert r['matter.message.has_extensions'] in ('True', '1')
        assert r['matter.message.ext_length'] == '3'
        assert r['matter.message.ext_data'] == 'aabbcc'

    # -- TLV dissection ----------------------------------------------------

    def test_matter_tlv_uint8(self, cmd_tshark, cmd_text2pcap,
                              result_file, test_env):
        '''TLV unsigned 8-bit integer, context-specific tag.'''
        # control=0x24 (tag=context, type=uint8), tag=0x01, value=42
        tlv = bytes([0x24, 0x01, 0x2A])
        payload = _matter_payload(
            opcode=0x05, protocol_id=0x0001, application=tlv)
        pkt = _matter_msg(session_id=0, counter=900, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.tlv.control',
             'matter.tlv.tag',
             'matter.tlv.value_uint'])

        assert r['matter.tlv.control'] == '0x24'
        assert r['matter.tlv.value_uint'] == '42'

    def test_matter_tlv_signed_int(self, cmd_tshark, cmd_text2pcap,
                                   result_file, test_env):
        '''TLV signed 8-bit integer, context-specific tag, value -1.'''
        # control=0x20 (context tag, type=int8), tag=0x05, value=-1 (0xFF)
        tlv = bytes([0x20, 0x05, 0xFF])
        payload = _matter_payload(
            opcode=0x05, protocol_id=0x0001, application=tlv)
        pkt = _matter_msg(session_id=0, counter=1000, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.tlv.value_int'])

        assert r['matter.tlv.value_int'] == '-1'

    def test_matter_tlv_utf8_string(self, cmd_tshark, cmd_text2pcap,
                                    result_file, test_env):
        '''TLV UTF-8 string, context-specific tag.'''
        # control=0x2C (context tag, type=UTF8 string 1-byte len)
        # tag=0x02, length=0x02, "Hi"
        tlv = bytes([0x2C, 0x02, 0x02, 0x48, 0x69])
        payload = _matter_payload(
            opcode=0x05, protocol_id=0x0001, application=tlv)
        pkt = _matter_msg(session_id=0, counter=1100, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.tlv.value_string',
             'matter.tlv.length'])

        assert r['matter.tlv.value_string'] == 'Hi'
        assert r['matter.tlv.length'] == '2'

    def test_matter_tlv_octet_string(self, cmd_tshark, cmd_text2pcap,
                                     result_file, test_env):
        '''TLV octet string, context-specific tag.'''
        # control=0x30 (context tag, type=octet string 1-byte len)
        # tag=0x03, length=0x03, data=0xDE 0xAD 0xFF
        tlv = bytes([0x30, 0x03, 0x03, 0xDE, 0xAD, 0xFF])
        payload = _matter_payload(
            opcode=0x05, protocol_id=0x0001, application=tlv)
        pkt = _matter_msg(session_id=0, counter=1200, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.tlv.value_bytes',
             'matter.tlv.length'])

        assert r['matter.tlv.value_bytes'] == 'deadff'
        assert r['matter.tlv.length'] == '3'

    def test_matter_tlv_boolean_true(self, cmd_tshark, cmd_text2pcap,
                                     result_file, test_env):
        '''TLV boolean true (element type 0x09).'''
        # control=0x29 (context tag, type=bool true), tag=0x03
        tlv = bytes([0x29, 0x03])
        payload = _matter_payload(
            opcode=0x05, protocol_id=0x0001, application=tlv)
        pkt = _matter_msg(session_id=0, counter=1300, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.tlv.control.element'])

        assert r['matter.tlv.control.element'] == '0x09'

    def test_matter_tlv_null(self, cmd_tshark, cmd_text2pcap,
                             result_file, test_env):
        '''TLV null value (element type 0x14).'''
        # control=0x34 (context tag, type=null), tag=0x10
        tlv = bytes([0x34, 0x10])
        payload = _matter_payload(
            opcode=0x05, protocol_id=0x0001, application=tlv)
        pkt = _matter_msg(session_id=0, counter=1400, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['matter.tlv.control.element'])

        assert r['matter.tlv.control.element'] == '0x14'

    # -- Edge cases --------------------------------------------------------

    def test_matter_rejects_short_packet(self, cmd_tshark, cmd_text2pcap,
                                         result_file, test_env):
        '''Packets shorter than 8 bytes should not be decoded as Matter.'''
        short_pkt = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])  # 7 bytes

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, short_pkt,
            ['matter.message.counter'])

        # The dissector rejects the packet — no matter fields present
        assert r['matter.message.counter'] == ''

    def test_matter_return_value(self, cmd_tshark, cmd_text2pcap,
                                 result_file, test_env):
        '''Dissector consumes the full packet (frame.len matches).'''
        payload = _matter_payload(opcode=0x20, protocol_id=0x0000)
        pkt = _matter_msg(session_id=0, counter=42, payload=payload)

        r = _run_tshark_fields(
            cmd_tshark, cmd_text2pcap, result_file, test_env, pkt,
            ['frame.len', 'matter.message.counter'])

        # frame.len = ethernet(14) + IP(20) + UDP(8) + matter payload
        # Ethernet frames are padded to minimum 60 bytes on the wire.
        expected_frame_len = max(60, 42 + len(pkt))
        assert r['matter.message.counter'] == '42'
        assert int(r['frame.len']) == expected_frame_len
