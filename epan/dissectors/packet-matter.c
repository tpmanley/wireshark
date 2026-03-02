/* packet-matter.c
 * Routines for Matter IoT protocol dissection
 * Copyright 2023, Nicolás Alvarez <nicolas.alvarez@gmail.com>
 * Copyright 2024, Arkadiusz Bokowy <a.bokowy@samsung.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The Matter protocol provides an interoperable application
 * layer solution for smart home devices over IPv6.
 *
 * The specification can be freely requested at:
 * https://csa-iot.org/developer-resource/specifications-download-request/
 *
 * Comments below reference section numbers of the Matter Core
 * Specification Version 1.5.
 */

#define WS_LOG_DOMAIN "packet-matter"

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <wsutil/array.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/wslog.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_matter(void);
void proto_register_matter(void);

static int  dissect_matter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int  dissect_matter_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static bool hex_to_bytes(const char *hex, uint8_t *out, unsigned len);

/* Initialize the protocol and registered fields */
static dissector_handle_t matter_handle;

static int proto_matter;
static int hf_message_flags;
static int hf_message_version;
static int hf_message_has_source;
static int hf_message_dsiz;
static int hf_message_session_id;
static int hf_message_security_flags;
static int hf_message_flag_privacy;
static int hf_message_flag_control;
static int hf_message_flag_extensions;
static int hf_message_session_type;
static int hf_message_counter;
static int hf_message_src_id;
static int hf_message_dest_node_id;
static int hf_message_dest_group_id;
static int hf_message_privacy_header;
static int hf_message_ext_length;
static int hf_message_ext_data;

static int hf_payload;
static int hf_payload_mic;
static int hf_payload_exchange_flags;
static int hf_payload_flag_initiator;
static int hf_payload_flag_ack;
static int hf_payload_flag_reliability;
static int hf_payload_flag_secured_extensions;
static int hf_payload_flag_vendor;
static int hf_payload_protocol_opcode;
static int hf_payload_exchange_id;
static int hf_payload_protocol_vendor_id;
static int hf_payload_protocol_id;
static int hf_payload_ack_counter;
static int hf_payload_secured_ext_length;
static int hf_payload_secured_ext;
static int hf_payload_application;

static int hf_matter_tlv_elem;
static int hf_matter_tlv_elem_control;
static int hf_matter_tlv_elem_control_tag_format;
static int hf_matter_tlv_elem_control_element_type;
static int hf_matter_tlv_elem_tag;
static int hf_matter_tlv_elem_tag_vendor_id;
static int hf_matter_tlv_elem_tag_profile;
static int hf_matter_tlv_elem_tag_number_16;
static int hf_matter_tlv_elem_tag_number_32;
static int hf_matter_tlv_elem_length;
static int hf_matter_tlv_elem_value_int;
static int hf_matter_tlv_elem_value_uint;
static int hf_matter_tlv_elem_value_float;
static int hf_matter_tlv_elem_value_double;
static int hf_matter_tlv_elem_value_string;
static int hf_matter_tlv_elem_value_bytes;

static int ett_matter;
static int ett_message_flags;
static int ett_security_flags;
static int ett_payload;
static int ett_exchange_flags;

static int ett_matter_tlv;
static int ett_matter_tlv_control;

static expert_field ei_matter_tlv_unsupported_control;
static expert_field ei_matter_decryption_no_key;
static expert_field ei_matter_decryption_failed;

/*
 * Session key storage for decryption.
 *
 * Keys are loaded from a key log file with lines in the format:
 *   SESSION_KEY <session_id_hex> <32_hex_bytes_of_key>
 *
 * For example:
 *   SESSION_KEY 0x1234 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
 *
 * The session key can be exported from the Matter SDK by instrumenting
 * the CASE session establishment code.
 */
#define MATTER_SESSION_KEY_LEN   16
#define MATTER_NONCE_LEN         13
#define MATTER_MIC_LEN           16  /* AES-128-CCM authentication tag */

/*
 * UAT (User Accessible Table) for entering CASE/PASE session keys
 * directly via the Wireshark Preferences dialog.
 *
 * Each row holds the I2R (Initiator-to-Responder) and/or
 * R2I (Responder-to-Initiator) 128-bit AES keys in hex, plus optional
 * Initiator/Responder node IDs for nonce construction.  The dissector
 * tries all UAT entries against every encrypted packet; only the
 * entry whose key passes MIC verification is used.
 */
typedef struct {
    char *initiator_node_id_str; /* 64-bit initiator node ID, hex with 0x prefix */
    char *responder_node_id_str; /* 64-bit responder node ID, hex with 0x prefix */
    char *i2r_key;               /* 32 hex chars (16 bytes) or empty */
    char *r2i_key;               /* 32 hex chars (16 bytes) or empty */
} matter_key_uat_record_t;

static matter_key_uat_record_t *matter_key_uat_records;
static unsigned                 num_matter_key_uat_records;

static void *
matter_key_uat_copy_cb(void *dest, const void *source, size_t len _U_)
{
    const matter_key_uat_record_t *s = (const matter_key_uat_record_t *)source;
    matter_key_uat_record_t       *d = (matter_key_uat_record_t *)dest;
    d->initiator_node_id_str = g_strdup(s->initiator_node_id_str);
    d->responder_node_id_str = g_strdup(s->responder_node_id_str);
    d->i2r_key              = g_strdup(s->i2r_key);
    d->r2i_key              = g_strdup(s->r2i_key);
    return dest;
}

static bool
matter_key_uat_update_cb(void *r, char **error)
{
    matter_key_uat_record_t *rec = (matter_key_uat_record_t *)r;

    /* Validate node IDs (optional, but if present must be valid hex) */
    if (rec->initiator_node_id_str && *rec->initiator_node_id_str) {
        char *endp2 = NULL;
        (void)g_ascii_strtoull(rec->initiator_node_id_str, &endp2, 0);
        if (endp2 == rec->initiator_node_id_str || *endp2 != '\0') {
            *error = g_strdup("Initiator Node ID must be a number (decimal or 0x hex)");
            return false;
        }
    }
    if (rec->responder_node_id_str && *rec->responder_node_id_str) {
        char *endp2 = NULL;
        (void)g_ascii_strtoull(rec->responder_node_id_str, &endp2, 0);
        if (endp2 == rec->responder_node_id_str || *endp2 != '\0') {
            *error = g_strdup("Responder Node ID must be a number (decimal or 0x hex)");
            return false;
        }
    }

    /* At least one key must be provided */
    bool has_i2r = rec->i2r_key && *rec->i2r_key;
    bool has_r2i = rec->r2i_key && *rec->r2i_key;
    if (!has_i2r && !has_r2i) {
        *error = g_strdup("At least one key (I2R or R2I) must be provided");
        return false;
    }

    /* Validate key lengths and hex encoding */
    if (has_i2r) {
        if (strlen(rec->i2r_key) != 2 * MATTER_SESSION_KEY_LEN) {
            *error = g_strdup("I2R key must be exactly 32 hex characters");
            return false;
        }
        uint8_t tmp[MATTER_SESSION_KEY_LEN];
        if (!hex_to_bytes(rec->i2r_key, tmp, MATTER_SESSION_KEY_LEN)) {
            *error = g_strdup("I2R key contains invalid hex characters");
            return false;
        }
    }
    if (has_r2i) {
        if (strlen(rec->r2i_key) != 2 * MATTER_SESSION_KEY_LEN) {
            *error = g_strdup("R2I key must be exactly 32 hex characters");
            return false;
        }
        uint8_t tmp[MATTER_SESSION_KEY_LEN];
        if (!hex_to_bytes(rec->r2i_key, tmp, MATTER_SESSION_KEY_LEN)) {
            *error = g_strdup("R2I key contains invalid hex characters");
            return false;
        }
    }
    return true;
}

static void
matter_key_uat_free_cb(void *r)
{
    matter_key_uat_record_t *rec = (matter_key_uat_record_t *)r;
    g_free(rec->initiator_node_id_str);
    g_free(rec->responder_node_id_str);
    g_free(rec->i2r_key);
    g_free(rec->r2i_key);
}

static void matter_key_uat_apply(void)  { /* Keys read on the fly during dissection */ }
static void matter_key_uat_reset(void)  { /* Nothing to clean up */ }

UAT_CSTRING_CB_DEF(matter_key_uat, initiator_node_id_str, matter_key_uat_record_t)
UAT_CSTRING_CB_DEF(matter_key_uat, responder_node_id_str, matter_key_uat_record_t)
UAT_CSTRING_CB_DEF(matter_key_uat, i2r_key, matter_key_uat_record_t)
UAT_CSTRING_CB_DEF(matter_key_uat, r2i_key, matter_key_uat_record_t)

static bool
hex_to_bytes(const char *hex, uint8_t *out, unsigned len)
{
    for (unsigned i = 0; i < len; i++) {
        int hi = g_ascii_xdigit_value(hex[2 * i]);
        int lo = g_ascii_xdigit_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/*
 * A candidate decryption key together with the source node ID to use
 * when constructing the nonce.  For I2R keys the source is the Initiator;
 * for R2I keys it is the Responder.  A value of 0 means "use whatever
 * source_node_id appeared in the message header".
 */
typedef struct {
    const uint8_t *key;
    uint64_t       source_node_id;
    bool           has_node_id;   /* true if source_node_id was explicitly set */
} matter_candidate_key_t;

/*
 * Collect all candidate decryption keys from the UAT.
 *
 * Every UAT entry is tried against every encrypted packet — session IDs
 * are not used for matching.  Only MIC verification determines the
 * correct key.  Returns the number of entries written into *candidates
 * (max *max_keys*).
 */
#define MAX_UAT_ENTRIES 16
static uint8_t uat_key_buf[MAX_UAT_ENTRIES * 2 * MATTER_SESSION_KEY_LEN];

static unsigned
matter_collect_session_keys(matter_candidate_key_t candidates[], unsigned max_keys)
{
    unsigned n = 0;

    /* UAT keys (I2R + R2I) with per-direction node IDs */
    for (unsigned i = 0; i < num_matter_key_uat_records && n < max_keys; i++) {
        matter_key_uat_record_t *rec = &matter_key_uat_records[i];

        /* Parse node IDs once per UAT row */
        uint64_t initiator_nid = 0;
        bool has_initiator_nid = false;
        if (rec->initiator_node_id_str && *rec->initiator_node_id_str) {
            initiator_nid = g_ascii_strtoull(rec->initiator_node_id_str, NULL, 0);
            has_initiator_nid = true;
        }
        uint64_t responder_nid = 0;
        bool has_responder_nid = false;
        if (rec->responder_node_id_str && *rec->responder_node_id_str) {
            responder_nid = g_ascii_strtoull(rec->responder_node_id_str, NULL, 0);
            has_responder_nid = true;
        }

        if (rec->i2r_key && strlen(rec->i2r_key) == 2 * MATTER_SESSION_KEY_LEN && n < max_keys) {
            uint8_t *buf = &uat_key_buf[(i * 2) * MATTER_SESSION_KEY_LEN];
            if (hex_to_bytes(rec->i2r_key, buf, MATTER_SESSION_KEY_LEN)) {
                candidates[n].key = buf;
                candidates[n].source_node_id = initiator_nid;
                candidates[n].has_node_id = has_initiator_nid;
                n++;
            }
        }
        if (rec->r2i_key && strlen(rec->r2i_key) == 2 * MATTER_SESSION_KEY_LEN && n < max_keys) {
            uint8_t *buf = &uat_key_buf[(i * 2 + 1) * MATTER_SESSION_KEY_LEN];
            if (hex_to_bytes(rec->r2i_key, buf, MATTER_SESSION_KEY_LEN)) {
                candidates[n].key = buf;
                candidates[n].source_node_id = responder_nid;
                candidates[n].has_node_id = has_responder_nid;
                n++;
            }
        }
    }
    return n;
}

/*
 * Construct the Matter message nonce (13 bytes) per spec Section 4.7.2:
 *   Nonce = security_flags (1) || message_counter (4 LE) || source_node_id (8 LE)
 *
 * For unicast sessions without a source node ID in the header, the source
 * node ID is set to all zeros.
 */
static void
matter_build_nonce(uint8_t security_flags, uint32_t message_counter,
                   uint64_t source_node_id, uint8_t *nonce)
{
    nonce[0] = security_flags;
    nonce[1] = (uint8_t)(message_counter);
    nonce[2] = (uint8_t)(message_counter >> 8);
    nonce[3] = (uint8_t)(message_counter >> 16);
    nonce[4] = (uint8_t)(message_counter >> 24);
    nonce[5]  = (uint8_t)(source_node_id);
    nonce[6]  = (uint8_t)(source_node_id >> 8);
    nonce[7]  = (uint8_t)(source_node_id >> 16);
    nonce[8]  = (uint8_t)(source_node_id >> 24);
    nonce[9]  = (uint8_t)(source_node_id >> 32);
    nonce[10] = (uint8_t)(source_node_id >> 40);
    nonce[11] = (uint8_t)(source_node_id >> 48);
    nonce[12] = (uint8_t)(source_node_id >> 56);
}

/*
 * Attempt AES-128-CCM decryption of a Matter secured message.
 * Returns a new tvbuff_t with the decrypted payload on success, or NULL.
 *
 * The AAD (additional authenticated data) is the message header bytes
 * from the start of the packet up to the encrypted payload.
 */
static tvbuff_t *
matter_decrypt_payload(tvbuff_t *tvb, packet_info *pinfo,
                       uint32_t header_len, uint32_t payload_len,
                       const uint8_t *key, const uint8_t *nonce)
{
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t gcrypt_err;
    uint64_t ccm_lengths[3];

    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0)) {
        return NULL;
    }

    gcrypt_err = gcry_cipher_setkey(cipher_hd, key, MATTER_SESSION_KEY_LEN);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    gcrypt_err = gcry_cipher_setiv(cipher_hd, nonce, MATTER_NONCE_LEN);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* CCM lengths: [0]=payload, [1]=AAD, [2]=tag(MIC) */
    ccm_lengths[0] = payload_len;
    ccm_lengths[1] = header_len;
    ccm_lengths[2] = MATTER_MIC_LEN;

    gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Authenticate the message header (AAD) */
    gcrypt_err = gcry_cipher_authenticate(cipher_hd,
        tvb_get_ptr(tvb, 0, header_len), header_len);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Decrypt the payload */
    uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, payload_len);
    gcrypt_err = gcry_cipher_decrypt(cipher_hd, decrypted, payload_len,
        tvb_get_ptr(tvb, header_len, payload_len), payload_len);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Verify the MIC (authentication tag) */
    uint8_t *tag = (uint8_t *)wmem_alloc(pinfo->pool, MATTER_MIC_LEN);
    gcrypt_err = gcry_cipher_gettag(cipher_hd, tag, MATTER_MIC_LEN);
    gcry_cipher_close(cipher_hd);

    if (gcrypt_err != 0) {
        return NULL;
    }

    const uint8_t *expected_mic = tvb_get_ptr(tvb, header_len + payload_len, MATTER_MIC_LEN);
    if (memcmp(tag, expected_mic, MATTER_MIC_LEN) != 0) {
        /* MIC mismatch - wrong key or corrupted message */
        return NULL;
    }

    /* Create a tvbuff from the decrypted data */
    tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, decrypted, payload_len, payload_len);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Matter Payload");
    return decrypted_tvb;
}

// Section 4.10.4: Matter operational discovery uses UDP port 5540 by default.
#define MATTER_DEFAULT_PORT 5540

/* message flags + session ID + security flags + counter */
#define MATTER_MIN_LENGTH 8

// Section 4.4.1.2
#define MESSAGE_FLAG_VERSION_MASK       0xF0
#define MESSAGE_FLAG_HAS_SOURCE         0x04
#define MESSAGE_FLAG_HAS_DEST_NODE      0x01
#define MESSAGE_FLAG_HAS_DEST_GROUP     0x02
#define MESSAGE_FLAG_DSIZ_MASK          0x03

// Section 4.4.1.4
#define SECURITY_FLAG_HAS_PRIVACY       0x80
#define SECURITY_FLAG_IS_CONTROL        0x40
#define SECURITY_FLAG_HAS_EXTENSIONS    0x20
#define SECURITY_FLAG_SESSION_TYPE_MASK 0x03
#define SECURITY_FLAG_SESSION_TYPE_UNICAST 0
#define SECURITY_FLAG_SESSION_TYPE_GROUP   1

// Section 4.4.3.1
#define EXCHANGE_FLAG_IS_INITIATOR      0x01
#define EXCHANGE_FLAG_ACK_MSG           0x02
#define EXCHANGE_FLAG_RELIABILITY       0x04
#define EXCHANGE_FLAG_HAS_SECURED_EXT   0x08
#define EXCHANGE_FLAG_HAS_VENDOR_PROTO  0x10

static const value_string dsiz_vals[] = {
    { 0, "Not present" },
    { MESSAGE_FLAG_HAS_DEST_NODE,  "64-bit Node ID" },
    { MESSAGE_FLAG_HAS_DEST_GROUP, "16-bit Group ID" },
    { 3, "64-bit Node ID (Reserved)" },
    { 0, NULL }
};

static const value_string session_type_vals[] = {
    { 0, "Unicast Session" },
    { 1, "Group Session" },
    { 0, NULL }
};

// Section 4.4.3.4: Protocol IDs
static const value_string protocol_id_vals[] = {
    { 0x0000, "Secure Channel" },
    { 0x0001, "Interaction Model" },
    { 0x0002, "BDX (Bulk Data Exchange)" },
    { 0x0003, "User Directed Commissioning" },
    { 0, NULL }
};

// Section 4.13.1: Secure Channel Protocol Opcodes
static const value_string sc_opcode_vals[] = {
    { 0x10, "MsgCounterSyncReq" },
    { 0x11, "MsgCounterSyncRsp" },
    { 0x20, "MRP Standalone Acknowledgement" },
    { 0x30, "PBKDFParamRequest" },
    { 0x31, "PBKDFParamResponse" },
    { 0x32, "PASE Pake1" },
    { 0x33, "PASE Pake2" },
    { 0x34, "PASE Pake3" },
    { 0x40, "StatusReport" },
    { 0x50, "ICD CheckIn" },
    { 0x60, "CASE Sigma1" },
    { 0x61, "CASE Sigma2" },
    { 0x62, "CASE Sigma3" },
    { 0x63, "CASE Sigma2Resume" },
    { 0, NULL }
};

// Section 8.2.3: Interaction Model Protocol Opcodes
static const value_string im_opcode_vals[] = {
    { 0x01, "StatusResponse" },
    { 0x02, "ReadRequest" },
    { 0x03, "SubscribeRequest" },
    { 0x04, "SubscribeResponse" },
    { 0x05, "ReportData" },
    { 0x06, "WriteRequest" },
    { 0x07, "WriteResponse" },
    { 0x08, "InvokeRequest" },
    { 0x09, "InvokeResponse" },
    { 0x0A, "TimedRequest" },
    { 0, NULL }
};

// Section 11.22.5: BDX Protocol Opcodes
static const value_string bdx_opcode_vals[] = {
    { 0x01, "SendInit" },
    { 0x02, "SendAccept" },
    { 0x04, "ReceiveInit" },
    { 0x05, "ReceiveAccept" },
    { 0x10, "BlockQuery" },
    { 0x11, "Block" },
    { 0x12, "BlockEOF" },
    { 0x13, "BlockAck" },
    { 0x14, "BlockAckEOF" },
    { 0x15, "BlockQueryWithSkip" },
    { 0, NULL }
};

// Section 5.3: User Directed Commissioning Protocol Opcodes
static const value_string udc_opcode_vals[] = {
    { 0x00, "IdentificationDeclaration" },
    { 0, NULL }
};

static const value_string *opcode_vals_by_protocol[] = {
    sc_opcode_vals,   // 0x0000: Secure Channel
    im_opcode_vals,   // 0x0001: Interaction Model
    bdx_opcode_vals,  // 0x0002: BDX
    udc_opcode_vals,  // 0x0003: User Directed Commissioning
};

// Matter Application Cluster IDs (Cluster Specification)
static const value_string matter_cluster_id_vals[] = {
    { 0x0003, "Identify" },
    { 0x0004, "Groups" },
    { 0x0005, "Scenes" },
    { 0x0006, "OnOff" },
    { 0x0008, "LevelControl" },
    { 0x000F, "BinaryInputBasic" },
    { 0x001D, "Descriptor" },
    { 0x001E, "Binding" },
    { 0x001F, "AccessControl" },
    { 0x0025, "Actions" },
    { 0x0028, "BasicInformation" },
    { 0x0029, "OtaSoftwareUpdateProvider" },
    { 0x002A, "OtaSoftwareUpdateRequestor" },
    { 0x002B, "LocalizationConfiguration" },
    { 0x002C, "TimeFormatLocalization" },
    { 0x002D, "UnitLocalization" },
    { 0x002E, "PowerSourceConfiguration" },
    { 0x002F, "PowerSource" },
    { 0x0030, "GeneralCommissioning" },
    { 0x0031, "NetworkCommissioning" },
    { 0x0032, "DiagnosticLogs" },
    { 0x0033, "GeneralDiagnostics" },
    { 0x0034, "SoftwareDiagnostics" },
    { 0x0035, "ThreadNetworkDiagnostics" },
    { 0x0036, "WiFiNetworkDiagnostics" },
    { 0x0037, "EthernetNetworkDiagnostics" },
    { 0x0038, "TimeSynchronization" },
    { 0x0039, "BridgedDeviceBasicInformation" },
    { 0x003B, "Switch" },
    { 0x003C, "AdministratorCommissioning" },
    { 0x003E, "OperationalCredentials" },
    { 0x003F, "GroupKeyManagement" },
    { 0x0040, "FixedLabel" },
    { 0x0041, "UserLabel" },
    { 0x0045, "BooleanState" },
    { 0x0046, "IcdManagement" },
    { 0x0047, "Timer" },
    { 0x0048, "OvenCavityOperationalState" },
    { 0x0049, "OvenMode" },
    { 0x0050, "ModeSelect" },
    { 0x0051, "LaundryWasherMode" },
    { 0x0052, "RefrigeratorAndTemperatureControlledCabinetMode" },
    { 0x0053, "LaundryWasherControls" },
    { 0x0054, "RvcRunMode" },
    { 0x0055, "RvcCleanMode" },
    { 0x0056, "TemperatureControl" },
    { 0x0057, "RefrigeratorAlarm" },
    { 0x0059, "DishwasherMode" },
    { 0x005B, "AirQuality" },
    { 0x005C, "SmokeCoAlarm" },
    { 0x005D, "DishwasherAlarm" },
    { 0x005E, "MicrowaveOvenMode" },
    { 0x005F, "MicrowaveOvenControl" },
    { 0x0060, "OperationalState" },
    { 0x0061, "RvcOperationalState" },
    { 0x0062, "ScenesManagement" },
    { 0x0071, "HepaFilterMonitoring" },
    { 0x0072, "ActivatedCarbonFilterMonitoring" },
    { 0x0080, "BooleanStateConfiguration" },
    { 0x0081, "ValveConfigurationAndControl" },
    { 0x0090, "ElectricalPowerMeasurement" },
    { 0x0091, "ElectricalEnergyMeasurement" },
    { 0x0094, "WaterHeaterManagement" },
    { 0x0096, "DemandResponseLoadControl" },
    { 0x0097, "Messages" },
    { 0x0098, "DeviceEnergyManagement" },
    { 0x0099, "EnergyEvse" },
    { 0x009B, "EnergyPreference" },
    { 0x009C, "PowerTopology" },
    { 0x009D, "EnergyEvseMode" },
    { 0x009E, "DeviceEnergyManagementMode" },
    { 0x0101, "DoorLock" },
    { 0x0102, "WindowCovering" },
    { 0x0150, "ServiceArea" },
    { 0x0200, "PumpConfigurationAndControl" },
    { 0x0201, "Thermostat" },
    { 0x0202, "FanControl" },
    { 0x0204, "ThermostatUserInterfaceConfiguration" },
    { 0x0300, "ColorControl" },
    { 0x0301, "BallastConfiguration" },
    { 0x0400, "IlluminanceMeasurement" },
    { 0x0402, "TemperatureMeasurement" },
    { 0x0403, "PressureMeasurement" },
    { 0x0404, "FlowMeasurement" },
    { 0x0405, "RelativeHumidityMeasurement" },
    { 0x0406, "OccupancySensing" },
    { 0x040C, "CarbonMonoxideConcentrationMeasurement" },
    { 0x040D, "CarbonDioxideConcentrationMeasurement" },
    { 0x0413, "NitrogenDioxideConcentrationMeasurement" },
    { 0x0415, "OzoneConcentrationMeasurement" },
    { 0x042A, "PM2.5ConcentrationMeasurement" },
    { 0x042B, "FormaldehydeConcentrationMeasurement" },
    { 0x042C, "PM1ConcentrationMeasurement" },
    { 0x042D, "PM10ConcentrationMeasurement" },
    { 0x042E, "TotalVolatileOrganicCompoundsConcentrationMeasurement" },
    { 0x042F, "RadonConcentrationMeasurement" },
    { 0x0503, "WakeOnLan" },
    { 0x0504, "Channel" },
    { 0x0505, "TargetNavigator" },
    { 0x0506, "MediaPlayback" },
    { 0x0507, "MediaInput" },
    { 0x0508, "LowPower" },
    { 0x0509, "KeypadInput" },
    { 0x050A, "ContentLauncher" },
    { 0x050B, "AudioOutput" },
    { 0x050C, "ApplicationLauncher" },
    { 0x050D, "ApplicationBasic" },
    { 0x050E, "AccountLogin" },
    { 0x050F, "ContentControl" },
    { 0x0510, "ContentAppObserver" },
    { 0, NULL }
};

// Appendix 7.2. Tag Control Field
static const value_string matter_tlv_tag_format_vals[] = {
    { 0, "Anonymous Tag Form, 0 octets" },
    { 1, "Context-specific Tag Form, 1 octet" },
    { 2, "Common Profile Tag Form, 2 octets" },
    { 3, "Common Profile Tag Form, 4 octets" },
    { 4, "Implicit Profile Tag Form, 2 octets" },
    { 5, "Implicit Profile Tag Form, 4 octets" },
    { 6, "Fully-qualified Tag Form, 6 octets" },
    { 7, "Fully-qualified Tag Form, 8 octets" },
    { 0, NULL }
};

// Appendix 7.1. Element Type Field
static const value_string matter_tlv_elem_type_vals[] = {
    { 0x00, "Signed Integer, 1-octet value" },
    { 0x01, "Signed Integer, 2-octet value" },
    { 0x02, "Signed Integer, 4-octet value" },
    { 0x03, "Signed Integer, 8-octet value" },
    { 0x04, "Unsigned Integer, 1-octet value" },
    { 0x05, "Unsigned Integer, 2-octet value" },
    { 0x06, "Unsigned Integer, 4-octet value" },
    { 0x07, "Unsigned Integer, 8-octet value" },
    { 0x08, "Boolean False" },
    { 0x09, "Boolean True" },
    { 0x0A, "Floating Point Number, 4-octet value" },
    { 0x0B, "Floating Point Number, 8-octet value" },
    { 0x0C, "UTF-8 String, 1-octet length" },
    { 0x0D, "UTF-8 String, 2-octet length" },
    { 0x0E, "UTF-8 String, 4-octet length" },
    { 0x0F, "UTF-8 String, 8-octet length" },
    { 0x10, "Octet String, 1-octet length" },
    { 0x11, "Octet String, 2-octet length" },
    { 0x12, "Octet String, 4-octet length" },
    { 0x13, "Octet String, 8-octet length" },
    { 0x14, "Null" },
    { 0x15, "Structure" },
    { 0x16, "Array" },
    { 0x17, "List" },
    // XXX: If the Tag Control Field is set to 0x00 (Anonymous Tag), the
    //      value of 0x18 means "End of Container". For other Tag Control
    //      Field values, the value of 0x18 is reserved.
    // TODO: This should be handled in the dissector.
    { 0x18, "End of Container" },
    { 0x19, "Reserved" },
    { 0x1A, "Reserved" },
    { 0x1B, "Reserved" },
    { 0x1C, "Reserved" },
    { 0x1D, "Reserved" },
    { 0x1E, "Reserved" },
    { 0x1F, "Reserved" },
    { 0, NULL }
};

/*
 * Interaction Model TLV context annotation tables.
 *
 * When the application payload belongs to the Interaction Model protocol
 * (protocol_id == 0x0001), the TLV context-specific tags carry semantic
 * meaning defined by the spec (Sections 8.4-8.9).  The tables below map
 * each (message-type, tag-number) pair to a human-readable field name and,
 * for container tags (Structures/Arrays/Lists), the child context that
 * should be used when recursing into the container.
 */
typedef enum {
    MATTER_TLV_CONTEXT_NONE = 0,
    /* IM action types (one per opcode) */
    MATTER_TLV_CONTEXT_STATUS_RESPONSE,
    MATTER_TLV_CONTEXT_READ_REQUEST,
    MATTER_TLV_CONTEXT_SUBSCRIBE_REQUEST,
    MATTER_TLV_CONTEXT_SUBSCRIBE_RESPONSE,
    MATTER_TLV_CONTEXT_REPORT_DATA,
    MATTER_TLV_CONTEXT_WRITE_REQUEST,
    MATTER_TLV_CONTEXT_WRITE_RESPONSE,
    MATTER_TLV_CONTEXT_INVOKE_REQUEST,
    MATTER_TLV_CONTEXT_INVOKE_RESPONSE,
    MATTER_TLV_CONTEXT_TIMED_REQUEST,
    /* IM Information Blocks (sub-structures) */
    MATTER_TLV_CONTEXT_ATTRIBUTE_PATH,
    MATTER_TLV_CONTEXT_EVENT_PATH,
    MATTER_TLV_CONTEXT_COMMAND_PATH,
    MATTER_TLV_CONTEXT_COMMAND_DATA,
    MATTER_TLV_CONTEXT_INVOKE_RESPONSE_IB,
    MATTER_TLV_CONTEXT_COMMAND_STATUS,
    MATTER_TLV_CONTEXT_STATUS_IB,
    MATTER_TLV_CONTEXT_ATTRIBUTE_REPORT,
    MATTER_TLV_CONTEXT_ATTRIBUTE_STATUS,
    MATTER_TLV_CONTEXT_ATTRIBUTE_DATA,
    MATTER_TLV_CONTEXT_EVENT_REPORT,
    MATTER_TLV_CONTEXT_EVENT_STATUS,
    MATTER_TLV_CONTEXT_EVENT_DATA,
    MATTER_TLV_CONTEXT_DATA_VERSION_FILTER,
    MATTER_TLV_CONTEXT_CLUSTER_PATH,
    MATTER_TLV_CONTEXT_EVENT_FILTER,
} matter_tlv_context_id_t;

typedef struct {
    uint8_t                  tag;
    const char              *name;
    matter_tlv_context_id_t  child_context; /* for containers; NONE for leaves */
} matter_tlv_tag_info_t;

/* --- IM Action Types --- */

// Section 8.9.2.6: StatusResponseMessage
static const matter_tlv_tag_info_t im_status_response_tags[] = {
    { 0,    "Status",                    MATTER_TLV_CONTEXT_NONE },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.4.3.1: ReadRequestMessage
static const matter_tlv_tag_info_t im_read_request_tags[] = {
    { 0,    "AttributeRequests",         MATTER_TLV_CONTEXT_ATTRIBUTE_PATH },
    { 1,    "EventRequests",             MATTER_TLV_CONTEXT_EVENT_PATH },
    { 2,    "EventFilters",              MATTER_TLV_CONTEXT_EVENT_FILTER },
    { 3,    "FabricFiltered",            MATTER_TLV_CONTEXT_NONE },
    { 4,    "DataVersionFilters",        MATTER_TLV_CONTEXT_DATA_VERSION_FILTER },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.5.3.1: SubscribeRequestMessage
static const matter_tlv_tag_info_t im_subscribe_request_tags[] = {
    { 0,    "KeepSubscriptions",         MATTER_TLV_CONTEXT_NONE },
    { 1,    "MinIntervalFloor",          MATTER_TLV_CONTEXT_NONE },
    { 2,    "MaxIntervalCeiling",        MATTER_TLV_CONTEXT_NONE },
    { 3,    "AttributeRequests",         MATTER_TLV_CONTEXT_ATTRIBUTE_PATH },
    { 4,    "EventRequests",             MATTER_TLV_CONTEXT_EVENT_PATH },
    { 5,    "EventFilters",              MATTER_TLV_CONTEXT_EVENT_FILTER },
    { 7,    "FabricFiltered",            MATTER_TLV_CONTEXT_NONE },
    { 8,    "DataVersionFilters",        MATTER_TLV_CONTEXT_DATA_VERSION_FILTER },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.5.3.2: SubscribeResponseMessage
static const matter_tlv_tag_info_t im_subscribe_response_tags[] = {
    { 0,    "SubscriptionId",            MATTER_TLV_CONTEXT_NONE },
    { 2,    "MaxInterval",               MATTER_TLV_CONTEXT_NONE },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.4.3.2: ReportDataMessage
static const matter_tlv_tag_info_t im_report_data_tags[] = {
    { 0,    "SubscriptionId",            MATTER_TLV_CONTEXT_NONE },
    { 1,    "AttributeReports",          MATTER_TLV_CONTEXT_ATTRIBUTE_REPORT },
    { 2,    "EventReports",              MATTER_TLV_CONTEXT_EVENT_REPORT },
    { 3,    "MoreChunkedMessages",       MATTER_TLV_CONTEXT_NONE },
    { 4,    "SuppressResponse",          MATTER_TLV_CONTEXT_NONE },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.7.3.1: WriteRequestMessage
static const matter_tlv_tag_info_t im_write_request_tags[] = {
    { 0,    "SuppressResponse",          MATTER_TLV_CONTEXT_NONE },
    { 1,    "TimedRequest",              MATTER_TLV_CONTEXT_NONE },
    { 2,    "WriteRequests",             MATTER_TLV_CONTEXT_ATTRIBUTE_DATA },
    { 3,    "MoreChunkedMessages",       MATTER_TLV_CONTEXT_NONE },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.7.3.2: WriteResponseMessage
static const matter_tlv_tag_info_t im_write_response_tags[] = {
    { 0,    "WriteResponses",            MATTER_TLV_CONTEXT_ATTRIBUTE_STATUS },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.8.3.1: InvokeRequestMessage
static const matter_tlv_tag_info_t im_invoke_request_tags[] = {
    { 0,    "SuppressResponse",          MATTER_TLV_CONTEXT_NONE },
    { 1,    "TimedRequest",              MATTER_TLV_CONTEXT_NONE },
    { 2,    "InvokeRequests",            MATTER_TLV_CONTEXT_COMMAND_DATA },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.8.3.2: InvokeResponseMessage
static const matter_tlv_tag_info_t im_invoke_response_tags[] = {
    { 0,    "SuppressResponse",          MATTER_TLV_CONTEXT_NONE },
    { 1,    "InvokeResponses",           MATTER_TLV_CONTEXT_INVOKE_RESPONSE_IB },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.6.6: TimedRequestMessage
static const matter_tlv_tag_info_t im_timed_request_tags[] = {
    { 0,    "Timeout",                   MATTER_TLV_CONTEXT_NONE },
    { 0xFF, "InteractionModelRevision",  MATTER_TLV_CONTEXT_NONE },
};

/* --- IM Information Blocks (Sub-structures) --- */

// Section 8.9.2.7: AttributePathIB
static const matter_tlv_tag_info_t im_attribute_path_tags[] = {
    { 0,    "EnableTagCompression",      MATTER_TLV_CONTEXT_NONE },
    { 1,    "Node",                      MATTER_TLV_CONTEXT_NONE },
    { 2,    "Endpoint",                  MATTER_TLV_CONTEXT_NONE },
    { 3,    "Cluster",                   MATTER_TLV_CONTEXT_NONE },
    { 4,    "Attribute",                 MATTER_TLV_CONTEXT_NONE },
    { 5,    "ListIndex",                 MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.8: EventPathIB
static const matter_tlv_tag_info_t im_event_path_tags[] = {
    { 0,    "Node",                      MATTER_TLV_CONTEXT_NONE },
    { 1,    "Endpoint",                  MATTER_TLV_CONTEXT_NONE },
    { 2,    "Cluster",                   MATTER_TLV_CONTEXT_NONE },
    { 3,    "Event",                     MATTER_TLV_CONTEXT_NONE },
    { 4,    "IsUrgent",                  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.9: EventFilterIB
static const matter_tlv_tag_info_t im_event_filter_tags[] = {
    { 0,    "Node",                      MATTER_TLV_CONTEXT_NONE },
    { 1,    "EventMin",                  MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.10: CommandPathIB
static const matter_tlv_tag_info_t im_command_path_tags[] = {
    { 0,    "Endpoint",                  MATTER_TLV_CONTEXT_NONE },
    { 1,    "Cluster",                   MATTER_TLV_CONTEXT_NONE },
    { 2,    "Command",                   MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.11: CommandDataIB
static const matter_tlv_tag_info_t im_command_data_tags[] = {
    { 0,    "CommandPath",               MATTER_TLV_CONTEXT_COMMAND_PATH },
    { 1,    "CommandFields",             MATTER_TLV_CONTEXT_NONE },
    { 2,    "CommandRef",                MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.12: InvokeResponseIB
static const matter_tlv_tag_info_t im_invoke_response_ib_tags[] = {
    { 0,    "Command",                   MATTER_TLV_CONTEXT_COMMAND_DATA },
    { 1,    "Status",                    MATTER_TLV_CONTEXT_COMMAND_STATUS },
};

// Section 8.9.2.13: CommandStatusIB
static const matter_tlv_tag_info_t im_command_status_tags[] = {
    { 0,    "CommandPath",               MATTER_TLV_CONTEXT_COMMAND_PATH },
    { 1,    "Status",                    MATTER_TLV_CONTEXT_STATUS_IB },
};

// Section 8.9.2.14: DataVersionFilterIB
static const matter_tlv_tag_info_t im_data_version_filter_tags[] = {
    { 0,    "Path",                      MATTER_TLV_CONTEXT_CLUSTER_PATH },
    { 1,    "DataVersion",               MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.15: AttributeDataIB
static const matter_tlv_tag_info_t im_attribute_data_tags[] = {
    { 0,    "DataVersion",               MATTER_TLV_CONTEXT_NONE },
    { 1,    "Path",                      MATTER_TLV_CONTEXT_ATTRIBUTE_PATH },
    { 2,    "Data",                      MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.16: AttributeStatusIB
static const matter_tlv_tag_info_t im_attribute_status_tags[] = {
    { 0,    "Path",                      MATTER_TLV_CONTEXT_ATTRIBUTE_PATH },
    { 1,    "Status",                    MATTER_TLV_CONTEXT_STATUS_IB },
};

// Section 8.9.2.17: AttributeReportIB
static const matter_tlv_tag_info_t im_attribute_report_tags[] = {
    { 0,    "AttributeStatus",           MATTER_TLV_CONTEXT_ATTRIBUTE_STATUS },
    { 1,    "AttributeData",             MATTER_TLV_CONTEXT_ATTRIBUTE_DATA },
};

// Section 8.9.2.18: EventDataIB
static const matter_tlv_tag_info_t im_event_data_tags[] = {
    { 0,    "Path",                      MATTER_TLV_CONTEXT_EVENT_PATH },
    { 1,    "EventNumber",               MATTER_TLV_CONTEXT_NONE },
    { 2,    "Priority",                  MATTER_TLV_CONTEXT_NONE },
    { 3,    "EpochTimestamp",            MATTER_TLV_CONTEXT_NONE },
    { 4,    "SystemTimestamp",           MATTER_TLV_CONTEXT_NONE },
    { 5,    "DeltaEpochTimestamp",       MATTER_TLV_CONTEXT_NONE },
    { 6,    "DeltaSystemTimestamp",      MATTER_TLV_CONTEXT_NONE },
    { 0xFE, "Data",                      MATTER_TLV_CONTEXT_NONE },
};

// Section 8.9.2.19: EventStatusIB
static const matter_tlv_tag_info_t im_event_status_tags[] = {
    { 0,    "Path",                      MATTER_TLV_CONTEXT_EVENT_PATH },
    { 1,    "Status",                    MATTER_TLV_CONTEXT_STATUS_IB },
};

// Section 8.9.2.20: EventReportIB
static const matter_tlv_tag_info_t im_event_report_tags[] = {
    { 0,    "EventStatus",               MATTER_TLV_CONTEXT_EVENT_STATUS },
    { 1,    "EventData",                 MATTER_TLV_CONTEXT_EVENT_DATA },
};

// Section 8.9.2.5: StatusIB
static const matter_tlv_tag_info_t im_status_ib_tags[] = {
    { 0,    "Status",                    MATTER_TLV_CONTEXT_NONE },
    { 1,    "ClusterStatus",             MATTER_TLV_CONTEXT_NONE },
};

// ClusterPathIB (subset of AttributePathIB)
static const matter_tlv_tag_info_t im_cluster_path_tags[] = {
    { 0,    "Node",                      MATTER_TLV_CONTEXT_NONE },
    { 1,    "Endpoint",                  MATTER_TLV_CONTEXT_NONE },
    { 2,    "Cluster",                   MATTER_TLV_CONTEXT_NONE },
};

/* Master context lookup table */
typedef struct {
    matter_tlv_context_id_t     context_id;
    const matter_tlv_tag_info_t *tags;
    unsigned                     num_tags;
} matter_tlv_context_def_t;

static const matter_tlv_context_def_t matter_tlv_contexts[] = {
    /* IM action types */
    { MATTER_TLV_CONTEXT_STATUS_RESPONSE,    im_status_response_tags,    array_length(im_status_response_tags) },
    { MATTER_TLV_CONTEXT_READ_REQUEST,       im_read_request_tags,       array_length(im_read_request_tags) },
    { MATTER_TLV_CONTEXT_SUBSCRIBE_REQUEST,  im_subscribe_request_tags,  array_length(im_subscribe_request_tags) },
    { MATTER_TLV_CONTEXT_SUBSCRIBE_RESPONSE, im_subscribe_response_tags, array_length(im_subscribe_response_tags) },
    { MATTER_TLV_CONTEXT_REPORT_DATA,        im_report_data_tags,        array_length(im_report_data_tags) },
    { MATTER_TLV_CONTEXT_WRITE_REQUEST,      im_write_request_tags,      array_length(im_write_request_tags) },
    { MATTER_TLV_CONTEXT_WRITE_RESPONSE,     im_write_response_tags,     array_length(im_write_response_tags) },
    { MATTER_TLV_CONTEXT_INVOKE_REQUEST,     im_invoke_request_tags,     array_length(im_invoke_request_tags) },
    { MATTER_TLV_CONTEXT_INVOKE_RESPONSE,    im_invoke_response_tags,    array_length(im_invoke_response_tags) },
    { MATTER_TLV_CONTEXT_TIMED_REQUEST,      im_timed_request_tags,      array_length(im_timed_request_tags) },
    /* IM Information Blocks */
    { MATTER_TLV_CONTEXT_ATTRIBUTE_PATH,     im_attribute_path_tags,     array_length(im_attribute_path_tags) },
    { MATTER_TLV_CONTEXT_EVENT_PATH,         im_event_path_tags,         array_length(im_event_path_tags) },
    { MATTER_TLV_CONTEXT_COMMAND_PATH,       im_command_path_tags,       array_length(im_command_path_tags) },
    { MATTER_TLV_CONTEXT_COMMAND_DATA,       im_command_data_tags,       array_length(im_command_data_tags) },
    { MATTER_TLV_CONTEXT_INVOKE_RESPONSE_IB, im_invoke_response_ib_tags, array_length(im_invoke_response_ib_tags) },
    { MATTER_TLV_CONTEXT_COMMAND_STATUS,     im_command_status_tags,     array_length(im_command_status_tags) },
    { MATTER_TLV_CONTEXT_STATUS_IB,          im_status_ib_tags,          array_length(im_status_ib_tags) },
    { MATTER_TLV_CONTEXT_ATTRIBUTE_REPORT,   im_attribute_report_tags,   array_length(im_attribute_report_tags) },
    { MATTER_TLV_CONTEXT_ATTRIBUTE_STATUS,   im_attribute_status_tags,   array_length(im_attribute_status_tags) },
    { MATTER_TLV_CONTEXT_ATTRIBUTE_DATA,     im_attribute_data_tags,     array_length(im_attribute_data_tags) },
    { MATTER_TLV_CONTEXT_EVENT_REPORT,       im_event_report_tags,       array_length(im_event_report_tags) },
    { MATTER_TLV_CONTEXT_EVENT_STATUS,       im_event_status_tags,       array_length(im_event_status_tags) },
    { MATTER_TLV_CONTEXT_EVENT_DATA,         im_event_data_tags,         array_length(im_event_data_tags) },
    { MATTER_TLV_CONTEXT_DATA_VERSION_FILTER, im_data_version_filter_tags, array_length(im_data_version_filter_tags) },
    { MATTER_TLV_CONTEXT_CLUSTER_PATH,       im_cluster_path_tags,       array_length(im_cluster_path_tags) },
    { MATTER_TLV_CONTEXT_EVENT_FILTER,       im_event_filter_tags,       array_length(im_event_filter_tags) },
};

/*
 * Look up a context-specific tag name within an IM TLV context.
 * Returns the human-readable field name, or NULL if not found.
 * If child_ctx is non-NULL it is set to the child context for containers.
 */
static const char *
matter_tlv_tag_name(matter_tlv_context_id_t ctx, uint8_t tag,
                    matter_tlv_context_id_t *child_ctx)
{
    for (unsigned i = 0; i < array_length(matter_tlv_contexts); i++) {
        if (matter_tlv_contexts[i].context_id == ctx) {
            const matter_tlv_tag_info_t *tags = matter_tlv_contexts[i].tags;
            for (unsigned j = 0; j < matter_tlv_contexts[i].num_tags; j++) {
                if (tags[j].tag == tag) {
                    if (child_ctx)
                        *child_ctx = tags[j].child_context;
                    return tags[j].name;
                }
            }
            return NULL;
        }
    }
    return NULL;
}

/*
 * Map an Interaction Model protocol opcode to the TLV context
 * for annotating the top-level application payload.
 */
static matter_tlv_context_id_t
matter_im_opcode_context(uint32_t protocol_id, uint32_t opcode)
{
    if (protocol_id != 0x0001) /* Only Interaction Model */
        return MATTER_TLV_CONTEXT_NONE;
    switch (opcode) {
    case 0x01: return MATTER_TLV_CONTEXT_STATUS_RESPONSE;
    case 0x02: return MATTER_TLV_CONTEXT_READ_REQUEST;
    case 0x03: return MATTER_TLV_CONTEXT_SUBSCRIBE_REQUEST;
    case 0x04: return MATTER_TLV_CONTEXT_SUBSCRIBE_RESPONSE;
    case 0x05: return MATTER_TLV_CONTEXT_REPORT_DATA;
    case 0x06: return MATTER_TLV_CONTEXT_WRITE_REQUEST;
    case 0x07: return MATTER_TLV_CONTEXT_WRITE_RESPONSE;
    case 0x08: return MATTER_TLV_CONTEXT_INVOKE_REQUEST;
    case 0x09: return MATTER_TLV_CONTEXT_INVOKE_RESPONSE;
    case 0x0A: return MATTER_TLV_CONTEXT_TIMED_REQUEST;
    default:   return MATTER_TLV_CONTEXT_NONE;
    }
}

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pl_tree);

/*
 * Heuristic dissector for Matter over UDP.
 *
 * Validates the message header and the beginning of the protocol
 * exchange header to decide whether a UDP payload is likely a Matter
 * message.  The checks are intentionally strict to avoid false
 * positives with other UDP protocols (e.g. DNS):
 *   - Minimum 8-byte message header
 *   - Version field (bits 4-7 of message flags) must be 0
 *   - Reserved bit 3 of message flags must be 0
 *   - Session type (bits 0-1 of security flags) must be 0 or 1
 *   - Reserved bits 2-4 of security flags must be 0
 *   - Expected minimum length based on DSIZ
 *   - For unsecured sessions: the exchange header contains a known
 *     protocol ID (Secure Channel, Interaction Model, BDX, or UDC)
 */
static bool
dissect_matter_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Need at least the fixed header: message_flags(1) + session_id(2) +
     * security_flags(1) + message_counter(4) = 8 bytes */
    if (tvb_captured_length(tvb) < MATTER_MIN_LENGTH)
        return false;

    uint8_t message_flags = tvb_get_uint8(tvb, 0);

    /* Version must be 0 (bits 4-7) */
    uint8_t version = (message_flags >> 4) & 0x0F;
    if (version != 0)
        return false;

    /* Bit 3 of message flags is reserved and must be 0 */
    if (message_flags & 0x08)
        return false;

    /* DSIZ (bits 0-1): 0=None, 1=16-bit Group, 2=32-bit Node, 3=64-bit Node */
    uint8_t dsiz = message_flags & 0x03;

    /* Check security flags byte */
    uint8_t security_flags = tvb_get_uint8(tvb, 3);
    uint8_t session_type = security_flags & 0x03;
    /* Session type must be 0 (unicast) or 1 (group) */
    if (session_type > 1)
        return false;

    /* Bits 2-4 of security flags are reserved and must be 0 */
    if (security_flags & 0x1C)
        return false;

    /* Calculate expected minimum length based on header fields */
    unsigned min_len = 8; /* fixed header */
    bool has_source = (message_flags & 0x04) != 0;
    if (has_source)
        min_len += 8; /* 64-bit source node ID */
    static const unsigned dsiz_len[] = { 0, 2, 8, 8 };
    min_len += dsiz_len[dsiz];

    if (tvb_captured_length(tvb) < min_len)
        return false;

    /* For unsecured sessions (session_type==0, session_id==0) the payload
     * is not encrypted so we can peek at the exchange header to validate
     * the protocol ID.  This greatly reduces false positives.
     *
     * For secured sessions the payload is encrypted and cannot be
     * validated, so we do NOT claim them heuristically — the false-
     * positive rate would be far too high.  Secured sessions on the
     * standard port (5540) are handled by the port-based dissector;
     * for non-standard ports the user can use "Decode As → Matter". */
    uint16_t session_id = tvb_get_letohs(tvb, 1);
    bool is_unsecured = (session_type == 0 && session_id == 0);

    if (!is_unsecured)
        return false;

    /* Exchange header: flags(1) + opcode(1) + exchange_id(2) +
     * [vendor_id(2)] + protocol_id(2) = at least 6 bytes */
    unsigned exch_offset = min_len;
    if (tvb_captured_length(tvb) < exch_offset + 6)
        return false;
    uint8_t exch_flags = tvb_get_uint8(tvb, exch_offset);
    unsigned proto_offset = exch_offset + 4; /* past flags+opcode+exchange_id */
    if (exch_flags & EXCHANGE_FLAG_HAS_VENDOR_PROTO)
        proto_offset += 2;
    if (tvb_captured_length(tvb) < proto_offset + 2)
        return false;
    uint16_t proto_id = tvb_get_letohs(tvb, proto_offset);
    /* Only accept known Matter protocol IDs (0x0000-0x0003) */
    if (proto_id > 0x0003)
        return false;

    dissect_matter(tvb, pinfo, tree, data);
    return true;
}

static int
dissect_matter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *matter_tree;
    uint32_t    offset = 0;

    /* info extracted from the packet */
    bool is_unsecured_session;
    uint8_t message_flags = 0;
    uint8_t security_flags = 0;
    uint8_t message_dsiz = 0;
    uint8_t message_session_type = 0;
    uint32_t session_id = 0;
    uint32_t message_counter = 0;
    uint64_t source_node_id = 0;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < MATTER_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Matter");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_matter, tvb, 0, -1, ENC_NA);

    matter_tree = proto_item_add_subtree(ti, ett_matter);

    static int* const message_flag_fields[] = {
        &hf_message_version,
        &hf_message_has_source,
        &hf_message_dsiz,
        NULL
    };
    static int* const message_secflag_fields[] = {
        &hf_message_flag_privacy,
        &hf_message_flag_control,
        &hf_message_flag_extensions,
        &hf_message_session_type,
        NULL
    };

    // Section 4.4.1.2
    proto_tree_add_bitmask(matter_tree, tvb, offset, hf_message_flags, ett_message_flags, message_flag_fields, ENC_LITTLE_ENDIAN);
    message_flags = tvb_get_uint8(tvb, offset);
    message_dsiz = (message_flags & MESSAGE_FLAG_DSIZ_MASK);
    offset += 1;

    // Section 4.4.1.3
    proto_tree_add_item_ret_uint(matter_tree, hf_message_session_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &session_id);
    offset += 2;

    // Section 4.4.1.4
    proto_tree_add_bitmask(matter_tree, tvb, offset, hf_message_security_flags, ett_security_flags, message_secflag_fields, ENC_LITTLE_ENDIAN);
    security_flags = tvb_get_uint8(tvb, offset);
    message_session_type = (security_flags & SECURITY_FLAG_SESSION_TYPE_MASK);
    offset += 1;

    // Section 4.4.1.4: "The Unsecured Session SHALL be indicated
    // when both Session Type and Session ID are set to 0."
    is_unsecured_session = (message_session_type == SECURITY_FLAG_SESSION_TYPE_UNICAST && session_id == 0);

    if (is_unsecured_session)
        col_set_str(pinfo->cinfo, COL_INFO, "Unsecured Session");
    else if (message_session_type == SECURITY_FLAG_SESSION_TYPE_UNICAST)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unicast Session [0x%04x]", session_id);
    else if (message_session_type == SECURITY_FLAG_SESSION_TYPE_GROUP)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Group Session [0x%04x]", session_id);

    // decryption of message privacy is not yet supported,
    // but add an opaque field with the encrypted blob
    // Section 4.8.3
    if (security_flags & SECURITY_FLAG_HAS_PRIVACY) {

        uint32_t privacy_header_length = 4;
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            privacy_header_length += 8;
        }
        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            privacy_header_length += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            privacy_header_length += 2;
        }
        proto_tree_add_bytes_format(matter_tree, hf_message_privacy_header, tvb, offset, privacy_header_length, NULL, "Encrypted Headers");
        offset += privacy_header_length;

    } else {

        // Section 4.4.1.5
        proto_tree_add_item_ret_uint(matter_tree, hf_message_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN, &message_counter);
        offset += 4;

        // Section 4.4.1.6
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            proto_tree_add_item_ret_uint64(matter_tree, hf_message_src_id, tvb, offset, 8, ENC_LITTLE_ENDIAN, &source_node_id);
            offset += 8;
        }

        // Section 4.4.1.7
        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            uint64_t node_id;
            proto_tree_add_item_ret_uint64(matter_tree, hf_message_dest_node_id, tvb, offset, 8, ENC_LITTLE_ENDIAN, &node_id);
            offset += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            unsigned int group_id;
            proto_tree_add_item_ret_uint(matter_tree, hf_message_dest_group_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &group_id);
            offset += 2;
        }

        // Section 4.4.1.8: Message Extensions
        if (security_flags & SECURITY_FLAG_HAS_EXTENSIONS) {
            uint32_t ext_len = 0;
            proto_tree_add_item_ret_uint(matter_tree, hf_message_ext_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ext_len);
            offset += 2;
            if (ext_len > 0) {
                proto_tree_add_item(matter_tree, hf_message_ext_data, tvb, offset, ext_len, ENC_NA);
                offset += ext_len;
            }
        }

    }

    if (is_unsecured_session) {
        proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, -1, "Protocol Payload");
        proto_tree *payload_tree = proto_item_add_subtree(payload_item, ett_payload);
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);

        offset += dissect_matter_payload(next_tvb, pinfo, payload_tree);
    } else {
        uint32_t payload_length = tvb_reported_length_remaining(tvb, offset) - MATTER_MIC_LEN;

        /* Collect all candidate keys from UAT and try each */
        matter_candidate_key_t candidates[MAX_UAT_ENTRIES * 2];
        unsigned num_keys = matter_collect_session_keys(candidates,
                                                       array_length(candidates));
        tvbuff_t *decrypted_tvb = NULL;

        for (unsigned ki = 0; ki < num_keys && !decrypted_tvb; ki++) {
            /* Build a per-key nonce: use the candidate's source_node_id if
             * explicitly provided (from UAT), otherwise fall back to
             * whatever source_node_id appeared in the message header. */
            uint64_t nonce_node_id = candidates[ki].has_node_id
                                   ? candidates[ki].source_node_id
                                   : source_node_id;
            uint8_t nonce[MATTER_NONCE_LEN];
            matter_build_nonce(security_flags, message_counter, nonce_node_id, nonce);

            decrypted_tvb = matter_decrypt_payload(tvb, pinfo, offset,
                                                   payload_length,
                                                   candidates[ki].key, nonce);
        }

        if (decrypted_tvb) {
            /* Decryption succeeded - show decrypted payload */
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Decrypted Payload (%u bytes)", payload_length);
            proto_tree *payload_tree = proto_item_add_subtree(payload_item, ett_payload);

            dissect_matter_payload(decrypted_tvb, pinfo, payload_tree);

            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
        } else if (num_keys > 0) {
            /* Keys were found but none worked */
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Encrypted Payload (%u bytes) [Decryption failed - %u key(s) tried]", payload_length, num_keys);
            expert_add_info_format(pinfo, payload_item, &ei_matter_decryption_failed,
                "Decryption failed: tried %u key(s), none passed MIC verification",
                num_keys);
            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
        } else {
            /* No key found for this session */
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Encrypted Payload (%u bytes) [No keys configured]", payload_length);
            expert_add_info_format(pinfo, payload_item, &ei_matter_decryption_no_key,
                "No decryption keys configured in Matter session keys table");
            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pl_tree)
{
    uint32_t offset = 0;

    uint8_t exchange_flags = 0;

    static int* const exchange_flag_fields[] = {
        &hf_payload_flag_initiator,
        &hf_payload_flag_ack,
        &hf_payload_flag_reliability,
        &hf_payload_flag_secured_extensions,
        &hf_payload_flag_vendor,
        NULL
    };
    // Section 4.4.3.1
    proto_tree_add_bitmask(pl_tree, tvb, offset, hf_payload_exchange_flags, ett_exchange_flags, exchange_flag_fields, ENC_LITTLE_ENDIAN);
    exchange_flags = tvb_get_uint8(tvb, offset);
    offset += 1;

    // Section 4.4.3.2
    uint32_t protocol_opcode = 0;
    proto_tree_add_item_ret_uint(pl_tree, hf_payload_protocol_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN, &protocol_opcode);
    offset += 1;

    // Section 4.4.3.3
    proto_tree_add_item(pl_tree, hf_payload_exchange_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    uint32_t protocol_vendor_id = 0;
    if (exchange_flags & EXCHANGE_FLAG_HAS_VENDOR_PROTO) {
        // NOTE: The Matter specification R1.0 (22-27349) section 4.4 says
        // the Vendor ID comes after the Protocol ID. However, the SDK
        // implementation expects and produces the vendor ID first and the
        // protocol ID afterwards. This was reported, and the maintainers
        // declared it a bug in the *specification*, which will be resolved
        // in a future version:
        // https://github.com/project-chip/connectedhomeip/issues/25003
        // So we parse Vendor ID first, contrary to the current spec.
        proto_tree_add_item_ret_uint(pl_tree, hf_payload_protocol_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &protocol_vendor_id);
        offset += 2;
    }

    // Section 4.4.3.4
    uint32_t protocol_id = 0;
    proto_tree_add_item_ret_uint(pl_tree, hf_payload_protocol_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &protocol_id);
    offset += 2;

    // Look up protocol-specific opcode name for display
    const char *opcode_name = NULL;
    if (protocol_vendor_id == 0 && protocol_id < array_length(opcode_vals_by_protocol)) {
        opcode_name = try_val_to_str(protocol_opcode, opcode_vals_by_protocol[protocol_id]);
    }
    const char *protocol_name = val_to_str_const(protocol_id, protocol_id_vals, "Unknown");
    if (opcode_name) {
        col_set_str(pinfo->cinfo, COL_INFO, opcode_name);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s: Opcode 0x%02x", protocol_name, protocol_opcode);
    }

    // Section 4.4.3.6
    if (exchange_flags & EXCHANGE_FLAG_ACK_MSG) {
        unsigned int ack_counter;
        proto_tree_add_item_ret_uint(pl_tree, hf_payload_ack_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ack_counter);
        offset += 4;
    }

    // Section 4.4.3.7
    if (exchange_flags & EXCHANGE_FLAG_HAS_SECURED_EXT) {
        uint32_t secured_ext_len = 0;
        proto_tree_add_item_ret_uint(pl_tree, hf_payload_secured_ext_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &secured_ext_len);
        offset += 2;
        proto_tree_add_item(pl_tree, hf_payload_secured_ext, tvb, offset, secured_ext_len, ENC_NA);
        offset += secured_ext_len;
    }
    uint32_t application_length = tvb_reported_length_remaining(tvb, offset);
    if (application_length > 0) {
        proto_item *app_item = proto_tree_add_bytes_format(pl_tree, hf_payload_application, tvb, offset, application_length, NULL, "Application payload (%u bytes)", application_length);
        proto_tree *app_tree = proto_item_add_subtree(app_item, ett_payload);
        tvbuff_t *app_tvb = tvb_new_subset_length(tvb, offset, application_length);
        matter_tlv_context_id_t im_ctx = matter_im_opcode_context(protocol_id, protocol_opcode);
        dissect_matter_tlv(app_tvb, pinfo, app_tree, GINT_TO_POINTER(im_ctx));
    }
    offset += application_length;
    return offset;
}

// Dissect the Matter-defined TLV encoding.
// Appendix A: Tag-length-value (TLV) Encoding Format
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_matter_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // For signed and unsigned integer types and for UTF-8 and octet strings,
    // the length is encoded in the lowest 2 bits of the control byte.
    static const int elem_sizes[] = { 1, 2, 4, 8 };

    int length = tvb_reported_length_remaining(tvb, 0);
    int offset = 0;

    /* Extract IM TLV context from the data parameter.  When non-NULL the
     * pointer encodes a matter_tlv_context_id_t via GINT_TO_POINTER. */
    matter_tlv_context_id_t ctx = (data != NULL)
        ? (matter_tlv_context_id_t)GPOINTER_TO_INT(data)
        : MATTER_TLV_CONTEXT_NONE;

    while (offset < length) {

        // The new element is created with initial length set to 1 which accounts
        // for the control byte (tag format and element type). The length will be
        // updated once the element is fully dissected.
        proto_item *ti_element = proto_tree_add_item(tree, hf_matter_tlv_elem, tvb, offset, 1, ENC_NA);
        proto_tree *tree_element = proto_item_add_subtree(ti_element, ett_matter_tlv);
        int base_offset = offset;

        uint32_t control_tag_format = 0;
        uint32_t control_element = 0;

        proto_item *ti_control = proto_tree_add_item(tree_element, hf_matter_tlv_elem_control, tvb, offset, 1, ENC_NA);
        proto_tree *tree_control = proto_item_add_subtree(ti_control, ett_matter_tlv_control);
        // The tag format is determined by the upper 3 bits of the control byte.
        proto_tree_add_item_ret_uint(tree_control, hf_matter_tlv_elem_control_tag_format, tvb, offset, 1, ENC_NA, &control_tag_format);
        // The element type is determined by the lower 5 bits of the control byte.
        proto_tree_add_item_ret_uint(tree_control, hf_matter_tlv_elem_control_element_type, tvb, offset, 1, ENC_NA, &control_element);

        offset += 1;

        proto_item_append_text(ti_element, ": %s", val_to_str_const(control_element, matter_tlv_elem_type_vals, "Unknown"));

        // The control byte 0x18 means "End of Container".
        if (control_tag_format == 0 && control_element == 0x18)
            return offset;

        /* child_ctx tracks the context to pass when recursing into
         * containers.  For anonymous elements it inherits the parent
         * context (correct for array elements); for context-specific
         * tags it is looked up from the IM tag-info tables. */
        matter_tlv_context_id_t child_ctx = MATTER_TLV_CONTEXT_NONE;
        bool is_cluster_tag = false;
        bool is_endpoint_tag = false;
        bool is_attribute_tag = false;

        switch (control_tag_format)
        {
        case 0: // Anonymous Tag Form (0 octets)
            child_ctx = ctx;  /* array elements inherit parent context */
            break;
        case 1: // Context-specific Tag Form (1 octet)
        {
            uint8_t tag_val = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag, tvb, offset, 1, ENC_NA);
            offset += 1;
            if (ctx != MATTER_TLV_CONTEXT_NONE) {
                const char *tag_name = matter_tlv_tag_name(ctx, tag_val, &child_ctx);
                if (tag_name) {
                    if (strcmp(tag_name, "Cluster") == 0) {
                        is_cluster_tag = true;
                    } else if (strcmp(tag_name, "Endpoint") == 0) {
                        is_endpoint_tag = true;
                    } else if (strcmp(tag_name, "Attribute") == 0) {
                        is_attribute_tag = true;
                    } else {
                        proto_item_append_text(ti_element, " (%s)", tag_name);
                    }
                }
            }
            break;
        }
        case 2: // Common Profile Tag Form, 2-octet tag number
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_number_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case 3: // Common Profile Tag Form, 4-octet tag number
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_number_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case 4: // Implicit Profile Tag Form, 2-octet tag number
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_number_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case 5: // Implicit Profile Tag Form, 4-octet tag number
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_number_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case 6: // Fully-qualified Tag Form, 6 octets (vendor 2 + profile 2 + tag 2)
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_profile, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_number_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case 7: // Fully-qualified Tag Form, 8 octets (vendor 2 + profile 2 + tag 4)
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_profile, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_tag_number_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            goto unsupported_control;
        }

        // The string length might be encoded on 1, 2, 4 or 8 octets. In theory,
        // the length can be up to 2^64 - 1 bytes, but in practice, it should be
        // limited to a reasonable value (it should be safe to assume that the
        // length will not exceed 2^16 - 1 bytes).
        uint64_t str_length;

        switch (control_element)
        {
        case 0x00: // Signed Integer, 1-octet value
        case 0x01: // Signed Integer, 2-octet value
        case 0x02: // Signed Integer, 4-octet value
        case 0x03: // Signed Integer, 8-octet value
        case 0x04: // Unsigned Integer, 1-octet value
        case 0x05: // Unsigned Integer, 2-octet value
        case 0x06: // Unsigned Integer, 4-octet value
        case 0x07: // Unsigned Integer, 8-octet value
        {
            // Integer type (signed or unsigned) is encoded in the 3rd bit of the control element.
            int hf = (control_element & 0x04) ? hf_matter_tlv_elem_value_uint : hf_matter_tlv_elem_value_int;
            int size = elem_sizes[control_element & 0x03];
            if ((is_cluster_tag || is_endpoint_tag || is_attribute_tag) &&
                (control_element & 0x04) && size <= 4) {
                uint32_t val = (size == 1) ? tvb_get_uint8(tvb, offset)
                             : (size == 2) ? tvb_get_letohs(tvb, offset)
                             :               tvb_get_letohl(tvb, offset);
                proto_tree_add_item(tree_element, hf, tvb, offset, size, ENC_LITTLE_ENDIAN);
                if (is_cluster_tag) {
                    const char *cluster_name = try_val_to_str(val, matter_cluster_id_vals);
                    if (cluster_name) {
                        proto_item_append_text(ti_element, " (Cluster: %s)", cluster_name);
                        if (!p_get_proto_data(pinfo->pool, pinfo, proto_matter, 0)) {
                            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", cluster_name);
                            p_add_proto_data(pinfo->pool, pinfo, proto_matter, 0, GUINT_TO_POINTER(1));
                        }
                    } else {
                        proto_item_append_text(ti_element, " (Cluster)");
                    }
                } else if (is_endpoint_tag) {
                    proto_item_append_text(ti_element, " (Endpoint: %u)", val);
                } else if (is_attribute_tag) {
                    proto_item_append_text(ti_element, " (Attribute: 0x%04X)", val);
                }
            } else {
                proto_tree_add_item(tree_element, hf, tvb, offset, size, ENC_LITTLE_ENDIAN);
            }
            offset += size;
            break;
        }
        case 0x08: // Boolean False
        case 0x09: // Boolean True
            break;
        case 0x0A: // Floating Point Number, 4-octet value (float)
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_value_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case 0x0B: // Floating Point Number, 8-octet value (double)
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case 0x0C: // UTF-8 String (1-octet length)
        case 0x0D: // UTF-8 String (2-octet length)
        case 0x0E: // UTF-8 String (4-octet length)
        case 0x0F: // UTF-8 String (8-octet length)
        {
            int size = elem_sizes[control_element & 0x03];
            proto_tree_add_item_ret_uint64(tree_element, hf_matter_tlv_elem_length, tvb, offset, size, ENC_LITTLE_ENDIAN, &str_length);
            offset += size;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_value_string, tvb, offset, (int)str_length, ENC_UTF_8);
            offset += (int)str_length;
            break;
        }
        case 0x10: // Octet String (1-octet length)
        case 0x11: // Octet String (2-octet length)
        case 0x12: // Octet String (4-octet length)
        case 0x13: // Octet String (8-octet length)
        {
            int size = elem_sizes[control_element & 0x03];
            proto_tree_add_item_ret_uint64(tree_element, hf_matter_tlv_elem_length, tvb, offset, size, ENC_LITTLE_ENDIAN, &str_length);
            offset += size;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_value_bytes, tvb, offset, (int)str_length, ENC_NA);
            offset += (int)str_length;
            break;
        }
        case 0x14: // Null
            break;
        case 0x15: // Structure
        case 0x16: // Array
        case 0x17: // List
            increment_dissection_depth(pinfo);
            offset += dissect_matter_tlv(tvb_new_subset_remaining(tvb, offset), pinfo, tree_element, GINT_TO_POINTER(child_ctx));
            decrement_dissection_depth(pinfo);
            break;
        default:
            goto unsupported_control;
        }

        proto_item_set_len(ti_element, offset - base_offset);
        continue;

unsupported_control:
        expert_add_info(pinfo, tree_control, &ei_matter_tlv_unsupported_control);
        proto_item_set_len(ti_element, offset - base_offset);
        return length;
    }

    return length;
}

void
proto_register_matter(void)
{
    static hf_register_info hf[] = {
        { &hf_message_flags,
          { "Message Flags", "matter.message.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_message_version,
          { "Version", "matter.message.version",
            FT_UINT8, BASE_DEC, NULL, MESSAGE_FLAG_VERSION_MASK,
            "Message format version", HFILL }
        },
        { &hf_message_has_source,
          { "Has Source ID", "matter.message.has_source_id",
            FT_BOOLEAN, 8, NULL, MESSAGE_FLAG_HAS_SOURCE,
            "Source ID field is present", HFILL }
        },
        { &hf_message_dsiz,
          { "Destination ID Type", "matter.message.dsiz",
            FT_UINT8, BASE_DEC, VALS(dsiz_vals), MESSAGE_FLAG_DSIZ_MASK,
            "Size and meaning of the Destination Node ID field", HFILL }
        },
        { &hf_message_session_id,
          { "Session ID", "matter.message.session_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "The session associated with this message", HFILL }
        },
        { &hf_message_security_flags,
          { "Security Flags", "matter.message.security_flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Message security flags", HFILL }
        },
        { &hf_message_flag_privacy,
          { "Privacy", "matter.message.has_privacy",
            FT_BOOLEAN, 8, NULL, SECURITY_FLAG_HAS_PRIVACY,
            "Whether the message is encoded with privacy enhancements", HFILL }
        },
        { &hf_message_flag_control,
          { "Control", "matter.message.is_control",
            FT_BOOLEAN, 8, NULL, SECURITY_FLAG_IS_CONTROL,
            "Whether this is a control message", HFILL }
        },
        { &hf_message_flag_extensions,
          { "Message Extensions", "matter.message.has_extensions",
            FT_BOOLEAN, 8, NULL, SECURITY_FLAG_HAS_EXTENSIONS,
            "Whether message extensions are present", HFILL }
        },
        { &hf_message_session_type,
          { "Session Type", "matter.message.session_type",
            FT_UINT8, BASE_HEX, VALS(session_type_vals), SECURITY_FLAG_SESSION_TYPE_MASK,
            "The type of session associated with the message", HFILL }
        },
        { &hf_message_counter,
          { "Message Counter", "matter.message.counter",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_message_src_id,
          { "Source Node ID", "matter.message.src_id",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Unique identifier of the source node", HFILL }
        },
        { &hf_message_dest_node_id,
          { "Destination Node ID", "matter.message.dest_node_id",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Unique identifier of the destination node", HFILL }
        },
        { &hf_message_dest_group_id,
          { "Destination Group ID", "matter.message.dest_group_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Unique identifier of the destination group", HFILL }
        },
        { &hf_message_privacy_header,
          { "Encrypted header fields", "matter.message.privacy_header",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Headers encrypted with message privacy", HFILL }
        },
        { &hf_message_ext_length,
          { "Message Extensions Length", "matter.message.ext_length",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Length of message extensions data, in bytes", HFILL }
        },
        { &hf_message_ext_data,
          { "Message Extensions Data", "matter.message.ext_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Message extensions payload", HFILL }
        },
        { &hf_payload,
          { "Payload", "matter.payload",
            FT_NONE, BASE_NONE, NULL, 0,
            "Message Payload", HFILL }
        },
        { &hf_payload_mic,
          { "Integrity Check", "matter.payload.mic",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Message Integrity Check (MIC) for the encrypted payload", HFILL }
        },
        { &hf_payload_exchange_flags,
          { "Exchange Flags", "matter.payload.exchange_flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Flags related to the exchange", HFILL }
        },
        { &hf_payload_flag_initiator,
          { "Initiator", "matter.payload.initiator",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_IS_INITIATOR,
            "Whether the message was sent by the initiator of the exchange", HFILL }
        },
        { &hf_payload_flag_ack,
          { "Acknowledgement", "matter.payload.ack_msg",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_ACK_MSG,
            "Whether the message is an acknowledgement of a previously-received message", HFILL }
        },
        { &hf_payload_flag_reliability,
          { "Reliability", "matter.payload.reliability",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_RELIABILITY,
            "Whether the sender wishes to receive an acknowledgement for this message", HFILL }
        },
        { &hf_payload_flag_secured_extensions,
          { "Secure extensions", "matter.payload.has_secured_ext",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_HAS_SECURED_EXT,
            "Whether this message contains Secured Extensions", HFILL }
        },
        { &hf_payload_flag_vendor,
          { "Has Vendor ID", "matter.payload.has_vendor_protocol",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_HAS_VENDOR_PROTO,
            "Whether this message contains a protocol vendor ID", HFILL }
        },
        { &hf_payload_protocol_opcode,
          { "Protocol Opcode", "matter.payload.protocol_opcode",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Opcode of the message (depends on Protocol ID)", HFILL }
        },
        { &hf_payload_exchange_id,
          { "Exchange ID", "matter.payload.exchange_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "The exchange to which the message belongs", HFILL }
        },
        { &hf_payload_protocol_vendor_id,
          { "Protocol Vendor ID", "matter.payload.protocol_vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Vendor ID namespace for the protocol ID", HFILL }
        },
        { &hf_payload_protocol_id,
          { "Protocol ID", "matter.payload.protocol_id",
            FT_UINT16, BASE_HEX, VALS(protocol_id_vals), 0,
            "The protocol in which the Protocol Opcode of the message is defined", HFILL }
        },
        { &hf_payload_ack_counter,
          { "Acknowledged message counter", "matter.payload.ack_counter",
            FT_UINT32, BASE_DEC, NULL, 0,
            "The message counter of a previous message that is being acknowledged by this message", HFILL }
        },
        { &hf_payload_secured_ext_length,
          { "Secured extensions length", "matter.payload.secured_ext.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Secured extensions payload length, in bytes", HFILL }
        },
        { &hf_payload_secured_ext,
          { "Secured extensions payload", "matter.payload.secured_ext",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_payload_application,
          { "Application payload", "matter.payload.application",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem,
          { "TLV Element", "matter.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Matter-TLV Element", HFILL }
        },
        { &hf_matter_tlv_elem_control,
          { "Control Byte", "matter.tlv.control",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Matter-TLV Control Byte", HFILL }
        },
        { &hf_matter_tlv_elem_control_tag_format,
          { "Tag Format", "matter.tlv.control.tag",
            FT_UINT8, BASE_HEX, VALS(matter_tlv_tag_format_vals), 0xE0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_control_element_type,
          { "Element Type", "matter.tlv.control.element",
            FT_UINT8, BASE_HEX, VALS(matter_tlv_elem_type_vals), 0x1F,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_tag,
          { "Tag", "matter.tlv.tag",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Context-specific tag number", HFILL }
        },
        { &hf_matter_tlv_elem_tag_vendor_id,
          { "Tag Vendor ID", "matter.tlv.tag_vendor",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Vendor ID portion of a fully-qualified tag", HFILL }
        },
        { &hf_matter_tlv_elem_tag_profile,
          { "Tag Profile Number", "matter.tlv.tag_profile",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Profile number portion of a fully-qualified tag", HFILL }
        },
        { &hf_matter_tlv_elem_tag_number_16,
          { "Tag Number", "matter.tlv.tag_number",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            "16-bit tag number", HFILL }
        },
        { &hf_matter_tlv_elem_tag_number_32,
          { "Tag Number", "matter.tlv.tag_number32",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            "32-bit tag number", HFILL }
        },
        { &hf_matter_tlv_elem_length,
          { "Length", "matter.tlv.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_int,
          { "Value", "matter.tlv.value_int",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_uint,
          { "Value", "matter.tlv.value_uint",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_float,
          { "Value", "matter.tlv.value_float",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_double,
          { "Value", "matter.tlv.value_double",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_string,
          { "Value", "matter.tlv.value_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_bytes,
          { "Value", "matter.tlv.value_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_matter,
        &ett_message_flags,
        &ett_security_flags,
        &ett_payload,
        &ett_exchange_flags,
        &ett_matter_tlv,
        &ett_matter_tlv_control,
    };

    static ei_register_info ei[] = {
        { &ei_matter_tlv_unsupported_control,
          { "matter.tlv.control.unsupported", PI_UNDECODED, PI_WARN,
            "Unsupported Matter-TLV control byte", EXPFILL }
        },
        { &ei_matter_decryption_no_key,
          { "matter.decryption.no_key", PI_DECRYPTION, PI_NOTE,
            "No decryption key configured for this session", EXPFILL }
        },
        { &ei_matter_decryption_failed,
          { "matter.decryption.failed", PI_DECRYPTION, PI_WARN,
            "Decryption failed (MIC verification failed for all keys)", EXPFILL }
        },
    };

    /* Register the protocol name and description */
    proto_matter = proto_register_protocol("Matter", "Matter", "matter");
    matter_handle = register_dissector("matter", dissect_matter, proto_matter);
    register_dissector("matter.tlv", dissect_matter_tlv, proto_matter);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_matter, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert = expert_register_protocol(proto_matter);
    expert_register_field_array(expert, ei, array_length(ei));

    module_t *matter_module = prefs_register_protocol(proto_matter, NULL);
    /* UAT for entering CASE session keys directly in preferences */
    static uat_field_t matter_key_uat_fields[] = {
        UAT_FLD_CSTRING(matter_key_uat, initiator_node_id_str, "Initiator Node ID",
                        "64-bit node ID of the session Initiator in hex (e.g. 0xF3AD187FAE395763). "
                        "Used in the nonce when decrypting with the I2R key."),
        UAT_FLD_CSTRING(matter_key_uat, responder_node_id_str, "Responder Node ID",
                        "64-bit node ID of the session Responder in hex (e.g. 0x73EC64A6E69AE0DF). "
                        "Used in the nonce when decrypting with the R2I key."),
        UAT_FLD_CSTRING(matter_key_uat, i2r_key, "I2R Key",
                        "Initiator-to-Responder AES-128 key (32 hex chars, or empty)"),
        UAT_FLD_CSTRING(matter_key_uat, r2i_key, "R2I Key",
                        "Responder-to-Initiator AES-128 key (32 hex chars, or empty)"),
        UAT_END_FIELDS
    };

    uat_t *matter_keys_uat = uat_new("Matter CASE Session Keys",
            sizeof(matter_key_uat_record_t),
            "matter_session_keys",           /* filename */
            true,                            /* from_profile */
            &matter_key_uat_records,         /* data_ptr */
            &num_matter_key_uat_records,     /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,          /* flags */
            NULL,                            /* help (currently wiki page) */
            matter_key_uat_copy_cb,
            matter_key_uat_update_cb,
            matter_key_uat_free_cb,
            matter_key_uat_apply,
            matter_key_uat_reset,
            matter_key_uat_fields);

    prefs_register_uat_preference(matter_module, "session_keys",
            "CASE session keys",
            "A table of Matter CASE/PASE session keys for decryption.\n"
            "Enter the Initiator and Responder node IDs (0x-prefixed hex)\n"
            "and the I2R and/or R2I AES-128 keys (32 hex characters each).\n"
            "Node IDs are needed for the decryption nonce when they are not\n"
            "present in the message header. All entries are tried against\n"
            "every secured packet; MIC verification determines the match.",
            matter_keys_uat);
}

void
proto_reg_handoff_matter(void)
{
    dissector_add_uint_with_preference("udp.port", MATTER_DEFAULT_PORT, matter_handle);
    heur_dissector_add("udp", dissect_matter_heur, "Matter over UDP", "matter_udp", proto_matter, HEURISTIC_ENABLE);
}
