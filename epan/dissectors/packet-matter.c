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
 * Specification Version 1.6.1.
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <wsutil/array.h>
#include <wsutil/wsgcrypt.h>
#include "packet-matter-clusters.h"

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
static int hf_group_addr_fabric_id;
static int hf_group_addr_group_id;
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
static int hf_sc_status_general_code;
static int hf_sc_status_protocol_id;
static int hf_sc_status_protocol_vendor_id;
static int hf_sc_status_protocol_code;
static int hf_sc_status_protocol_data;

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
 * Keys are entered through the "Matter CASE Session Keys" UAT below.
 * The session keys can be exported from the Matter SDK by instrumenting
 * the CASE/PASE session establishment code.
 */
#define MATTER_SESSION_KEY_LEN          16
#define MATTER_COMPRESSED_FABRIC_ID_LEN 8
#define MATTER_NONCE_LEN                13
#define MATTER_MIC_LEN                  16  /* AES-128-CCM authentication tag */

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

    /* Parsed forms of the fields above, filled in by matter_key_uat_update_cb */
    uint64_t initiator_node_id;
    uint64_t responder_node_id;
    bool     has_initiator_node_id;
    bool     has_responder_node_id;
    uint8_t  i2r_key_bytes[MATTER_SESSION_KEY_LEN];
    uint8_t  r2i_key_bytes[MATTER_SESSION_KEY_LEN];
    bool     has_i2r_key;
    bool     has_r2i_key;
} matter_key_uat_record_t;

static matter_key_uat_record_t *matter_key_uat_records;
static unsigned                 num_matter_key_uat_records;

static void *
matter_key_uat_copy_cb(void *dest, const void *source, size_t len _U_)
{
    const matter_key_uat_record_t *s = (const matter_key_uat_record_t *)source;
    matter_key_uat_record_t       *d = (matter_key_uat_record_t *)dest;
    *d = *s;  /* parsed node IDs and key bytes */
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
    rec->has_initiator_node_id = false;
    if (rec->initiator_node_id_str && *rec->initiator_node_id_str) {
        char *endp2 = NULL;
        rec->initiator_node_id = g_ascii_strtoull(rec->initiator_node_id_str, &endp2, 0);
        if (endp2 == rec->initiator_node_id_str || *endp2 != '\0') {
            *error = g_strdup("Initiator Node ID must be a number (decimal or 0x hex)");
            return false;
        }
        rec->has_initiator_node_id = true;
    }
    rec->has_responder_node_id = false;
    if (rec->responder_node_id_str && *rec->responder_node_id_str) {
        char *endp2 = NULL;
        rec->responder_node_id = g_ascii_strtoull(rec->responder_node_id_str, &endp2, 0);
        if (endp2 == rec->responder_node_id_str || *endp2 != '\0') {
            *error = g_strdup("Responder Node ID must be a number (decimal or 0x hex)");
            return false;
        }
        rec->has_responder_node_id = true;
    }

    /* At least one key must be provided */
    rec->has_i2r_key = rec->i2r_key && *rec->i2r_key;
    rec->has_r2i_key = rec->r2i_key && *rec->r2i_key;
    if (!rec->has_i2r_key && !rec->has_r2i_key) {
        *error = g_strdup("At least one key (I2R or R2I) must be provided");
        return false;
    }

    /* Validate key lengths and hex encoding */
    if (rec->has_i2r_key) {
        if (strlen(rec->i2r_key) != 2 * MATTER_SESSION_KEY_LEN) {
            *error = g_strdup("I2R key must be exactly 32 hex characters");
            return false;
        }
        if (!hex_to_bytes(rec->i2r_key, rec->i2r_key_bytes, MATTER_SESSION_KEY_LEN)) {
            *error = g_strdup("I2R key contains invalid hex characters");
            return false;
        }
    }
    if (rec->has_r2i_key) {
        if (strlen(rec->r2i_key) != 2 * MATTER_SESSION_KEY_LEN) {
            *error = g_strdup("R2I key must be exactly 32 hex characters");
            return false;
        }
        if (!hex_to_bytes(rec->r2i_key, rec->r2i_key_bytes, MATTER_SESSION_KEY_LEN)) {
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
 * Group key derivation (Sections 4.16.2 and 4.17.2), all HKDF-SHA256:
 *   OperationalGroupKey = HKDF(EpochKey,  salt=CompressedFabricID, info="GroupKey v1.0", 16)
 *   GroupSessionID      = HKDF(OperationalKey, salt=[], info="GroupKeyHash", 2)  (big-endian)
 *   PrivacyKey          = HKDF(OperationalKey, salt=[], info="PrivacyKey",   16)
 */
static void
matter_hkdf_sha256(const uint8_t *ikm, unsigned ikm_len, const uint8_t *salt, unsigned salt_len,
                   const uint8_t *info, unsigned info_len, uint8_t *out, unsigned out_len)
{
    uint8_t prk[HASH_SHA2_256_LENGTH];
    hkdf_extract(GCRY_MD_SHA256, salt, salt_len, ikm, ikm_len, prk);
    hkdf_expand(GCRY_MD_SHA256, prk, sizeof(prk), info, info_len, out, out_len);
}

static void
matter_derive_group_keys(const uint8_t *epoch_key, const uint8_t *compressed_fabric_id,
                         uint8_t *operational_key, uint8_t *privacy_key, uint16_t *group_session_id)
{
    static const uint8_t info_group[]   = "GroupKey v1.0"; /* without the NUL terminator */
    static const uint8_t info_hash[]    = "GroupKeyHash";
    static const uint8_t info_privacy[] = "PrivacyKey";
    uint8_t gsid[2];

    matter_hkdf_sha256(epoch_key, MATTER_SESSION_KEY_LEN, compressed_fabric_id, MATTER_COMPRESSED_FABRIC_ID_LEN,
                       info_group, sizeof(info_group) - 1, operational_key, MATTER_SESSION_KEY_LEN);
    matter_hkdf_sha256(operational_key, MATTER_SESSION_KEY_LEN, NULL, 0,
                       info_hash, sizeof(info_hash) - 1, gsid, sizeof(gsid));
    *group_session_id = (uint16_t)((gsid[0] << 8) | gsid[1]); /* big-endian */
    matter_hkdf_sha256(operational_key, MATTER_SESSION_KEY_LEN, NULL, 0,
                       info_privacy, sizeof(info_privacy) - 1, privacy_key, MATTER_SESSION_KEY_LEN);
}

/*
 * UAT for group (multicast) keys. Each row holds an epoch key and the
 * compressed fabric ID; the operational key, privacy key and group
 * session ID are derived from them when the row is committed.
 */
typedef struct {
    char *epoch_key;              /* 32 hex chars (16 bytes) */
    char *compressed_fabric_id;   /* 16 hex chars (8 bytes) */

    uint8_t  epoch_key_bytes[MATTER_SESSION_KEY_LEN];
    uint8_t  compressed_fabric_id_bytes[MATTER_COMPRESSED_FABRIC_ID_LEN];
    uint8_t  operational_key[MATTER_SESSION_KEY_LEN];
    uint8_t  privacy_key[MATTER_SESSION_KEY_LEN];
    uint16_t group_session_id;
} matter_group_key_uat_record_t;

static matter_group_key_uat_record_t *matter_group_key_uat_records;
static unsigned                       num_matter_group_key_uat_records;

static void *
matter_group_key_uat_copy_cb(void *dest, const void *source, size_t len _U_)
{
    const matter_group_key_uat_record_t *s = (const matter_group_key_uat_record_t *)source;
    matter_group_key_uat_record_t       *d = (matter_group_key_uat_record_t *)dest;
    *d = *s;
    d->epoch_key            = g_strdup(s->epoch_key);
    d->compressed_fabric_id = g_strdup(s->compressed_fabric_id);
    return dest;
}

static bool
matter_group_key_uat_update_cb(void *r, char **error)
{
    matter_group_key_uat_record_t *rec = (matter_group_key_uat_record_t *)r;

    if (!rec->epoch_key || strlen(rec->epoch_key) != 2 * MATTER_SESSION_KEY_LEN ||
        !hex_to_bytes(rec->epoch_key, rec->epoch_key_bytes, MATTER_SESSION_KEY_LEN)) {
        *error = g_strdup("Epoch key must be exactly 32 hex characters");
        return false;
    }
    if (!rec->compressed_fabric_id || strlen(rec->compressed_fabric_id) != 2 * MATTER_COMPRESSED_FABRIC_ID_LEN ||
        !hex_to_bytes(rec->compressed_fabric_id, rec->compressed_fabric_id_bytes, MATTER_COMPRESSED_FABRIC_ID_LEN)) {
        *error = g_strdup("Compressed Fabric ID must be exactly 16 hex characters");
        return false;
    }
    matter_derive_group_keys(rec->epoch_key_bytes, rec->compressed_fabric_id_bytes,
                             rec->operational_key, rec->privacy_key, &rec->group_session_id);
    return true;
}

static void
matter_group_key_uat_free_cb(void *r)
{
    matter_group_key_uat_record_t *rec = (matter_group_key_uat_record_t *)r;
    g_free(rec->epoch_key);
    g_free(rec->compressed_fabric_id);
}

UAT_CSTRING_CB_DEF(matter_group_key_uat, epoch_key, matter_group_key_uat_record_t)
UAT_CSTRING_CB_DEF(matter_group_key_uat, compressed_fabric_id, matter_group_key_uat_record_t)

/*
 * A session key together with the source node ID to use in the nonce.
 * The key that successfully decrypts a message is remembered per session
 * ID for the rest of the capture, so that a large capture does not try
 * every configured key on every packet.
 */
typedef struct {
    uint8_t  key[MATTER_SESSION_KEY_LEN];
    uint64_t node_id;      /* Source node ID for the nonce ... */
    bool     has_node_id;  /* ... or false to use the one from the message header */
} matter_session_key_t;

/* Session ID -> matter_session_key_t*, reset for each capture file */
static wmem_map_t *matter_session_key_cache;

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
                       uint32_t payload_off, uint32_t payload_len,
                       const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, unsigned aad_len)
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
    ccm_lengths[1] = aad_len;
    ccm_lengths[2] = MATTER_MIC_LEN;

    gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Authenticate the message header (AAD) */
    gcrypt_err = gcry_cipher_authenticate(cipher_hd, aad, aad_len);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Decrypt the payload */
    uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, payload_len);
    gcrypt_err = gcry_cipher_decrypt(cipher_hd, decrypted, payload_len,
        tvb_get_ptr(tvb, payload_off, payload_len), payload_len);
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

    const uint8_t *expected_mic = tvb_get_ptr(tvb, payload_off + payload_len, MATTER_MIC_LEN);
    if (memcmp(tag, expected_mic, MATTER_MIC_LEN) != 0) {
        /* MIC mismatch - wrong key or corrupted message */
        return NULL;
    }

    /* Create a tvbuff from the decrypted data */
    tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, decrypted, payload_len, payload_len);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Matter Payload");
    return decrypted_tvb;
}

static tvbuff_t *
matter_try_session_key(tvbuff_t *tvb, packet_info *pinfo, uint32_t offset, uint32_t payload_length,
                       uint8_t security_flags, uint32_t message_counter, uint64_t source_node_id,
                       const matter_session_key_t *sk)
{
    uint8_t nonce[MATTER_NONCE_LEN];
    matter_build_nonce(security_flags, message_counter,
                       sk->has_node_id ? sk->node_id : source_node_id, nonce);
    return matter_decrypt_payload(tvb, pinfo, offset, payload_length, sk->key, nonce,
                                  tvb_get_ptr(tvb, 0, offset), offset);
}

/*
 * Matter privacy obfuscation (Section 4.8.2) is AES-CCM keystream with the
 * tag discarded, so decrypting is the same operation as encrypting: running
 * the obfuscated bytes back through CCM yields the plaintext. Returns false
 * on any libgcrypt error.
 */
static bool
matter_privacy_deobfuscate(const uint8_t *privacy_key, const uint8_t *nonce,
                           const uint8_t *in, unsigned len, uint8_t *out)
{
    gcry_cipher_hd_t hd;
    uint64_t ccm_lengths[3] = { len, 0, MATTER_MIC_LEN };
    bool ok = false;

    if (gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0))
        return false;
    if (gcry_cipher_setkey(hd, privacy_key, MATTER_SESSION_KEY_LEN) == 0 &&
        gcry_cipher_setiv(hd, nonce, MATTER_NONCE_LEN) == 0 &&
        gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths)) == 0 &&
        gcry_cipher_encrypt(hd, out, len, in, len) == 0) {
        ok = true;
    }
    gcry_cipher_close(hd);
    return ok;
}

/*
 * Attempt to decrypt a privacy-obfuscated group message with one candidate
 * operational/privacy key pair. On success returns the decrypted payload
 * tvb, writes the recovered message counter and source node ID, and fills
 * deobf_header (privacy_len bytes) with the deobfuscated header region.
 *
 * The privacy nonce is sessionId (2, big-endian) || MIC[5..16] (Section
 * 4.8.2), and the AEAD additional data is the *decrypted* message header.
 */
static tvbuff_t *
matter_try_group_privacy(tvbuff_t *tvb, packet_info *pinfo, uint32_t privacy_off,
                         uint32_t privacy_len, uint32_t payload_off, uint32_t payload_len,
                         uint32_t session_id, uint8_t message_flags,
                         const uint8_t *op_key, const uint8_t *privacy_key,
                         uint8_t *deobf_header, uint32_t *out_counter, uint64_t *out_source)
{
    const uint8_t *mic = tvb_get_ptr(tvb, payload_off + payload_len, MATTER_MIC_LEN);
    uint8_t priv_nonce[MATTER_NONCE_LEN];
    priv_nonce[0] = (uint8_t)(session_id >> 8);   /* session ID, big-endian */
    priv_nonce[1] = (uint8_t)(session_id);
    memcpy(&priv_nonce[2], mic + 5, MATTER_NONCE_LEN - 2);

    if (!matter_privacy_deobfuscate(privacy_key, priv_nonce,
                                    tvb_get_ptr(tvb, privacy_off, privacy_len), privacy_len, deobf_header))
        return NULL;

    uint32_t counter = deobf_header[0] | (deobf_header[1] << 8) |
                       (deobf_header[2] << 16) | ((uint32_t)deobf_header[3] << 24);
    uint64_t source = 0;
    if (message_flags & 0x04) {   /* MESSAGE_FLAG_HAS_SOURCE */
        for (unsigned i = 0; i < 8; i++)
            source |= (uint64_t)deobf_header[4 + i] << (8 * i);
    }

    /* AAD is the full decrypted header: the cleartext fixed part (up to the
     * privacy region) followed by the deobfuscated region. */
    uint8_t *aad = (uint8_t *)wmem_alloc(pinfo->pool, payload_off);
    tvb_memcpy(tvb, aad, 0, privacy_off);
    memcpy(aad + privacy_off, deobf_header, privacy_len);

    uint8_t nonce[MATTER_NONCE_LEN];
    matter_build_nonce(tvb_get_uint8(tvb, 3), counter, source, nonce);

    tvbuff_t *dec = matter_decrypt_payload(tvb, pinfo, payload_off, payload_len, op_key, nonce,
                                           aad, payload_off);
    if (dec) {
        *out_counter = counter;
        *out_source = source;
    }
    return dec;
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
    { 3, "Reserved" },
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

// Section 4.10.1.1: Secure Channel Protocol Opcodes
#define SC_OPCODE_MSG_COUNTER_SYNC_REQ  0x00
#define SC_OPCODE_MSG_COUNTER_SYNC_RSP  0x01
#define SC_OPCODE_STANDALONE_ACK        0x10
#define SC_OPCODE_PBKDF_PARAM_REQUEST   0x20
#define SC_OPCODE_PBKDF_PARAM_RESPONSE  0x21
#define SC_OPCODE_PASE_PAKE1            0x22
#define SC_OPCODE_PASE_PAKE2            0x23
#define SC_OPCODE_PASE_PAKE3            0x24
#define SC_OPCODE_CASE_SIGMA1           0x30
#define SC_OPCODE_CASE_SIGMA2           0x31
#define SC_OPCODE_CASE_SIGMA3           0x32
#define SC_OPCODE_CASE_SIGMA2_RESUME    0x33
#define SC_OPCODE_STATUS_REPORT         0x40
#define SC_OPCODE_ICD_CHECK_IN          0x50

static const value_string sc_opcode_vals[] = {
    { SC_OPCODE_MSG_COUNTER_SYNC_REQ,  "MsgCounterSyncReq" },
    { SC_OPCODE_MSG_COUNTER_SYNC_RSP,  "MsgCounterSyncRsp" },
    { SC_OPCODE_STANDALONE_ACK,        "MRP Standalone Acknowledgement" },
    { SC_OPCODE_PBKDF_PARAM_REQUEST,   "PBKDFParamRequest" },
    { SC_OPCODE_PBKDF_PARAM_RESPONSE,  "PBKDFParamResponse" },
    { SC_OPCODE_PASE_PAKE1,            "PASE Pake1" },
    { SC_OPCODE_PASE_PAKE2,            "PASE Pake2" },
    { SC_OPCODE_PASE_PAKE3,            "PASE Pake3" },
    { SC_OPCODE_CASE_SIGMA1,           "CASE Sigma1" },
    { SC_OPCODE_CASE_SIGMA2,           "CASE Sigma2" },
    { SC_OPCODE_CASE_SIGMA3,           "CASE Sigma3" },
    { SC_OPCODE_CASE_SIGMA2_RESUME,    "CASE Sigma2Resume" },
    { SC_OPCODE_STATUS_REPORT,         "StatusReport" },
    { SC_OPCODE_ICD_CHECK_IN,          "ICD CheckIn" },
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

// Section 5.3.1: User Directed Commissioning Protocol Opcodes
static const value_string udc_opcode_vals[] = {
    { 0x00, "IdentificationDeclaration" },
    { 0x01, "CommissionerDeclaration" },
    { 0, NULL }
};

// Section 4.10.1.3 / Appendix 7.1: StatusReport General Codes
static const value_string sc_status_general_code_vals[] = {
    { 0,  "SUCCESS" },
    { 1,  "FAILURE" },
    { 2,  "BAD_PRECONDITION" },
    { 3,  "OUT_OF_RANGE" },
    { 4,  "BAD_REQUEST" },
    { 5,  "UNSUPPORTED" },
    { 6,  "UNEXPECTED" },
    { 7,  "RESOURCE_EXHAUSTED" },
    { 8,  "BUSY" },
    { 9,  "TIMEOUT" },
    { 10, "CONTINUE" },
    { 11, "ABORTED" },
    { 12, "INVALID_ARGUMENT" },
    { 13, "NOT_FOUND" },
    { 14, "ALREADY_EXISTS" },
    { 15, "PERMISSION_DENIED" },
    { 16, "DATA_LOSS" },
    { 17, "MESSAGE_TOO_LARGE" },
    { 0, NULL }
};

// Section 4.10.1.3.1: Secure Channel Protocol Codes
static const value_string sc_status_protocol_code_vals[] = {
    { 0x0000, "SESSION_ESTABLISHMENT_SUCCESS" },
    { 0x0001, "NO_SHARED_TRUST_ROOTS" },
    { 0x0002, "INVALID_PARAMETER" },
    { 0x0003, "CLOSE_SESSION" },
    { 0x0004, "BUSY" },
    { 0, NULL }
};

static const value_string *opcode_vals_by_protocol[] = {
    sc_opcode_vals,   // 0x0000: Secure Channel
    im_opcode_vals,   // 0x0001: Interaction Model
    bdx_opcode_vals,  // 0x0002: BDX
    udc_opcode_vals,  // 0x0003: User Directed Commissioning
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
 * TLV context annotation tables.
 *
 * The context-specific tags of an application payload carry semantic
 * meaning defined by the spec for the message being sent: the Interaction
 * Model messages (Sections 8.4-8.9) and the PASE and CASE session
 * establishment messages (Sections 4.14 and 4.15).  The tables below map
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
    /* Secure Channel session establishment (Sections 4.14 and 4.15) */
    MATTER_TLV_CONTEXT_PBKDF_PARAM_REQUEST,
    MATTER_TLV_CONTEXT_PBKDF_PARAM_RESPONSE,
    MATTER_TLV_CONTEXT_PBKDF_PARAMETERS,
    MATTER_TLV_CONTEXT_PASE_PAKE1,
    MATTER_TLV_CONTEXT_PASE_PAKE2,
    MATTER_TLV_CONTEXT_PASE_PAKE3,
    MATTER_TLV_CONTEXT_CASE_SIGMA1,
    MATTER_TLV_CONTEXT_CASE_SIGMA2,
    MATTER_TLV_CONTEXT_CASE_SIGMA2_RESUME,
    MATTER_TLV_CONTEXT_CASE_SIGMA3,
    MATTER_TLV_CONTEXT_SESSION_PARAMETERS,
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
    { 2,    "MoreChunkedMessages",       MATTER_TLV_CONTEXT_NONE },
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
    { 6,    "WildcardPathFlags",         MATTER_TLV_CONTEXT_NONE },
    { 7,    "WildcardFilterConfigurationVersion", MATTER_TLV_CONTEXT_NONE },
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
    { 7,    "Data",                      MATTER_TLV_CONTEXT_NONE },
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

static int dissect_matter_tlv_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       int hf_tag, matter_tlv_context_id_t ctx);

/* --- Secure Channel session establishment --- */

// Section 4.13.2.2: Session Parameters (formerly MRP Parameters)
static const matter_tlv_tag_info_t sc_session_parameters_tags[] = {
    { 1,    "SESSION_IDLE_INTERVAL",      MATTER_TLV_CONTEXT_NONE },
    { 2,    "SESSION_ACTIVE_INTERVAL",    MATTER_TLV_CONTEXT_NONE },
    { 3,    "SESSION_ACTIVE_THRESHOLD",   MATTER_TLV_CONTEXT_NONE },
    { 4,    "DATA_MODEL_REVISION",        MATTER_TLV_CONTEXT_NONE },
    { 5,    "INTERACTION_MODEL_REVISION", MATTER_TLV_CONTEXT_NONE },
    { 6,    "SPECIFICATION_VERSION",      MATTER_TLV_CONTEXT_NONE },
    { 7,    "MAX_PATHS_PER_INVOKE",       MATTER_TLV_CONTEXT_NONE },
    { 8,    "SUPPORTED_TRANSPORTS",       MATTER_TLV_CONTEXT_NONE },
    { 9,    "MAX_TCP_MESSAGE_SIZE",       MATTER_TLV_CONTEXT_NONE },
};

// Section 4.14.1.2: PBKDFParamRequest
static const matter_tlv_tag_info_t sc_pbkdf_param_request_tags[] = {
    { 1,    "initiatorRandom",           MATTER_TLV_CONTEXT_NONE },
    { 2,    "initiatorSessionId",        MATTER_TLV_CONTEXT_NONE },
    { 3,    "passcodeId",                MATTER_TLV_CONTEXT_NONE },
    { 4,    "hasPBKDFParameters",        MATTER_TLV_CONTEXT_NONE },
    { 5,    "initiatorSessionParams",    MATTER_TLV_CONTEXT_SESSION_PARAMETERS },
};

// Section 4.14.1.3: PBKDFParamResponse
static const matter_tlv_tag_info_t sc_pbkdf_param_response_tags[] = {
    { 1,    "initiatorRandom",           MATTER_TLV_CONTEXT_NONE },
    { 2,    "responderRandom",           MATTER_TLV_CONTEXT_NONE },
    { 3,    "responderSessionId",        MATTER_TLV_CONTEXT_NONE },
    { 4,    "pbkdf_parameters",          MATTER_TLV_CONTEXT_PBKDF_PARAMETERS },
    { 5,    "responderSessionParams",    MATTER_TLV_CONTEXT_SESSION_PARAMETERS },
};

// Section 4.14.1.3: Crypto_PBKDFParameterSet
static const matter_tlv_tag_info_t sc_pbkdf_parameters_tags[] = {
    { 1,    "iterations",                MATTER_TLV_CONTEXT_NONE },
    { 2,    "salt",                      MATTER_TLV_CONTEXT_NONE },
};

// Section 4.14.1.4: Pake1
static const matter_tlv_tag_info_t sc_pase_pake1_tags[] = {
    { 1,    "pA",                        MATTER_TLV_CONTEXT_NONE },
};

// Section 4.14.1.5: Pake2
static const matter_tlv_tag_info_t sc_pase_pake2_tags[] = {
    { 1,    "pB",                        MATTER_TLV_CONTEXT_NONE },
    { 2,    "cB",                        MATTER_TLV_CONTEXT_NONE },
};

// Section 4.14.1.6: Pake3
static const matter_tlv_tag_info_t sc_pase_pake3_tags[] = {
    { 1,    "cA",                        MATTER_TLV_CONTEXT_NONE },
};

// Section 4.15.2.2: Sigma1
static const matter_tlv_tag_info_t sc_case_sigma1_tags[] = {
    { 1,    "initiatorRandom",           MATTER_TLV_CONTEXT_NONE },
    { 2,    "initiatorSessionId",        MATTER_TLV_CONTEXT_NONE },
    { 3,    "destinationId",             MATTER_TLV_CONTEXT_NONE },
    { 4,    "initiatorEphPubKey",        MATTER_TLV_CONTEXT_NONE },
    { 5,    "initiatorSessionParams",    MATTER_TLV_CONTEXT_SESSION_PARAMETERS },
    { 6,    "resumptionID",              MATTER_TLV_CONTEXT_NONE },
    { 7,    "initiatorResumeMIC",        MATTER_TLV_CONTEXT_NONE },
};

// Section 4.15.2.3: Sigma2
static const matter_tlv_tag_info_t sc_case_sigma2_tags[] = {
    { 1,    "responderRandom",           MATTER_TLV_CONTEXT_NONE },
    { 2,    "responderSessionId",        MATTER_TLV_CONTEXT_NONE },
    { 3,    "responderEphPubKey",        MATTER_TLV_CONTEXT_NONE },
    { 4,    "encrypted2",                MATTER_TLV_CONTEXT_NONE },
    { 5,    "responderSessionParams",    MATTER_TLV_CONTEXT_SESSION_PARAMETERS },
};

// Section 4.15.2.4: Sigma2_Resume
static const matter_tlv_tag_info_t sc_case_sigma2_resume_tags[] = {
    { 1,    "resumptionID",              MATTER_TLV_CONTEXT_NONE },
    { 2,    "sigma2ResumeMIC",           MATTER_TLV_CONTEXT_NONE },
    { 3,    "responderSessionID",        MATTER_TLV_CONTEXT_NONE },
    { 4,    "responderSessionParams",    MATTER_TLV_CONTEXT_SESSION_PARAMETERS },
};

// Section 4.15.2.5: Sigma3
static const matter_tlv_tag_info_t sc_case_sigma3_tags[] = {
    { 1,    "encrypted3",                MATTER_TLV_CONTEXT_NONE },
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
    /* Secure Channel session establishment */
    { MATTER_TLV_CONTEXT_PBKDF_PARAM_REQUEST,  sc_pbkdf_param_request_tags,  array_length(sc_pbkdf_param_request_tags) },
    { MATTER_TLV_CONTEXT_PBKDF_PARAM_RESPONSE, sc_pbkdf_param_response_tags, array_length(sc_pbkdf_param_response_tags) },
    { MATTER_TLV_CONTEXT_PBKDF_PARAMETERS,     sc_pbkdf_parameters_tags,     array_length(sc_pbkdf_parameters_tags) },
    { MATTER_TLV_CONTEXT_PASE_PAKE1,           sc_pase_pake1_tags,           array_length(sc_pase_pake1_tags) },
    { MATTER_TLV_CONTEXT_PASE_PAKE2,           sc_pase_pake2_tags,           array_length(sc_pase_pake2_tags) },
    { MATTER_TLV_CONTEXT_PASE_PAKE3,           sc_pase_pake3_tags,           array_length(sc_pase_pake3_tags) },
    { MATTER_TLV_CONTEXT_CASE_SIGMA1,          sc_case_sigma1_tags,          array_length(sc_case_sigma1_tags) },
    { MATTER_TLV_CONTEXT_CASE_SIGMA2,          sc_case_sigma2_tags,          array_length(sc_case_sigma2_tags) },
    { MATTER_TLV_CONTEXT_CASE_SIGMA2_RESUME,   sc_case_sigma2_resume_tags,   array_length(sc_case_sigma2_resume_tags) },
    { MATTER_TLV_CONTEXT_CASE_SIGMA3,          sc_case_sigma3_tags,          array_length(sc_case_sigma3_tags) },
    { MATTER_TLV_CONTEXT_SESSION_PARAMETERS,   sc_session_parameters_tags,   array_length(sc_session_parameters_tags) },
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
 * Map a protocol opcode to the TLV context for annotating the top-level
 * application payload.
 */
static matter_tlv_context_id_t
matter_payload_context(uint32_t vendor_id, uint32_t protocol_id, uint32_t opcode)
{
    if (vendor_id != 0)
        return MATTER_TLV_CONTEXT_NONE;

    if (protocol_id == 0x0000) { /* Secure Channel */
        switch (opcode) {
        case SC_OPCODE_PBKDF_PARAM_REQUEST:  return MATTER_TLV_CONTEXT_PBKDF_PARAM_REQUEST;
        case SC_OPCODE_PBKDF_PARAM_RESPONSE: return MATTER_TLV_CONTEXT_PBKDF_PARAM_RESPONSE;
        case SC_OPCODE_PASE_PAKE1:           return MATTER_TLV_CONTEXT_PASE_PAKE1;
        case SC_OPCODE_PASE_PAKE2:           return MATTER_TLV_CONTEXT_PASE_PAKE2;
        case SC_OPCODE_PASE_PAKE3:           return MATTER_TLV_CONTEXT_PASE_PAKE3;
        case SC_OPCODE_CASE_SIGMA1:          return MATTER_TLV_CONTEXT_CASE_SIGMA1;
        case SC_OPCODE_CASE_SIGMA2:          return MATTER_TLV_CONTEXT_CASE_SIGMA2;
        case SC_OPCODE_CASE_SIGMA3:          return MATTER_TLV_CONTEXT_CASE_SIGMA3;
        case SC_OPCODE_CASE_SIGMA2_RESUME:   return MATTER_TLV_CONTEXT_CASE_SIGMA2_RESUME;
        default:                             return MATTER_TLV_CONTEXT_NONE;
        }
    }

    if (protocol_id == 0x0001) { /* Interaction Model */
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

    return MATTER_TLV_CONTEXT_NONE;
}

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pl_tree);
static int
dissect_matter_status_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pl_tree);

// Section 8.10.1: Interaction Model status codes (used in StatusIB and in
// a StatusReport whose Protocol ID is Interaction Model).
static const value_string matter_im_status_vals[] = {
    { 0x00, "SUCCESS" },                 { 0x01, "FAILURE" },
    { 0x7D, "INVALID_SUBSCRIPTION" },    { 0x7E, "UNSUPPORTED_ACCESS" },
    { 0x7F, "UNSUPPORTED_ENDPOINT" },    { 0x80, "INVALID_ACTION" },
    { 0x81, "UNSUPPORTED_COMMAND" },     { 0x85, "INVALID_COMMAND" },
    { 0x86, "UNSUPPORTED_ATTRIBUTE" },   { 0x87, "CONSTRAINT_ERROR" },
    { 0x88, "UNSUPPORTED_WRITE" },       { 0x89, "RESOURCE_EXHAUSTED" },
    { 0x8B, "NOT_FOUND" },               { 0x8C, "UNREPORTABLE_ATTRIBUTE" },
    { 0x8D, "INVALID_DATA_TYPE" },       { 0x8F, "UNSUPPORTED_READ" },
    { 0x92, "DATA_VERSION_MISMATCH" },   { 0x94, "TIMEOUT" },
    { 0x9C, "BUSY" },                    { 0x9D, "ACCESS_RESTRICTED" },
    { 0xC3, "UNSUPPORTED_CLUSTER" },     { 0xC5, "NO_UPSTREAM_SUBSCRIPTION" },
    { 0xC6, "NEEDS_TIMED_INTERACTION" }, { 0xC7, "UNSUPPORTED_EVENT" },
    { 0xC8, "PATHS_EXHAUSTED" },         { 0xC9, "TIMED_REQUEST_MISMATCH" },
    { 0xCA, "FAILSAFE_REQUIRED" },       { 0xCB, "INVALID_IN_STATE" },
    { 0xCC, "NO_COMMAND_RESPONSE" },     { 0xCF, "DYNAMIC_CONSTRAINT_ERROR" },
    { 0xD0, "ALREADY_EXISTS" },          { 0xD1, "INVALID_TRANSPORT_TYPE" },
    { 0xF0, "WRITE_IGNORED" },
    { 0, NULL }
};

// Not every application payload is Matter-TLV encoded. Secure Channel
// StatusReport (Section 4.10.1.3), MsgCounterSync (Section 4.18.2), ICD
// CheckIn (Section 4.19.3) and all BDX messages (Section 11.22.5) use fixed
// binary layouts, and vendor-specific protocols are opaque to us.
static bool
matter_payload_is_tlv(uint32_t vendor_id, uint32_t protocol_id, uint32_t opcode)
{
    if (vendor_id != 0)
        return false;

    switch (protocol_id) {
    case 0x0000: // Secure Channel
        // The PASE and CASE session establishment messages
        return (opcode >= SC_OPCODE_PBKDF_PARAM_REQUEST && opcode <= SC_OPCODE_PASE_PAKE3) ||
               (opcode >= SC_OPCODE_CASE_SIGMA1 && opcode <= SC_OPCODE_CASE_SIGMA2_RESUME);
    case 0x0001: // Interaction Model
    case 0x0003: // User Directed Commissioning
        return true;
    default:
        return false;
    }
}

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
 *   - DSIZ must not be the reserved value 3
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

    /* DSIZ (bits 0-1): 0=None, 1=64-bit Node ID, 2=16-bit Group ID, 3=Reserved */
    uint8_t dsiz = message_flags & MESSAGE_FLAG_DSIZ_MASK;
    if (dsiz == 3)
        return false;

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
    if (dsiz == MESSAGE_FLAG_HAS_DEST_NODE)
        min_len += 8;
    else if (dsiz == MESSAGE_FLAG_HAS_DEST_GROUP)
        min_len += 2;

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
    tvbuff_t *privacy_payload_tvb = NULL;  /* set when a privacy header was decrypted */
    unsigned  privacy_num_keys = 0;

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

    /* Section 2.5.4.2: operational group multicast addresses have the form
     * FF35:0040:FD<fabric-id>:00<group-id>. When the message arrived on such
     * an address, surface the fabric and group IDs as generated fields. */
    if (message_session_type == SECURITY_FLAG_SESSION_TYPE_GROUP &&
        pinfo->dst.type == AT_IPv6 && pinfo->dst.len == 16) {
        const uint8_t *a = (const uint8_t *)pinfo->dst.data;
        if (a[0] == 0xFF && a[1] == 0x35 && a[2] == 0x00 && a[3] == 0x40 &&
            a[4] == 0xFD && a[13] == 0x00) {
            uint64_t fabric_id = 0;
            for (unsigned i = 0; i < 8; i++)
                fabric_id = (fabric_id << 8) | a[5 + i];
            uint16_t group_id = (uint16_t)((a[14] << 8) | a[15]);
            proto_item *fi = proto_tree_add_uint64(matter_tree, hf_group_addr_fabric_id, tvb, 0, 0, fabric_id);
            proto_item_set_generated(fi);
            proto_item *gi = proto_tree_add_uint(matter_tree, hf_group_addr_group_id, tvb, 0, 0, group_id);
            proto_item_set_generated(gi);
        }
    }

    // Section 4.8.3: with the privacy flag set, the counter, source and
    // destination fields are obfuscated. For a group session we can undo
    // this with the derived privacy key and then dissect the header.
    if (security_flags & SECURITY_FLAG_HAS_PRIVACY) {

        uint32_t privacy_off = offset;
        uint32_t privacy_header_length = 4;
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            privacy_header_length += 8;
        }
        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            privacy_header_length += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            privacy_header_length += 2;
        }

        uint32_t payload_off = privacy_off + privacy_header_length;
        tvb_ensure_bytes_exist(tvb, payload_off, MATTER_MIC_LEN);
        uint32_t payload_len = tvb_reported_length_remaining(tvb, payload_off) - MATTER_MIC_LEN;

        uint8_t deobf[20];  /* max privacy header = 4 + 8 (source) + 8 (dest) */
        tvbuff_t *dec = NULL;

        if (message_session_type == SECURITY_FLAG_SESSION_TYPE_GROUP) {
            for (unsigned i = 0; i < num_matter_group_key_uat_records && !dec; i++) {
                const matter_group_key_uat_record_t *rec = &matter_group_key_uat_records[i];
                if (rec->group_session_id != session_id)
                    continue;
                privacy_num_keys++;
                dec = matter_try_group_privacy(tvb, pinfo, privacy_off, privacy_header_length,
                                               payload_off, payload_len, session_id, message_flags,
                                               rec->operational_key, rec->privacy_key,
                                               deobf, &message_counter, &source_node_id);
            }
        }

        if (dec) {
            /* Dissect the deobfuscated header from a decrypted data source. */
            uint8_t *full = (uint8_t *)wmem_alloc(pinfo->pool, payload_off);
            tvb_memcpy(tvb, full, 0, privacy_off);
            memcpy(full + privacy_off, deobf, privacy_header_length);
            tvbuff_t *htvb = tvb_new_child_real_data(tvb, full, payload_off, payload_off);
            add_new_data_source(pinfo, htvb, "Decrypted Matter Headers");

            proto_tree_add_item(matter_tree, hf_message_counter, htvb, privacy_off, 4, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, ": Counter=%u", message_counter);
            uint32_t ho = privacy_off + 4;
            if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
                proto_tree_add_item(matter_tree, hf_message_src_id, htvb, ho, 8, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Src=0x%016" PRIx64, source_node_id);
                ho += 8;
            }
            if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
                proto_tree_add_item(matter_tree, hf_message_dest_node_id, htvb, ho, 8, ENC_LITTLE_ENDIAN);
            } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
                uint32_t group_id;
                proto_tree_add_item_ret_uint(matter_tree, hf_message_dest_group_id, htvb, ho, 2, ENC_LITTLE_ENDIAN, &group_id);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Group=0x%04x", group_id);
            }
            privacy_payload_tvb = dec;
        } else {
            proto_tree_add_bytes_format(matter_tree, hf_message_privacy_header, tvb, offset, privacy_header_length, NULL, "Encrypted Headers");
        }
        offset += privacy_header_length;

    } else {

        // Section 4.4.1.5
        proto_tree_add_item_ret_uint(matter_tree, hf_message_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN, &message_counter);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Counter=%u", message_counter);
        offset += 4;

        // Section 4.4.1.6
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            proto_tree_add_item_ret_uint64(matter_tree, hf_message_src_id, tvb, offset, 8, ENC_LITTLE_ENDIAN, &source_node_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Src=0x%016" PRIx64, source_node_id);
            offset += 8;
        }

        // Section 4.4.1.7
        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            uint64_t node_id;
            proto_tree_add_item_ret_uint64(matter_tree, hf_message_dest_node_id, tvb, offset, 8, ENC_LITTLE_ENDIAN, &node_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Dest=0x%016" PRIx64, node_id);
            offset += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            unsigned int group_id;
            proto_tree_add_item_ret_uint(matter_tree, hf_message_dest_group_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &group_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Group=0x%04x", group_id);
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
    } else if (security_flags & SECURITY_FLAG_HAS_PRIVACY) {
        // Privacy messages were decrypted (or not) together with the header above.
        uint32_t payload_length = tvb_reported_length_remaining(tvb, offset) - MATTER_MIC_LEN;
        if (privacy_payload_tvb) {
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Decrypted Payload (%u bytes)", payload_length);
            proto_tree *payload_tree = proto_item_add_subtree(payload_item, ett_payload);
            dissect_matter_payload(privacy_payload_tvb, pinfo, payload_tree);
            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
            col_append_str(pinfo->cinfo, COL_INFO, " [Decrypted]");
        } else if (privacy_num_keys > 0) {
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Encrypted Payload (%u bytes) [Decryption failed - %u key(s) tried]", payload_length, privacy_num_keys);
            expert_add_info_format(pinfo, payload_item, &ei_matter_decryption_failed,
                "Decryption failed: tried %u key(s), none passed MIC verification", privacy_num_keys);
            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
        } else {
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Encrypted Payload (%u bytes) [No keys configured]", payload_length);
            expert_add_info_format(pinfo, payload_item, &ei_matter_decryption_no_key,
                "No decryption keys configured in Matter session keys table");
            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
        }
    } else {
        // A secured message always ends with the MIC; anything shorter is truncated.
        tvb_ensure_bytes_exist(tvb, offset, MATTER_MIC_LEN);
        uint32_t payload_length = tvb_reported_length_remaining(tvb, offset) - MATTER_MIC_LEN;

        /* The session ID in the header is the receiver's local session
         * ID, so it identifies both the session and the direction. Try
         * the key that last worked for it first; otherwise every UAT
         * entry (I2R and R2I key) is tried, and only MIC verification
         * determines the correct key.  For I2R keys the nonce uses the
         * Initiator node ID, for R2I keys the Responder node ID, falling
         * back to the source node ID from the message header when the
         * UAT row does not provide one. */
        tvbuff_t *decrypted_tvb = NULL;
        unsigned num_keys = 0;
        matter_session_key_t winner = { { 0 }, 0, false };
        bool from_cache = false;

        const matter_session_key_t *cached = wmem_map_lookup(matter_session_key_cache, GUINT_TO_POINTER(session_id));
        if (cached) {
            num_keys++;
            decrypted_tvb = matter_try_session_key(tvb, pinfo, offset, payload_length,
                                                   security_flags, message_counter, source_node_id, cached);
            from_cache = (decrypted_tvb != NULL);
        }

        if (message_session_type == SECURITY_FLAG_SESSION_TYPE_GROUP) {
            /* Group session: the session ID in the header is the derived
             * Group Session ID, so only keys whose derived ID matches are
             * tried (a 16-bit hash, so more than one may match).  The
             * source node ID for the nonce always comes from the header. */
            for (unsigned i = 0; i < num_matter_group_key_uat_records && !decrypted_tvb; i++) {
                const matter_group_key_uat_record_t *rec = &matter_group_key_uat_records[i];
                if (rec->group_session_id != session_id)
                    continue;
                num_keys++;
                memcpy(winner.key, rec->operational_key, MATTER_SESSION_KEY_LEN);
                winner.node_id = 0;
                winner.has_node_id = false;
                decrypted_tvb = matter_try_session_key(tvb, pinfo, offset, payload_length,
                                                       security_flags, message_counter, source_node_id, &winner);
            }
        } else {
            for (unsigned i = 0; i < num_matter_key_uat_records && !decrypted_tvb; i++) {
                const matter_key_uat_record_t *rec = &matter_key_uat_records[i];

                if (rec->has_i2r_key) {
                    num_keys++;
                    memcpy(winner.key, rec->i2r_key_bytes, MATTER_SESSION_KEY_LEN);
                    winner.node_id = rec->initiator_node_id;
                    winner.has_node_id = rec->has_initiator_node_id;
                    decrypted_tvb = matter_try_session_key(tvb, pinfo, offset, payload_length,
                                                           security_flags, message_counter, source_node_id, &winner);
                }
                if (rec->has_r2i_key && !decrypted_tvb) {
                    num_keys++;
                    memcpy(winner.key, rec->r2i_key_bytes, MATTER_SESSION_KEY_LEN);
                    winner.node_id = rec->responder_node_id;
                    winner.has_node_id = rec->has_responder_node_id;
                    decrypted_tvb = matter_try_session_key(tvb, pinfo, offset, payload_length,
                                                           security_flags, message_counter, source_node_id, &winner);
                }
            }
        }

        if (decrypted_tvb && !from_cache) {
            matter_session_key_t *entry = wmem_new(wmem_file_scope(), matter_session_key_t);
            *entry = winner;
            wmem_map_insert(matter_session_key_cache, GUINT_TO_POINTER(session_id), entry);
        }

        if (decrypted_tvb) {
            /* Decryption succeeded - show decrypted payload */
            proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Decrypted Payload (%u bytes)", payload_length);
            proto_tree *payload_tree = proto_item_add_subtree(payload_item, ett_payload);

            dissect_matter_payload(decrypted_tvb, pinfo, payload_tree);

            proto_tree_add_item(matter_tree, hf_payload_mic, tvb, offset + payload_length, MATTER_MIC_LEN, ENC_NA);
            col_append_str(pinfo->cinfo, COL_INFO, " [Decrypted]");
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
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s: %s", protocol_name, opcode_name);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s: Opcode=0x%02x", protocol_name, protocol_opcode);
    }

    // Section 4.4.3.6
    if (exchange_flags & EXCHANGE_FLAG_ACK_MSG) {
        unsigned int ack_counter;
        proto_tree_add_item_ret_uint(pl_tree, hf_payload_ack_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ack_counter);
        col_append_fstr(pinfo->cinfo, COL_INFO, " AckCounter=%u", ack_counter);
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
    if (protocol_vendor_id == 0 && protocol_id == 0x0000 && protocol_opcode == SC_OPCODE_STATUS_REPORT) {
        tvbuff_t *sr_tvb = tvb_new_subset_length(tvb, offset, application_length);
        offset += dissect_matter_status_report(sr_tvb, pinfo, pl_tree);
    } else if (application_length > 0) {
        proto_item *app_item = proto_tree_add_bytes_format(pl_tree, hf_payload_application, tvb, offset, application_length, NULL, "Application payload (%u bytes)", application_length);
        if (matter_payload_is_tlv(protocol_vendor_id, protocol_id, protocol_opcode)) {
            proto_tree *app_tree = proto_item_add_subtree(app_item, ett_payload);
            tvbuff_t *app_tvb = tvb_new_subset_length(tvb, offset, application_length);
            matter_tlv_context_id_t ctx = matter_payload_context(protocol_vendor_id, protocol_id, protocol_opcode);
            dissect_matter_tlv_internal(app_tvb, pinfo, app_tree, hf_matter_tlv_elem_tag, ctx);
        }
        offset += application_length;
    }
    return offset;
}

// Section 4.10.1.3: StatusReport
//   GeneralCode (2) || ProtocolId (4) || ProtocolCode (2) || ProtocolData (variable)
// ProtocolId carries the Vendor ID in its upper 16 bits.
static int
dissect_matter_status_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pl_tree)
{
    unsigned offset = 0;
    uint32_t general_code, protocol_id, protocol_vendor_id, protocol_code;

    proto_tree_add_item_ret_uint(pl_tree, hf_sc_status_general_code, tvb, offset, 2, ENC_LITTLE_ENDIAN, &general_code);
    offset += 2;
    // Little-endian, so the Protocol ID (lower 16 bits) comes first on the wire.
    proto_tree_add_item_ret_uint(pl_tree, hf_sc_status_protocol_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &protocol_id);
    proto_tree_add_item_ret_uint(pl_tree, hf_sc_status_protocol_vendor_id, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN, &protocol_vendor_id);
    offset += 4;
    proto_item *code_item = proto_tree_add_item_ret_uint(pl_tree, hf_sc_status_protocol_code, tvb, offset, 2, ENC_LITTLE_ENDIAN, &protocol_code);
    if (protocol_vendor_id == 0 && protocol_id == 0x0000)
        proto_item_append_text(code_item, " (%s)", val_to_str_const(protocol_code, sc_status_protocol_code_vals, "Unknown"));
    else if (protocol_vendor_id == 0 && protocol_id == 0x0001)
        proto_item_append_text(code_item, " (%s)", val_to_str_const(protocol_code, matter_im_status_vals, "Unknown"));
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s",
                    val_to_str_const(general_code, sc_status_general_code_vals, "Unknown"));
    if (protocol_vendor_id == 0 && protocol_id == 0x0000)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s)",
                        val_to_str_const(protocol_code, sc_status_protocol_code_vals, "Unknown"));
    else if (protocol_vendor_id == 0 && protocol_id == 0x0001)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s)",
                        val_to_str_const(protocol_code, matter_im_status_vals, "Unknown"));
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Protocol=0x%04x:0x%04x Code=0x%04x)",
                        protocol_vendor_id, protocol_id, protocol_code);

    unsigned data_length = tvb_reported_length_remaining(tvb, offset);
    if (data_length > 0) {
        proto_tree_add_item(pl_tree, hf_sc_status_protocol_data, tvb, offset, data_length, ENC_NA);
        offset += data_length;
    }
    return offset;
}

// Dissect the Matter-defined TLV encoding.
// Appendix A: Tag-length-value (TLV) Encoding Format
//
// hf_tag is the field used for context-specific tags (callers such as the
// BTP dissector supply their own), and ctx names the Interaction Model
// structure being dissected, if known, so that tags can be annotated.
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_matter_tlv_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            int hf_tag, matter_tlv_context_id_t ctx)
{
    // For signed and unsigned integer types and for UTF-8 and octet strings,
    // the length is encoded in the lowest 2 bits of the control byte.
    static const int elem_sizes[] = { 1, 2, 4, 8 };

    unsigned length = tvb_reported_length_remaining(tvb, 0);
    unsigned offset = 0;
    /* Cluster ID seen earlier in this container, so a sibling Attribute or
     * Command element can be resolved to a name (path IBs list the cluster
     * before the attribute/command). */
    uint32_t current_cluster = 0xFFFFFFFF;

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
        bool is_command_tag = false;
        bool is_status_tag = false;
        /* Tag name whose annotation is deferred until the value is known */
        const char *deferred_tag_name = NULL;

        switch (control_tag_format)
        {
        case 0: // Anonymous Tag Form (0 octets)
            child_ctx = ctx;  /* array elements inherit parent context */
            break;
        case 1: // Context-specific Tag Form (1 octet)
        {
            uint8_t tag_val = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(tree_element, hf_tag, tvb, offset, 1, ENC_NA);
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
                    } else if (strcmp(tag_name, "Command") == 0) {
                        is_command_tag = true;
                    } else if (strcmp(tag_name, "Status") == 0) {
                        is_status_tag = true;
                    }
                    if (is_cluster_tag || is_endpoint_tag || is_attribute_tag ||
                        is_command_tag || is_status_tag)
                        deferred_tag_name = tag_name;
                    else
                        proto_item_append_text(ti_element, " (%s)", tag_name);
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
            if ((is_cluster_tag || is_endpoint_tag || is_attribute_tag ||
                 is_command_tag || is_status_tag) &&
                (control_element & 0x04) && size <= 4) {
                uint32_t val = (size == 1) ? tvb_get_uint8(tvb, offset)
                             : (size == 2) ? tvb_get_letohs(tvb, offset)
                             :               tvb_get_letohl(tvb, offset);
                proto_tree_add_item(tree_element, hf, tvb, offset, size, ENC_LITTLE_ENDIAN);
                if (is_cluster_tag) {
                    current_cluster = val;
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
                    const char *an = matter_cluster_member_name(current_cluster, false, val);
                    if (an)
                        proto_item_append_text(ti_element, " (Attribute: %s)", an);
                    else
                        proto_item_append_text(ti_element, " (Attribute: 0x%04X)", val);
                } else if (is_status_tag) {
                    proto_item_append_text(ti_element, " (Status: %s)",
                                           val_to_str_const(val, matter_im_status_vals, "Unknown"));
                } else if (is_command_tag) {
                    const char *cn = matter_cluster_member_name(current_cluster, true, val);
                    if (cn)
                        proto_item_append_text(ti_element, " (Command: %s)", cn);
                    else
                        proto_item_append_text(ti_element, " (Command: 0x%02X)", val);
                }
            } else {
                proto_tree_add_item(tree_element, hf, tvb, offset, size, ENC_LITTLE_ENDIAN);
                if (deferred_tag_name)
                    proto_item_append_text(ti_element, " (%s)", deferred_tag_name);
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
            // Throws if the declared length runs past the end of the buffer,
            // which also keeps the int cast below from going negative.
            tvb_ensure_bytes_exist64(tvb, offset, str_length);
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
            tvb_ensure_bytes_exist64(tvb, offset, str_length);
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_value_bytes, tvb, offset, (int)str_length, ENC_NA);
            offset += (int)str_length;
            break;
        }
        case 0x14: // Null
            if (deferred_tag_name)
                proto_item_append_text(ti_element, " (%s)", deferred_tag_name);
            break;
        case 0x15: // Structure
        case 0x16: // Array
        case 0x17: // List
            if (deferred_tag_name)
                proto_item_append_text(ti_element, " (%s)", deferred_tag_name);
            increment_dissection_depth(pinfo);
            offset += dissect_matter_tlv_internal(tvb_new_subset_remaining(tvb, offset), pinfo, tree_element, hf_tag, child_ctx);
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

// Entry point for the registered "matter.tlv" dissector. If data is non-NULL
// it points to the hf the caller wants used for context-specific tags.
static int
dissect_matter_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int hf_tag = (data != NULL) ? *((int *)data) : hf_matter_tlv_elem_tag;
    return dissect_matter_tlv_internal(tvb, pinfo, tree, hf_tag, MATTER_TLV_CONTEXT_NONE);
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
        { &hf_group_addr_fabric_id,
          { "Group Address Fabric ID", "matter.group_addr.fabric_id",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Fabric ID from the operational group multicast address", HFILL }
        },
        { &hf_group_addr_group_id,
          { "Group Address Group ID", "matter.group_addr.group_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Group ID from the operational group multicast address", HFILL }
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
        { &hf_sc_status_general_code,
          { "General Code", "matter.sc.status.general_code",
            FT_UINT16, BASE_DEC, VALS(sc_status_general_code_vals), 0,
            "StatusReport general status code", HFILL }
        },
        { &hf_sc_status_protocol_vendor_id,
          { "Protocol Vendor ID", "matter.sc.status.protocol_vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Vendor ID of the protocol the status applies to", HFILL }
        },
        { &hf_sc_status_protocol_id,
          { "Protocol ID", "matter.sc.status.protocol_id",
            FT_UINT16, BASE_HEX, VALS(protocol_id_vals), 0,
            "Protocol the status applies to", HFILL }
        },
        { &hf_sc_status_protocol_code,
          { "Protocol Code", "matter.sc.status.protocol_code",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Protocol-specific status code", HFILL }
        },
        { &hf_sc_status_protocol_data,
          { "Protocol Data", "matter.sc.status.protocol_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Protocol-specific status data", HFILL }
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

    matter_session_key_cache = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                      g_direct_hash, g_direct_equal);

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

    /* UAT for group (multicast) keys */
    static uat_field_t matter_group_key_uat_fields[] = {
        UAT_FLD_CSTRING(matter_group_key_uat, epoch_key, "Epoch Key",
                        "Operational group epoch key (32 hex chars)"),
        UAT_FLD_CSTRING(matter_group_key_uat, compressed_fabric_id, "Compressed Fabric ID",
                        "64-bit compressed fabric identifier (16 hex chars)"),
        UAT_END_FIELDS
    };

    uat_t *matter_group_keys_uat = uat_new("Matter Group Keys",
            sizeof(matter_group_key_uat_record_t),
            "matter_group_keys",
            true,
            &matter_group_key_uat_records,
            &num_matter_group_key_uat_records,
            UAT_AFFECTS_DISSECTION,
            NULL,
            matter_group_key_uat_copy_cb,
            matter_group_key_uat_update_cb,
            matter_group_key_uat_free_cb,
            NULL,
            NULL,
            matter_group_key_uat_fields);

    prefs_register_uat_preference(matter_module, "group_keys",
            "Group keys",
            "A table of Matter group (multicast) keys for decryption.\n"
            "Enter the operational group epoch key (32 hex characters) and\n"
            "the compressed fabric ID (16 hex characters). The operational\n"
            "key, group session ID and privacy key are derived from them.",
            matter_group_keys_uat);
}

void
proto_reg_handoff_matter(void)
{
    dissector_add_uint_with_preference("udp.port", MATTER_DEFAULT_PORT, matter_handle);
    heur_dissector_add("udp", dissect_matter_heur, "Matter over UDP", "matter_udp", proto_matter, HEURISTIC_ENABLE);
}
