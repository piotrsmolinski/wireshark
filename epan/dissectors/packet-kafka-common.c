/* packet-kafka-common.c
 * Common routines for Apache Kafka Protocol dissection (version 0.8 - 3.6)
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 * Update from Kafka 0.10.1.0 to 3.6 by Piotr Smolinski <piotr.smolinski@confluent.io>
 *
 * https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol
 * https://kafka.apache.org/protocol.html
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-kafka-common.h"

int
kafka_tvb_get_regular_buffer_size(
        tvbuff_t *tvb,
        int offset,
        int *size_len
)
{
    int count = tvb_get_ntohis(tvb, offset);;
    THROW_MESSAGE_ON(count < -1, ReportedBoundsError, "Invalid buffer length");
    *size_len = 2;
    return count;
}

int
kafka_tvb_get_compact_buffer_size(
        tvbuff_t *tvb,
        int offset,
        int *size_len
)
{
    guint64 count;
    gint32 len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");
    *size_len = len;
    return (int)count - 1;
}

int
kafka_tvb_get_buffer_size(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int *size_len
)
{
    if (kinfo->flexible_api) {
        return kafka_tvb_get_compact_buffer_size(tvb, offset, size_len);
    } else {
        return kafka_tvb_get_regular_buffer_size(tvb, offset, size_len);
    }
}

int
kafka_tvb_get_regular_array_size(
        tvbuff_t *tvb,
        int offset,
        int *size_len
)
{
    int count = tvb_get_ntohil(tvb, offset);;
    THROW_MESSAGE_ON(count < -1, ReportedBoundsError, "Invalid array length");
    *size_len = 4;
    return count;
}

int
kafka_tvb_get_compact_array_size(
        tvbuff_t *tvb,
        int offset,
        int *size_len
)
{
    guint64 count;
    gint32 len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");
    *size_len = len;
    return (int)count - 1;
}

int
kafka_tvb_get_array_size(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int *size_len
)
{
    if (kinfo->flexible_api) {
        return kafka_tvb_get_compact_array_size(tvb, offset, size_len);
    } else {
        return kafka_tvb_get_regular_array_size(tvb, offset, size_len);
    }
}

/*
 * Retrieve null-terminated copy of string from a package.
 * The function wraps the tvb_get_string_enc that if given string is NULL, which is represented as negative length,
 * a substitute string is returned instead of failing.
 */
gint8*
kafka_tvb_get_string(
        wmem_allocator_t *scope,
        tvbuff_t *tvb,
        int offset,
        int length)
{
    if (length >= 0) {
        return tvb_get_string_enc(scope, tvb, offset, length, ENC_UTF_8);
    } else {
        return NULL;
    }
}

gint8*
kafka_tvb_get_bytes(
        wmem_allocator_t *scope,
        tvbuff_t *tvb,
        int offset,
        int length)
{
    if (length >= 0) {
        return tvb_memdup(scope, tvb, offset, length);
    } else {
        return NULL;
    }
}

static const unsigned char base64_table[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

gint8*
kafka_tvb_get_base64(
        wmem_allocator_t *scope,
        tvbuff_t *tvb,
        int offset,
        int length)
{
    gint8 *bytes;
    gint8 *result;
    int result_length  = (length + 2) / 3 * 4;

    if (length < 0) {
        return NULL;
    }

    bytes = tvb_memdup(scope, tvb, offset, length);
    result = wmem_alloc(scope, result_length + 1);
    for (int i = 0, j = 0; i < length; ) {
        guint32 a = i < length ? bytes[i++] : 0;
        guint32 b = i < length ? bytes[i++] : 0;
        guint32 c = i < length ? bytes[i++] : 0;
        guint32 triple = (a << 16) + (b << 8) + c;
        result[j++] = base64_table[(triple >> 3 * 6) & 0x3f];
        result[j++] = base64_table[(triple >> 2 * 6) & 0x3f];
        result[j++] = base64_table[(triple >> 1 * 6) & 0x3f];
        result[j++] = base64_table[(triple >> 0 * 6) & 0x3f];
    }
    wmem_free(scope, bytes);

    if (length % 3 == 1) {
        result[result_length - 2] = '=';
        result[result_length - 1] = '=';
    }
    if (length % 3 == 2) {
        result[result_length - 1] = '=';
    }
    result[result_length] = 0;

    return result;

}

/*
 * Kafka topic id is in fact UUID, but the tools report it as base64 without padding.
 */
gint8*
kafka_tvb_get_uuid(
        wmem_allocator_t *scope,
        tvbuff_t *tvb,
        int offset)
{
    gint8 uuid[16];
    gint8 *result;

    tvb_memcpy(tvb, uuid, offset, 16);

    // to avoid boundary checking, allocate the padding and use it later as string termination
    result = wmem_alloc(scope, 24);
    for (int i = 0, j = 0; i < 16; ) {
        guint32 a = i < 16 ? uuid[i++] : 0;
        guint32 b = i < 16 ? uuid[i++] : 0;
        guint32 c = i < 16 ? uuid[i++] : 0;
        guint32 triple = (a << 16) + (b << 8) + c;
        result[j++] = base64_table[(triple >> 3 * 6) & 0x3f];
        result[j++] = base64_table[(triple >> 2 * 6) & 0x3f];
        result[j++] = base64_table[(triple >> 1 * 6) & 0x3f];
        result[j++] = base64_table[(triple >> 0 * 6) & 0x3f];
    }
    result[22] = 0;
    result[23] = 0;

    return result;
}

int
dissect_kafka_int8_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint8 *ret)
{
    if (ret) *ret = tvb_get_gint8(tvb, offset);
    proto_tree_add_item(tree, hf_item, tvb, offset, 1, ENC_NA);
    return offset+1;
}

int
dissect_kafka_int8(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_int8_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

int
dissect_kafka_int16_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint16 *ret)
{
    if (ret) *ret = tvb_get_gint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 2, ENC_BIG_ENDIAN);
    return offset+2;
}

int
dissect_kafka_int16(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

int
dissect_kafka_int32_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint32 *ret)
{
    if (ret) *ret = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset+4;
}

int
dissect_kafka_int32(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

int
dissect_kafka_int64_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint64 *ret)
{
    if (ret) *ret = tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 8, ENC_BIG_ENDIAN);
    return offset + 8;
}

int
dissect_kafka_int64(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_int64_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}


int
dissect_kafka_varint_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint64 *ret)
{
    gint64 value;
    guint len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &value, ENC_VARINT_ZIGZAG);
    if (len == 0) {
        THROW_MESSAGE(ReportedBoundsError, "Invalid varint content");
    }

    if (ret) *ret = value;
    proto_tree_add_int64(tree, hf_item, tvb, offset, len, value);

    return offset + len;
}

int
dissect_kafka_varuint_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        guint64 *ret)
{
    guint64 value;
    guint len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &value, ENC_VARINT_PROTOBUF);
    if (len == 0) {
        THROW_MESSAGE(ReportedBoundsError, "Invalid varint content");
    }

    if (ret) *ret = value;
    proto_tree_add_uint64(tree, hf_item, tvb, offset, len, value);

    return offset + len;
}

int
dissect_kafka_timestamp_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint64 *ret)
{
    if (ret) *ret = tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 8, ENC_TIME_MSECS | ENC_BIG_ENDIAN);
    return offset+8;
}

int
dissect_kafka_timestamp(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_timestamp_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}


int
dissect_kafka_replica_id_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint32 *ret)
{

    gint32 replica_id;

    replica_id = tvb_get_ntohl(tvb, offset);

    // handle special cases first
    if (replica_id == -2) {
        proto_tree_add_int_format_value(tree, hf_item, tvb, offset, 4, replica_id, "-2 (debug)");
    } else if (replica_id == -1) {
        proto_tree_add_int_format_value(tree, hf_item, tvb, offset, 4, replica_id, "-1 (consumer)");
    } else {
        proto_tree_add_int(tree, hf_item, tvb, offset, 4, replica_id);
    }
    offset += 4;

    if (ret) *ret = replica_id;

    return offset;
}

int
dissect_kafka_replica_id(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_replica_id_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

int
dissect_kafka_string_internal(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        int count,
        int count_len,
        kafka_buffer_ref *p_buffer
)
{
    if (p_buffer) {
        p_buffer->offset = offset + count_len;
        p_buffer->length = count;
    }

    if (count == -1) {
        proto_tree_add_string(tree, hf_item, tvb, offset, count_len, NULL);
        offset += count_len;
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, count_len + count,
                              kafka_tvb_get_string(kinfo->pinfo->pool, tvb, offset + count_len, count));
        offset += count_len;
        offset += count;
    }
    return offset;
}

/*
 * Pre KIP-482 coding. The string is prefixed with 16-bit signed integer. Value -1 means null.
 */
int
dissect_kafka_regular_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    int count, count_len;
    count = kafka_tvb_get_regular_buffer_size(tvb, offset, &count_len);
    return dissect_kafka_string_internal(tvb, kinfo, tree, offset, hf_item, count, count_len, p_buffer);
}

/*
 * Compact coding. The string is prefixed with unsigned varint containing number of octets + 1.
 */
int
dissect_kafka_compact_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    int count, count_len;
    count = kafka_tvb_get_compact_buffer_size(tvb, offset, &count_len);
    return dissect_kafka_string_internal(tvb, kinfo, tree, offset, hf_item, count, count_len, p_buffer);
}

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
int
dissect_kafka_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    if (kinfo->flexible_api) {
        return dissect_kafka_compact_string_ret(tvb, kinfo, tree, offset, hf_item, p_buffer);
    } else {
        return dissect_kafka_regular_string_ret(tvb, kinfo, tree, offset, hf_item, p_buffer);
    }
}

int
dissect_kafka_string(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

int
dissect_kafka_bytes_internal(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        int count,
        int count_len,
        kafka_buffer_ref *p_buffer
)
{
    if (p_buffer) {
        p_buffer->offset = offset + count_len;
        p_buffer->length = count;
    }

    if (count < 0) {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, count_len, NULL, 0);
        offset += count_len;
    } else {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, count_len + count,
                                         kafka_tvb_get_bytes(kinfo->pinfo->pool, tvb, offset + count_len, count), count);
        offset += count_len;
        offset += count;
    }
    return offset;
}

/*
 * Pre KIP-482 coding. The string is prefixed with signed 16-bit integer containing number of octets.
 */
int
dissect_kafka_regular_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    int count, count_len;
    count = kafka_tvb_get_regular_buffer_size(tvb, offset, &count_len);
    return dissect_kafka_bytes_internal(tvb, kinfo, tree, offset, hf_item, count, count_len, p_buffer);
}

/*
 * Compact coding. The bytes is prefixed with unsigned varint containing number of octets + 1.
 */
int
dissect_kafka_compact_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    int count, count_len;
    count = kafka_tvb_get_compact_buffer_size(tvb, offset, &count_len);
    return dissect_kafka_bytes_internal(tvb, kinfo, tree, offset, hf_item, count, count_len, p_buffer);
}

/*
 * Dissect bytes. Depending on the 'flexible_api' flag in 'kinfo' use old style or compact coding.
 */
int
dissect_kafka_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    if (kinfo->flexible_api) {
        return dissect_kafka_compact_bytes_ret(tvb, kinfo, tree, offset, hf_item, p_buffer);
    } else {
        return dissect_kafka_regular_bytes_ret(tvb, kinfo, tree, offset, hf_item, p_buffer);
    }
}

int
dissect_kafka_bytes(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_bytes_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

int
dissect_kafka_base64_internal(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        int count,
        int count_len,
        kafka_buffer_ref *p_buffer
)
{
    if (p_buffer) {
        p_buffer->offset = offset + count_len;
        p_buffer->length = count;
    }

    if (count == -1) {
        proto_tree_add_string(tree, hf_item, tvb, offset, count_len, NULL);
        offset += count_len;
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, count_len + count,
                              kafka_tvb_get_base64(kinfo->pinfo->pool, tvb, offset + count_len, count));
        offset += count_len;
        offset += count;
    }
    return offset;
}

/*
 * Pre KIP-482 coding. The string is prefixed with 16-bit signed integer. Value -1 means null.
 */
int
dissect_kafka_regular_base64_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    int count, count_len;
    count = kafka_tvb_get_regular_buffer_size(tvb, offset, &count_len);
    return dissect_kafka_base64_internal(tvb, kinfo, tree, offset, hf_item, count, count_len, p_buffer);
}

/*
 * Compact coding. The string is prefixed with unsigned varint containing number of octets + 1.
 */
int
dissect_kafka_compact_base64_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    int count, count_len;
    count = kafka_tvb_get_compact_buffer_size(tvb, offset, &count_len);
    return dissect_kafka_base64_internal(tvb, kinfo, tree, offset, hf_item, count, count_len, p_buffer);
}

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
int
dissect_kafka_base64_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    if (kinfo->flexible_api) {
        return dissect_kafka_compact_base64_ret(tvb, kinfo, tree, offset, hf_item, p_buffer);
    } else {
        return dissect_kafka_regular_base64_ret(tvb, kinfo, tree, offset, hf_item, p_buffer);
    }
}

int
dissect_kafka_base64(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_base64_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}


int
dissect_kafka_object(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int ett_idx,
        const char *label,
        dissect_kafka_object_content_cb func
)
{
    proto_item *object_ti;
    proto_tree *object_tree;

    object_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_idx, &object_ti, label);
    offset = func(tvb, kinfo, object_tree, offset);
    proto_item_set_end(object_ti, tvb, offset);

    return offset;
}


int
tvb_get_array_size(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int *size_len
)
{
    if (kinfo->flexible_api) {
        guint64 count;
        gint32 len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
        THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");
        *size_len = len;
        return (int)count - 1;
    } else {
        int count = tvb_get_ntohl(tvb, offset);
        THROW_MESSAGE_ON(count < -1, ReportedBoundsError, "Invalid array length");
        *size_len = 4;
        return count;
    }
}

/*
 * Dissect array. Use 'flexible' flag to select which variant should be used.
 */
int
dissect_kafka_array_simple(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int collection_ett, const char *collection_label,
        dissect_kafka_array_simple_cb func,
        int item_hf
)
{
    int count, count_len;
    proto_item *collection_ti;
    proto_tree *collection_tree;

    count = kafka_tvb_get_array_size(tvb, kinfo, offset, &count_len);
    if (count < 0) {
        return offset + count_len;
    }
    if (collection_label) {
        collection_tree = proto_tree_add_subtree(tree, tvb, offset, -1, collection_ett, &collection_ti, collection_label);
    }
    offset += count_len;
    for (int i=0; i<count; i++) {
        offset = func(tvb, kinfo, collection_label ? collection_tree : tree, offset, item_hf);
    }
    if (collection_label) {
        proto_item_set_end(collection_ti, tvb, offset);
    }
    return offset;
}

int
dissect_kafka_array_object(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int collection_ett, const char *collection_label,
        int item_ett, const char *item_label,
        dissect_kafka_object_content_cb func
)
{
    int count, count_len;
    proto_item *collection_ti, *item_ti;
    proto_tree *collection_tree, *item_tree;

    count = tvb_get_array_size(tvb, kinfo, offset, &count_len);
    if (count < 0) {
        return offset + count_len;
    }
    if (collection_label) {
        collection_tree = proto_tree_add_subtree(tree, tvb, offset, -1, collection_ett, &collection_ti, collection_label);
    }
    offset += count_len;
    for (int i=0; i<count; i++) {
        item_tree = proto_tree_add_subtree(collection_label ? collection_tree : tree, tvb, offset, -1, item_ett, &item_ti, item_label);
        offset = func(tvb, kinfo, item_tree, offset);
        proto_item_set_end(item_ti, tvb, offset);
    }
    if (collection_label) {
        proto_item_set_end(collection_ti, tvb, offset);
    }
    return offset;
}

static const unsigned char* EMPTY_UUID = "AAAAAAAAAAAAAAAAAAAAAA";

int
dissect_kafka_uuid_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *ret
)
{

    gint8 *uuid = kafka_tvb_get_uuid(kinfo->pinfo->pool, tvb, offset);

    if (strcmp(uuid, EMPTY_UUID) == 0) {
        proto_tree_add_string_format_value(tree, hf_item, tvb, offset, 16, uuid, "[ Empty ]");
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, 16, uuid);
    }

    if (ret)
    {
        ret->offset = offset;
        ret->length = 16;
    }

    offset += 16;

    return offset;
}

int
dissect_kafka_uuid(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
)
{
    return dissect_kafka_uuid_ret(tvb, kinfo, tree, offset, hf_item, NULL);
}

/* Tagged fields support (since Kafka 2.4) */

static int
dissect_kafka_tagged_field(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        dissect_kafka_object_tags_cb func)
{

    guint field_tag_len;
    guint field_length_len;
    guint64 field_tag;
    guint64 field_length;

    field_tag_len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &field_tag, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(field_tag_len == 0, ReportedBoundsError, "Invalid varint content");

    field_length_len = tvb_get_varint(tvb, offset + field_tag_len, FT_VARINT_MAX_LEN, &field_length, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(field_length_len == 0, ReportedBoundsError, "Invalid varint content");

    if (func) func(
                tvb_new_subset_length_caplen(
                        tvb,
                        offset + field_tag_len + field_length_len,
                        (guint)field_length,
                        (guint)field_length),
                kinfo,
                tree,
                0,
                field_tag);

    return offset + field_tag_len + field_length_len + (guint)field_length;

}

int
dissect_kafka_tagged_fields(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        dissect_kafka_object_tags_cb func)
{
    gint64 count;
    guint len;

    /*
     * Tagged fields are only present in protocol versions supporting Flexible API
     */
    if (! kinfo->flexible_api)
    {
        return offset;
    }

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");

    offset += len;

    /*
     * Contrary to compact arrays, tagged fields store just count
     * https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
     */
    for (int i=0; i<count; i++)
    {
        offset = dissect_kafka_tagged_field(tvb, kinfo, tree, offset, func);
    }

    return offset;
}
