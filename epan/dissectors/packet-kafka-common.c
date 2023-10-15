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

/*
 * Retrieve null-terminated copy of string from a package.
 * The function wraps the tvb_get_string_enc that if given string is NULL, which is represented as negative length,
 * a substitute string is returned instead of failing.
 */
gint8*
kafka_tvb_get_string(
        wmem_allocator_t *pool,
        tvbuff_t *tvb,
        int offset,
        int length)
{
    if (length >= 0) {
        return tvb_get_string_enc(pool, tvb, offset, length, ENC_UTF_8);
    } else {
        return "[ Null ]";
    }
}

static const unsigned char base64_table[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/*
 * Kafka topic id is in fact UUID, but the tools report it as base64 without padding.
 */
gint8*
kafka_tvb_get_uuid(
        wmem_allocator_t *pool,
        tvbuff_t *tvb,
        int offset)
{
    gint8 *result;
    int i, j;

    // to avoid boundary checking, allocate the padding and use it later as string termination
    result = wmem_alloc(pool, 24);
    for (i = 0, j = 0; i < 16; ) {
        guint32 a = i < 16 ? tvb_get_gint8(tvb, offset + i++) : 0;
        guint32 b = i < 16 ? tvb_get_gint8(tvb, offset + i++) : 0;
        guint32 c = i < 16 ? tvb_get_gint8(tvb, offset + i++) : 0;
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
dissect_kafka_int8_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        gint8 *ret)
{
    if (ret != NULL) *ret = tvb_get_gint8(tvb, offset);
    proto_tree_add_item(tree, hf_item, tvb, offset, 1, ENC_NA);
    return offset+1;
}

int
dissect_kafka_int8(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        gint8 *ret)
{
    return dissect_kafka_int8_v2(tree, tvb, kinfo, offset, hf_item, ret);
}

int
dissect_kafka_int16_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        gint16 *ret)
{
    if (ret != NULL) *ret = tvb_get_gint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 2, ENC_BIG_ENDIAN);
    return offset+2;
}

int
dissect_kafka_int16(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint16 *ret)
{
    return dissect_kafka_int16_v2(tree, tvb, kinfo, offset, hf_item, ret);
}

int
dissect_kafka_int32_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        gint32 *ret)
{
    if (ret != NULL) *ret = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset+4;
}

int
dissect_kafka_int32(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint32 *ret)
{
    return dissect_kafka_int32_v2(tree, tvb, kinfo, offset, hf_item, ret);
}

int
dissect_kafka_int64_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        gint64 *ret)
{
    if (ret != NULL) *ret = tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 8, ENC_BIG_ENDIAN);
    return offset + 8;
}

int
dissect_kafka_int64(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint64 *ret)
{
    return dissect_kafka_int64_v2(tree, tvb, kinfo, offset, hf_item, ret);
}

int
dissect_kafka_varint(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        gint64 *ret)
{
    gint64 value;
    guint len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &value, ENC_VARINT_ZIGZAG);
    if (len == 0) {
        THROW_MESSAGE(ReportedBoundsError, "Invalid varint content");
    }

    if (ret != NULL) *ret = value;
    proto_tree_add_int64(tree, hf_item, tvb, offset, len, value);

    return offset + len;
}

int
dissect_kafka_varuint(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        guint64 *ret)
{
    guint64 value;
    guint len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &value, ENC_VARINT_PROTOBUF);
    if (len == 0) {
        THROW_MESSAGE(ReportedBoundsError, "Invalid varint content");
    }

    if (ret != NULL) *ret = value;
    proto_tree_add_uint64(tree, hf_item, tvb, offset, len, value);

    return offset + len;
}


int
dissect_kafka_timestamp_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        gint64 *ret)
{
    if (ret != NULL) *ret = tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 8, ENC_TIME_MSECS | ENC_BIG_ENDIAN);
    return offset+8;
}

int
dissect_kafka_timestamp(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint64 *ret)
{
    return dissect_kafka_timestamp_v2(tree, tvb, kinfo, offset, hf_item, ret);
}

int
dissect_kafka_replica_id(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        gint32 *ret)
{
    proto_item *subti;
    gint32 replica_id;

    replica_id = tvb_get_ntohl(tvb, offset);
    subti = proto_tree_add_item(tree, hf_item, tvb, offset, 4, ENC_BIG_ENDIAN);
    if (replica_id == -2) {
        proto_item_append_text(subti, " (debug)");
    } else if (replica_id == -1) {
        proto_item_append_text(subti, " (consumer)");
    }
    offset += 4;

    if (ret != NULL) *ret = replica_id;
    return offset;
}

/*
 * Pre KIP-482 coding. The string is prefixed with 16-bit signed integer. Value -1 means null.
 */
int
dissect_kafka_regular_string_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer)
{
    gint16 length;

    length = (gint16) tvb_get_ntohs(tvb, offset);
    if (length < -1) {
        // the value read does not make sense, fail
        THROW_MESSAGE(ReportedBoundsError, "Invalid buffer length");
    }

    if (length == -1) {
        proto_tree_add_string(tree, hf_item, tvb, offset, 2, NULL);
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, length + 2,
                              kafka_tvb_get_string(kinfo->pinfo->pool, tvb, offset + 2, length));
    }

    if (p_buffer) {
        p_buffer->offset = offset + 2;
        p_buffer->length = length;
    }

    offset += 2;
    if (length != -1) offset += length;

    return offset;
}

/*
 * Compact coding. The string is prefixed with unsigned varint containing number of octets + 1.
 */
int
dissect_kafka_compact_string_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer)
{
    guint len;
    guint64 length;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);
    if (len == 0) {
        // we cannot parse the varint, there is no point to continue parsing
        THROW_MESSAGE(ReportedBoundsError, "Invalid varint content");
    }

    if (length == 0) {
        proto_tree_add_string(tree, hf_item, tvb, offset, len, NULL);
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, len + (gint)length - 1,
                              kafka_tvb_get_string(kinfo->pinfo->pool, tvb, offset + len, (gint)length - 1));
    }

    if (p_buffer) {
        p_buffer->offset = offset + len;
        p_buffer->length = (gint)length - 1;
    }

    offset += len;
    if (length > 0) {
        offset += (gint)length - 1;
    }

    return offset;
}

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
int
dissect_kafka_string_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer)
{
    if (kinfo->flexible_api) {
        return dissect_kafka_compact_string_v2(tree, tvb, kinfo, offset, hf_item, p_buffer);
    } else {
        return dissect_kafka_regular_string_v2(tree, tvb, kinfo, offset, hf_item, p_buffer);
    }
}

int
dissect_kafka_string(proto_tree *tree, int hf_item, tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset,
                     kafka_buffer_ref *p_buffer)
{
    return dissect_kafka_string_v2(tree, tvb, kinfo, offset, hf_item, p_buffer);
}

/*
 * Pre KIP-482 coding. The string is prefixed with signed 16-bit integer containing number of octets.
 */
int
dissect_kafka_regular_bytes_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer)
{
    gint16 length;

    length = (gint16) tvb_get_ntohs(tvb, offset);
    if (length < -1) {
        // the value read does not make sense, fail
        THROW_MESSAGE(ReportedBoundsError, "Invalid buffer length");
    }

    if (length == -1) {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, 2,
                                         NULL, 0);
    } else {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, 2 + length,
                                         tvb_get_ptr(tvb, offset + 2, length), length);
    }

    if (p_buffer) {
        p_buffer->offset = offset + 2;
        p_buffer->length = length;
    }

    offset += 2;
    if (length != -1) offset += length;

    return offset;
}

/*
 * Compact coding. The bytes is prefixed with unsigned varint containing number of octets + 1.
 */
int
dissect_kafka_compact_bytes_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer)
{
    guint len;
    guint64 length;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);

    if (len == 0) {
        // we cannot parse the varint, there is no point to continue parsing
        THROW_MESSAGE(ReportedBoundsError, "Invalid varint content");
    }

    if (length == 0) {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, len,
                                         NULL, 0);
    } else {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, len + (gint)length - 1,
                                         tvb_get_ptr(tvb, offset + len, (gint)length - 1), (gint)length - 1);
    }


    if (p_buffer) {
        p_buffer->offset = offset + len;
        p_buffer->length = (gint)length - 1;
    }

    offset += len;
    if (length > 0) {
        offset += (gint)length - 1;
    }

    return offset;
}

/*
 * Dissect bytes. Depending on the 'flexible_api' flag in 'kinfo' use old style or compact coding.
 */
int
dissect_kafka_bytes_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer)
{
    if (kinfo->flexible_api) {
        return dissect_kafka_compact_bytes_v2(tree, tvb, kinfo, offset, hf_item, p_buffer);
    } else {
        return dissect_kafka_regular_bytes_v2(tree, tvb, kinfo, offset, hf_item, p_buffer);
    }
}

int
dissect_kafka_bytes(proto_tree *tree, int hf_item, tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset,
                    kafka_buffer_ref *p_buffer)
{
    return dissect_kafka_bytes_v2(tree, tvb, kinfo, offset, hf_item, p_buffer);
}

int
dissect_kafka_array_elements(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        dissect_kafka_array_element_cb func,
        int count)
{
    int i;
    for (i=0; i<count; i++) {
        offset = func(tvb, kinfo, tree, offset);
    }
    return offset;
}

/*
 * In the pre KIP-482 the arrays had length saved in 32-bit signed integer. If the value was -1,
 * the array was considered to be null.
 */
int
dissect_kafka_regular_array(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        dissect_kafka_array_element_cb func,
        int *p_count)
{
    gint32 count;

    count = (gint32) tvb_get_ntohl(tvb, offset);
    THROW_MESSAGE_ON(count < -1, ReportedBoundsError, "Invalid array length");

    offset += 4;

    proto_item_append_text(tree, " (regular %u items)", (guint)count);

    offset = dissect_kafka_array_elements(tree, tvb, kinfo, offset, func, count);

    if (p_count != NULL) *p_count = count;

    return offset;
}

/*
 * KIP-482 introduced concept of compact arrays. If API version for the given call is marked flexible,
 * all arrays are prefixed with unsigned varint. The value is the array length + 1. If the value is 0,
 * the array is null.
 */
int
dissect_kafka_compact_array(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        dissect_kafka_array_element_cb func,
        int *p_count)
{
    guint64 count;
    gint32 len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len ==0, ReportedBoundsError, "Invalid varint content");

    offset += len;

    /*
     * Compact arrays store count+1, 0 is special value indicating null array, 1 means empty array
     * https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
     */
    if (count > 0)
    {
        offset = dissect_kafka_array_elements(tree, tvb, kinfo, offset, func, (int)count - 1);
    }

    if (p_count != NULL) *p_count = (int)count - 1;

    return offset;
}

/*
 * Dissect array. Use 'flexible' flag to select which variant should be used.
 */
int
dissect_kafka_array(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        dissect_kafka_array_element_cb func,
        int *p_count)
{
    if (kinfo->flexible_api) {
        return dissect_kafka_compact_array(tree, tvb, kinfo, offset, func, p_count);
    } else {
        return dissect_kafka_regular_array(tree, tvb, kinfo, offset, func, p_count);
    }

}

int
dissect_kafka_uuid_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        void *ret _U_)
{

    proto_tree_add_string(tree, hf_item, tvb, offset, 16, kafka_tvb_get_uuid(kinfo->pinfo->pool, tvb, offset));
    offset += 16;

    return offset;
}

int
dissect_kafka_uuid(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        kafka_buffer_ref *ret)
{
    return dissect_kafka_uuid_v2(tree, tvb, kinfo, offset, hf_item, ret);
}
