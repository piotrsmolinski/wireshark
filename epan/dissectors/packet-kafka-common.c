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
    gint8 uuid[16];
    gint8 *result;
    int i, j;
    gboolean empty = 1;

    tvb_memcpy(tvb, uuid, offset, 16);

    for (i = 0; i < 16; i++) {
        if (uuid[i]) {
            empty = 0;
            break;
        }
    }

    if (empty) {
        return "[ Empty ]";
    }

    // to avoid boundary checking, allocate the padding and use it later as string termination
    result = wmem_alloc(pool, 24);
    for (i = 0, j = 0; i < 16; ) {
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
    if (ret != NULL) *ret = tvb_get_gint8(tvb, offset);
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
    if (ret != NULL) *ret = tvb_get_gint16(tvb, offset, ENC_BIG_ENDIAN);
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
    if (ret != NULL) *ret = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
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
    if (ret != NULL) *ret = tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN);
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

    if (ret != NULL) *ret = value;
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

    if (ret != NULL) *ret = value;
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
    if (ret != NULL) *ret = tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN);
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
    gint16 length;

    length = (gint16) tvb_get_ntohs(tvb, offset);
    THROW_MESSAGE_ON(length < -1, ReportedBoundsError, "Invalid buffer length");

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
dissect_kafka_compact_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    guint len;
    guint64 length;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");

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
    gint16 length;

    length = (gint16) tvb_get_ntohs(tvb, offset);
    THROW_MESSAGE_ON(length < -1, ReportedBoundsError, "Invalid buffer length");

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
dissect_kafka_compact_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo _U_,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
)
{
    guint len;
    guint64 length;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");

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

    count = tvb_get_array_size(tvb, kinfo, offset, &count_len);
    offset += count_len;

    if (count < 0) {
        return offset;
    }

    if (collection_label) {
        collection_tree = proto_tree_add_subtree(tree, tvb, offset, 0, collection_ett, &collection_ti, collection_label);
    }
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
    offset += count_len;

    if (count < 0) {
        return offset;
    }

    if (collection_label) {
        collection_tree = proto_tree_add_subtree(tree, tvb, offset, -1, collection_ett, &collection_ti, collection_label);
    }
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

    proto_tree_add_string(tree, hf_item, tvb, offset, 16, kafka_tvb_get_uuid(kinfo->pinfo->pool, tvb, offset));

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
