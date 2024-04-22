/* packet-kafka-common.h
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

#ifndef __PACKET_KAFKA_COMMON_H
#define __PACKET_KAFKA_COMMON_H

#include "ws_symbol_export.h"

typedef gint16 kafka_api_key_t;
typedef gint16 kafka_api_version_t;
typedef gint16 kafka_error_t;
typedef gint32 kafka_partition_t;
typedef gint64 kafka_offset_t;

typedef struct kafka_api_info_s {
    kafka_api_key_t api_key;
    const char *name;
    /* If api key is not supported then set min_version and max_version to -1 */
    kafka_api_version_t min_version;
    kafka_api_version_t max_version;
    /* Added in Kafka 2.4. Protocol messages are upgraded gradually. */
    kafka_api_version_t flexible_since;
} kafka_api_info_t;

typedef struct kafka_conv_info_s {
    char *sasl_auth_mech;    /* authentication mechanism, set by KAFKA_SASL_HANDSHAKE */
    wmem_multimap_t *match_map; /* */
} kafka_conv_info_t;

typedef struct kafka_proto_data_s {
    kafka_api_key_t     api_key;
    kafka_api_version_t api_version;
    guint32  correlation_id;
    guint32  request_frame;
    guint32  response_frame;
    gboolean flexible_api;
    gint8    *client_id;
} kafka_proto_data_t;

typedef struct kafka_packet_info_s {
    packet_info *pinfo;
    kafka_api_key_t     api_key;
    kafka_api_version_t api_version;
    guint32  correlation_id;
    guint32  request_frame;
    guint32  response_frame;
    gboolean flexible_api;
    gint8    *client_id;
} kafka_packet_info_t;

typedef struct kafka_buffer_ref {
    gint offset;
    gint length;
} kafka_buffer_ref;

#define __KAFKA_SINCE_VERSION__(x) \
	if (kinfo->api_version >= x) \
    /* user's code goes here */

#define __KAFKA_UNTIL_VERSION__(x) \
	if (kinfo->api_version <= x) \
    /* user's code goes here */

#define __KAFKA_STRING__(x) \
	kafka_tvb_get_string(kinfo->pinfo->pool, tvb, x.offset, x.length)
#define __KAFKA_UUID__(x) \
	kafka_tvb_get_uuid(kinfo->pinfo->pool, tvb, x)

WS_DLL_PUBLIC gint8*
kafka_tvb_get_string(
        wmem_allocator_t *pool,
        tvbuff_t *tvb,
        int offset,
        int length);

WS_DLL_PUBLIC gint8*
kafka_tvb_get_uuid(
        wmem_allocator_t *pool,
        tvbuff_t *tvb,
        int offset);

WS_DLL_PUBLIC int
dissect_kafka_int8_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint8 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int8(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item);

WS_DLL_PUBLIC int
dissect_kafka_int16_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint16 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int16(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item);

WS_DLL_PUBLIC int
dissect_kafka_int32_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint32 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int32(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

WS_DLL_PUBLIC int
dissect_kafka_int64_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int64(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item);

WS_DLL_PUBLIC int
dissect_kafka_varint_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_varuint_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        guint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_timestamp_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint64 *ret
);

WS_DLL_PUBLIC int
dissect_kafka_timestamp(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

WS_DLL_PUBLIC int
dissect_kafka_replica_id_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        gint32 *ret
);

WS_DLL_PUBLIC int
dissect_kafka_replica_id(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

WS_DLL_PUBLIC int
dissect_kafka_regular_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

WS_DLL_PUBLIC int
dissect_kafka_compact_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
WS_DLL_PUBLIC int
dissect_kafka_string_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

WS_DLL_PUBLIC int
dissect_kafka_string(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

WS_DLL_PUBLIC int
dissect_kafka_regular_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

WS_DLL_PUBLIC int
dissect_kafka_compact_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

/*
 * Dissect bytes. Depending on the 'flexible' flag use old style or compact coding.
 */
WS_DLL_PUBLIC int
dissect_kafka_bytes_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

WS_DLL_PUBLIC int
dissect_kafka_bytes(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

WS_DLL_PUBLIC int
dissect_kafka_base64_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer
);

WS_DLL_PUBLIC int
dissect_kafka_base64(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

WS_DLL_PUBLIC int
dissect_kafka_uuid_ret(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item,
        kafka_buffer_ref *ret
);

WS_DLL_PUBLIC int
dissect_kafka_uuid(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int hf_item
);

typedef int(*dissect_kafka_object_content_cb)(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset
);

WS_DLL_PUBLIC int
dissect_kafka_object(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int ett_idx,
        const char *label,
        dissect_kafka_object_content_cb func
);

typedef int(*dissect_kafka_array_simple_cb)(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int idx
);

WS_DLL_PUBLIC int
dissect_kafka_array_simple(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int collection_ett, const char *collection_label,
        dissect_kafka_array_simple_cb func,
        int item_hf
);

WS_DLL_PUBLIC int
dissect_kafka_array_object(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        int collection_ett, const char *collection_label,
        int item_ett, const char *item_label,
        dissect_kafka_object_content_cb func
);

typedef int(*dissect_kafka_object_tags_cb)(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        gint offset,
        guint64 tag
);

WS_DLL_PUBLIC int
dissect_kafka_tagged_fields(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        dissect_kafka_object_tags_cb func
);

#endif /* packet-kafka-common.h */
