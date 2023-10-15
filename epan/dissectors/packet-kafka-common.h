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

/* Some values to temporarily remember during dissection */
typedef struct kafka_packet_values_s {
    kafka_partition_t partition_id;
    kafka_offset_t    offset;
} kafka_packet_values_t;

typedef struct kafka_buffer_ref {
    gint offset;
    gint length;
} kafka_buffer_ref;

typedef int(*dissect_kafka_object_v2_fields_cb)(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset
        );

typedef int(*dissect_kafka_object_v2_tags_cb)(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset,
        guint64 tag
        );

typedef int(*dissect_kafka_array_element_cb)(
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        proto_tree *tree,
        int offset
);

#define __KAFKA_SINCE_VERSION__(x) \
	if (kinfo->api_version >= x) \
    /* user's code goes here */

#define __KAFKA_UNTIL_VERSION__(x) \
	if (kinfo->api_version <= x) \
    /* user's code goes here */

#define __KAFKA_STRING__(x) \
	kafka_tvb_get_string(kinfo->pinfo->pool, tvb, x.offset, x.length)

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
dissect_kafka_int8_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        gint8 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int8(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint8 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int16_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        gint16 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int16(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint16 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int32_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        gint32 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int32(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint32 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int64_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_int64(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_varint(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_varuint(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        guint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_timestamp_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_timestamp(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        gint64 *ret);

WS_DLL_PUBLIC int
dissect_kafka_regular_string_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer);

WS_DLL_PUBLIC int
dissect_kafka_compact_string_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer);

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
WS_DLL_PUBLIC int
dissect_kafka_string_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer);

WS_DLL_PUBLIC int
dissect_kafka_string(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        kafka_buffer_ref *p_buffer);

WS_DLL_PUBLIC int
dissect_kafka_regular_bytes_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer);

WS_DLL_PUBLIC int
dissect_kafka_compact_bytes_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer);

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
WS_DLL_PUBLIC int
dissect_kafka_bytes_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        kafka_buffer_ref *p_buffer);

WS_DLL_PUBLIC int
dissect_kafka_bytes(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        kafka_buffer_ref *p_buffer);

WS_DLL_PUBLIC int
dissect_kafka_uuid_v2(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        int hf_item,
        void *ret);

WS_DLL_PUBLIC int
dissect_kafka_uuid(
        proto_tree *tree,
        int hf_item,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        kafka_buffer_ref *ret);

WS_DLL_PUBLIC int
dissect_kafka_array(
        proto_tree *tree,
        tvbuff_t *tvb,
        kafka_packet_info_t *kinfo,
        int offset,
        dissect_kafka_array_element_cb element_cb,
        int *p_count);

#endif /* packet-kafka-common.h */
