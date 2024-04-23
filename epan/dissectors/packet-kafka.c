/* packet-kafka.c
 * Routines for Apache Kafka Protocol dissection (version 0.8 - 2.5)
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 * Update from Kafka 0.10.1.0 to 2.5 by Piotr Smolinski <piotr.smolinski@confluent.io>
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

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#ifdef HAVE_SNAPPY
#include <snappy-c.h>
#endif
#ifdef HAVE_LZ4FRAME_H
#include <lz4.h>
#include <lz4frame.h>
#endif
#include "packet-tcp.h"
#include "packet-tls.h"
#include "packet-gssapi.h"

#include "packet-kafka-common.h"

void proto_register_kafka(void);
void proto_reg_handoff_kafka(void);

static int proto_kafka = -1;

static dissector_handle_t kafka_handle;
static dissector_handle_t gssapi_handle;

static int hf_kafka_len = -1;
static int hf_kafka_api_key = -1;
static int hf_kafka_api_version = -1;
static int hf_kafka_request_api_key = -1;
static int hf_kafka_response_api_key = -1;
static int hf_kafka_request_api_version = -1;
static int hf_kafka_response_api_version = -1;
static int hf_kafka_correlation_id = -1;
static int hf_kafka_client_id = -1;
static int hf_kafka_client_host = -1;
static int hf_kafka_required_acks = -1;
static int hf_kafka_timeout = -1;
static int hf_kafka_topic_name = -1;
static int hf_kafka_topic_id = -1;
static int hf_kafka_transactional_id = -1;
static int hf_kafka_transaction_result = -1;
static int hf_kafka_transaction_timeout = -1;
static int hf_kafka_transaction_state = -1;
static int hf_kafka_transaction_state_filter = -1;
static int hf_kafka_unknown_transaction_state_filter = -1;
static int hf_kafka_transaction_start_time = -1;
static int hf_kafka_partition_id = -1;
static int hf_kafka_replica = -1;
static int hf_kafka_replica_epoch = -1;
static int hf_kafka_replication_factor = -1;
static int hf_kafka_isr = -1;
static int hf_kafka_offline = -1;
static int hf_kafka_high_watermark = -1;
static int hf_kafka_last_stable_offset = -1;
static int hf_kafka_last_fetched_epoch = -1;
static int hf_kafka_candidate_id = -1;
static int hf_kafka_candidate_epoch = -1;
static int hf_kafka_preferred_successor = -1;
static int hf_kafka_last_offset = -1;
static int hf_kafka_last_offset_epoch = -1;
static int hf_kafka_log_start_offset = -1;
static int hf_kafka_first_offset = -1;
static int hf_kafka_preferred_read_replica = -1;
static int hf_kafka_producer_id = -1;
static int hf_kafka_producer_id_filter = -1;
static int hf_kafka_producer_id_start = -1;
static int hf_kafka_producer_id_length = -1;
static int hf_kafka_duration_filter = -1;
static int hf_kafka_producer_epoch = -1;
static int hf_kafka_message_size = -1;
static int hf_kafka_message_crc = -1;
static int hf_kafka_message_magic = -1;
static int hf_kafka_message_codec = -1;
static int hf_kafka_message_timestamp_type = -1;
static int hf_kafka_message_timestamp = -1;
static int hf_kafka_batch_crc = -1;
static int hf_kafka_batch_codec = -1;
static int hf_kafka_batch_timestamp_type = -1;
static int hf_kafka_batch_transactional = -1;
static int hf_kafka_batch_control_batch = -1;
static int hf_kafka_batch_last_offset_delta = -1;
static int hf_kafka_batch_first_timestamp = -1;
static int hf_kafka_batch_last_timestamp = -1;
static int hf_kafka_batch_base_sequence = -1;
static int hf_kafka_batch_size = -1;
static int hf_kafka_batch_index = -1;
static int hf_kafka_batch_index_error_message = -1;
static int hf_kafka_message_key = -1;
static int hf_kafka_message_value = -1;
static int hf_kafka_message_compression_reduction = -1;
static int hf_kafka_truncated_content = -1;
static int hf_kafka_request_frame = -1;
static int hf_kafka_response_frame = -1;
static int hf_kafka_consumer_group = -1;
static int hf_kafka_consumer_group_instance = -1;
static int hf_kafka_coordinator_key = -1;
static int hf_kafka_coordinator_type = -1;
static int hf_kafka_group_operation_reason = -1;
static int hf_kafka_group_state = -1;
static int hf_kafka_group_type = -1;
static int hf_kafka_offset = -1;
static int hf_kafka_offset_time = -1;
static int hf_kafka_max_offsets = -1;
static int hf_kafka_metadata = -1;
static int hf_kafka_error = -1;
static int hf_kafka_error_message = -1;
static int hf_kafka_broker_nodeid = -1;
static int hf_kafka_broker_epoch = -1;
static int hf_kafka_broker_host = -1;
static int hf_kafka_broker_metadata_offset = -1;
static int hf_kafka_broker_want_fence = -1;
static int hf_kafka_broker_want_shutdown = -1;
static int hf_kafka_broker_is_caught_up = -1;
static int hf_kafka_broker_is_fenced = -1;
static int hf_kafka_broker_should_shutdown = -1;
static int hf_kafka_leader_and_isr_type = -1;
static int hf_kafka_lead_recovery_state = -1;
static int hf_kafka_is_kraft_controller = -1;
static int hf_kafka_is_migrating_zk_broker = -1;
static int hf_kafka_isr_request_type = -1;
static int hf_kafka_listener_name = -1;
static int hf_kafka_broker_port = -1;
static int hf_kafka_rack = -1;
static int hf_kafka_broker_security_protocol_type = -1;
static int hf_kafka_cluster_id = -1;
static int hf_kafka_controller_id = -1;
static int hf_kafka_controller_epoch = -1;
static int hf_kafka_delete_partitions = -1;
static int hf_kafka_leader_id = -1;
static int hf_kafka_group_leader_id = -1;
static int hf_kafka_skip_assignments = -1;
static int hf_kafka_leader_epoch = -1;
static int hf_kafka_current_leader_epoch = -1;
static int hf_kafka_end_offset = -1;
static int hf_kafka_last_fetch_timestamp = -1;
static int hf_kafka_last_caught_up_timestamp = -1;
static int hf_kafka_is_internal = -1;
static int hf_kafka_isolation_level = -1;
static int hf_kafka_min_bytes = -1;
static int hf_kafka_max_bytes = -1;
static int hf_kafka_max_wait_time = -1;
static int hf_kafka_throttle_time = -1;
static int hf_kafka_api_versions_api_key = -1;
static int hf_kafka_api_versions_min_version = -1;
static int hf_kafka_api_versions_max_version = -1;
static int hf_kafka_feature_name = -1;
static int hf_kafka_feature_min_version = -1;
static int hf_kafka_feature_max_version = -1;
static int hf_kafka_finalized_features_epoch = -1;
static int hf_kafka_session_timeout = -1;
static int hf_kafka_rebalance_timeout = -1;
static int hf_kafka_member_id = -1;
static int hf_kafka_member_epoch = -1;
static int hf_kafka_protocol_type = -1;
static int hf_kafka_protocol_name = -1;
static int hf_kafka_protocol_metadata = -1;
static int hf_kafka_member_metadata = -1;
static int hf_kafka_generation_id = -1;
static int hf_kafka_member_assignment = -1;
static int hf_kafka_sasl_mechanism = -1;
static int hf_kafka_num_partitions = -1;
static int hf_kafka_zk_version = -1;
static int hf_kafka_is_new_replica = -1;
static int hf_kafka_config_key = -1;
static int hf_kafka_config_value = -1;
static int hf_kafka_config_error_code = -1;
static int hf_kafka_commit_timestamp = -1;
static int hf_kafka_retention_time = -1;
static int hf_kafka_forgotten_topic_name = -1;
static int hf_kafka_forgotten_topic_partition = -1;
static int hf_kafka_fetch_session_id = -1;
static int hf_kafka_fetch_session_epoch = -1;
static int hf_kafka_require_stable_offset = -1;
static int hf_kafka_record_header_key = -1;
static int hf_kafka_record_header_value = -1;
static int hf_kafka_record_attributes = -1;
static int hf_kafka_allow_auto_topic_creation = -1;
static int hf_kafka_validate_only = -1;
static int hf_kafka_coordinator_epoch = -1;
static int hf_kafka_sasl_auth_bytes = -1;
static int hf_kafka_session_lifetime_ms = -1;
static int hf_kafka_acl_resource_type = -1;
static int hf_kafka_acl_resource_name = -1;
static int hf_kafka_acl_resource_pattern_type = -1;
static int hf_kafka_acl_principal = -1;
static int hf_kafka_acl_host = -1;
static int hf_kafka_acl_operation = -1;
static int hf_kafka_acl_permission_type = -1;
static int hf_kafka_config_resource_type = -1;
static int hf_kafka_config_resource_name = -1;
static int hf_kafka_config_include_synonyms = -1;
static int hf_kafka_config_include_documentation = -1;
static int hf_kafka_config_source = -1;
static int hf_kafka_config_type = -1;
static int hf_kafka_config_readonly = -1;
static int hf_kafka_config_default = -1;
static int hf_kafka_config_sensitive = -1;
static int hf_kafka_config_operation = -1;
static int hf_kafka_config_documentation = -1;
static int hf_kafka_log_dir = -1;
static int hf_kafka_segment_size = -1;
static int hf_kafka_offset_lag = -1;
static int hf_kafka_future = -1;
static int hf_kafka_dir_total_bytes = -1;
static int hf_kafka_dir_usable_bytes = -1;
static int hf_kafka_partition_count = -1;
static int hf_kafka_token_max_life_time = -1;
static int hf_kafka_token_renew_time = -1;
static int hf_kafka_token_expiry_time = -1;
static int hf_kafka_token_principal_type = -1;
static int hf_kafka_token_principal_name = -1;
static int hf_kafka_requester_principal_type = -1;
static int hf_kafka_requester_principal_name = -1;
static int hf_kafka_token_issue_timestamp = -1;
static int hf_kafka_token_expiry_timestamp = -1;
static int hf_kafka_token_max_timestamp = -1;
static int hf_kafka_token_id = -1;
static int hf_kafka_token_hmac = -1;
static int hf_kafka_include_cluster_authorized_ops = -1;
static int hf_kafka_endpoint_type = -1;
static int hf_kafka_include_topic_authorized_ops = -1;
static int hf_kafka_include_group_authorized_ops = -1;
static int hf_kafka_cluster_authorized_ops = -1;
static int hf_kafka_topic_authorized_ops = -1;
static int hf_kafka_group_authorized_ops = -1;
static int hf_kafka_election_type = -1;
static int hf_kafka_unknown_tagged_field_tag = -1;
static int hf_kafka_unknown_tagged_field_data = -1;
static int hf_kafka_client_software_name = -1;
static int hf_kafka_client_software_version = -1;
static int hf_kafka_quota_entity_name = -1;
static int hf_kafka_quota_entity_type = -1;
static int hf_kafka_quota_key = -1;
static int hf_kafka_quota_value = -1;
static int hf_kafka_quota_remove = -1;
static int hf_kafka_quota_match_type = -1;
static int hf_kafka_quota_match_text = -1;
static int hf_kafka_quota_strict_match = -1;
static int hf_kafka_quota_validate_only = -1;
static int hf_kafka_scram_user_name = -1;
static int hf_kafka_scram_mechanism = -1;
static int hf_kafka_scram_iterations = -1;
static int hf_kafka_scram_salt = -1;
static int hf_kafka_scram_salted_password = -1;
static int hf_kafka_isr_version = -1;
static int hf_kafka_feature_allow_downgrade = -1;
static int hf_kafka_feature_upgrade_type = -1;
static int hf_kafka_envelope_data = -1;
static int hf_kafka_envelope_request_principal = -1;
static int hf_kafka_envelope_client_host = -1;
static int hf_kafka_snapshot_size = -1;
static int hf_kafka_snapshot_position = -1;
static int hf_kafka_snapshot_unaligned_records = -1;
static int hf_kafka_last_sequence = -1;
static int hf_kafka_last_timestamp = -1;
static int hf_kafka_current_txn_start_offset = -1;
static int hf_kafka_incarnation_id = -1;
static int hf_kafka_vote_granted = -1;

static int hf_sasl_plain_authzid = -1;
static int hf_sasl_plain_authcid = -1;
static int hf_sasl_plain_passwd = -1;

static int ett_kafka = -1;
static int ett_kafka_batch = -1;
static int ett_kafka_message = -1;
static int ett_kafka_message_set = -1;
static int ett_kafka_replicas = -1;
static int ett_kafka_replica_state = -1;
static int ett_kafka_isrs = -1;
static int ett_kafka_offline = -1;
static int ett_kafka_broker = -1;
static int ett_kafka_brokers = -1;
static int ett_kafka_broker_endpoint = -1;
static int ett_kafka_markers = -1;
static int ett_kafka_marker = -1;
static int ett_kafka_topics = -1;
static int ett_kafka_topic = -1;
static int ett_kafka_partitions = -1;
static int ett_kafka_partition = -1;
static int ett_kafka_api_version = -1;
static int ett_kafka_group_protocols = -1;
static int ett_kafka_group_protocol = -1;
static int ett_kafka_group_members = -1;
static int ett_kafka_group_member = -1;
static int ett_kafka_group_assignments = -1;
static int ett_kafka_group_assignment = -1;
static int ett_kafka_groups = -1;
static int ett_kafka_group = -1;
static int ett_kafka_sasl_enabled_mechanisms = -1;
static int ett_kafka_replica_assignment = -1;
static int ett_kafka_configs = -1;
static int ett_kafka_config = -1;
static int ett_kafka_request_forgotten_topic = -1;
static int ett_kafka_record = -1;
static int ett_kafka_record_headers = -1;
static int ett_kafka_record_headers_header = -1;
static int ett_kafka_aborted_transactions = -1;
static int ett_kafka_aborted_transaction = -1;
static int ett_kafka_resources = -1;
static int ett_kafka_resource = -1;
static int ett_kafka_acls = -1;
static int ett_kafka_acl = -1;
static int ett_kafka_acl_creations = -1;
static int ett_kafka_acl_creation = -1;
static int ett_kafka_acl_filters = -1;
static int ett_kafka_acl_filter = -1;
static int ett_kafka_acl_filter_matches = -1;
static int ett_kafka_acl_filter_match = -1;
static int ett_kafka_config_synonyms = -1;
static int ett_kafka_config_synonym = -1;
static int ett_kafka_config_entries = -1;
static int ett_kafka_config_entry = -1;
static int ett_kafka_log_dirs = -1;
static int ett_kafka_log_dir = -1;
static int ett_kafka_principals = -1;
static int ett_kafka_principal = -1;
static int ett_kafka_owners = -1;
static int ett_kafka_owner = -1;
static int ett_kafka_tokens = -1;
static int ett_kafka_token = -1;
static int ett_kafka_unknown_tagged_field = -1;
static int ett_kafka_record_errors = -1;
static int ett_kafka_record_error = -1;
static int ett_kafka_states_filter = -1;
static int ett_kafka_quota_component = -1;
static int ett_kafka_quota_entity = -1;
static int ett_kafka_quota_entry = -1;
static int ett_kafka_quota_value = -1;
static int ett_kafka_quota_operation = -1;
static int ett_kafka_diverging_epoch = -1;
static int ett_kafka_current_leader = -1;
static int ett_kafka_snapshot_id = -1;
static int ett_kafka_scram_user = -1;
static int ett_kafka_scram_credential_info = -1;
static int ett_kafka_scram_operation = -1;
static int ett_kafka_scram_result = -1;
static int ett_kafka_voter = -1;
static int ett_kafka_feature = -1;
static int ett_kafka_producer = -1;
static int ett_kafka_listener = -1;
static int ett_kafka_transaction = -1;
static int ett_kafka_sasl_token = -1;

static expert_field ei_kafka_request_missing = EI_INIT;
static expert_field ei_kafka_duplicate_correlation_id = EI_INIT;
static expert_field ei_kafka_unknown_api_key = EI_INIT;
static expert_field ei_kafka_unsupported_api_version = EI_INIT;
static expert_field ei_kafka_error_response = EI_INIT;
static expert_field ei_kafka_bad_string_length = EI_INIT;
static expert_field ei_kafka_bad_bytes_length = EI_INIT;
static expert_field ei_kafka_bad_array_length = EI_INIT;
static expert_field ei_kafka_bad_record_length = EI_INIT;
static expert_field ei_kafka_bad_varint = EI_INIT;
static expert_field ei_kafka_bad_message_set_length = EI_INIT;
static expert_field ei_kafka_bad_decompression_length = EI_INIT;
static expert_field ei_kafka_zero_decompression_length = EI_INIT;
static expert_field ei_kafka_unknown_message_magic = EI_INIT;
static expert_field ei_kafka_pdu_length_mismatch = EI_INIT;

#define KAFKA_TCP_DEFAULT_RANGE     "9092"

#define KAFKA_PRODUCE                        0
#define KAFKA_FETCH                          1
#define KAFKA_OFFSETS                        2
#define KAFKA_METADATA                       3
#define KAFKA_LEADER_AND_ISR                 4
#define KAFKA_STOP_REPLICA                   5
#define KAFKA_UPDATE_METADATA                6
#define KAFKA_CONTROLLED_SHUTDOWN            7
#define KAFKA_OFFSET_COMMIT                  8
#define KAFKA_OFFSET_FETCH                   9
#define KAFKA_FIND_COORDINATOR              10
#define KAFKA_JOIN_GROUP                    11
#define KAFKA_HEARTBEAT                     12
#define KAFKA_LEAVE_GROUP                   13
#define KAFKA_SYNC_GROUP                    14
#define KAFKA_DESCRIBE_GROUPS               15
#define KAFKA_LIST_GROUPS                   16
#define KAFKA_SASL_HANDSHAKE                17
#define KAFKA_API_VERSIONS                  18
#define KAFKA_CREATE_TOPICS                 19
#define KAFKA_DELETE_TOPICS                 20
#define KAFKA_DELETE_RECORDS                21
#define KAFKA_INIT_PRODUCER_ID              22
#define KAFKA_OFFSET_FOR_LEADER_EPOCH       23
#define KAFKA_ADD_PARTITIONS_TO_TXN         24
#define KAFKA_ADD_OFFSETS_TO_TXN            25
#define KAFKA_END_TXN                       26
#define KAFKA_WRITE_TXN_MARKERS             27
#define KAFKA_TXN_OFFSET_COMMIT             28
#define KAFKA_DESCRIBE_ACLS                 29
#define KAFKA_CREATE_ACLS                   30
#define KAFKA_DELETE_ACLS                   31
#define KAFKA_DESCRIBE_CONFIGS              32
#define KAFKA_ALTER_CONFIGS                 33
#define KAFKA_ALTER_REPLICA_LOG_DIRS        34
#define KAFKA_DESCRIBE_LOG_DIRS             35
#define KAFKA_SASL_AUTHENTICATE             36
#define KAFKA_CREATE_PARTITIONS             37
#define KAFKA_CREATE_DELEGATION_TOKEN       38
#define KAFKA_RENEW_DELEGATION_TOKEN        39
#define KAFKA_EXPIRE_DELEGATION_TOKEN       40
#define KAFKA_DESCRIBE_DELEGATION_TOKEN     41
#define KAFKA_DELETE_GROUPS                 42
#define KAFKA_ELECT_LEADERS                 43
#define KAFKA_INC_ALTER_CONFIGS             44
#define KAFKA_ALTER_PARTITION_REASSIGNMENTS 45
#define KAFKA_LIST_PARTITION_REASSIGNMENTS  46
#define KAFKA_OFFSET_DELETE                 47
#define KAFKA_DESCRIBE_CLIENT_QUOTAS        48
#define KAFKA_ALTER_CLIENT_QUOTAS           49
#define KAFKA_DESCRIBE_USER_SCRAM_CREDENTIALS 50
#define KAFKA_ALTER_USER_SCRAM_CREDENTIALS    51
#define KAFKA_VOTE                            52
#define KAFKA_BEGIN_QUORUM_EPOCH              53
#define KAFKA_END_QUORUM_EPOCH                54
#define KAFKA_DESCRIBE_QUORUM                 55
#define KAFKA_ALTER_PARTITION                 56
#define KAFKA_UPDATE_FEATURES                 57
#define KAFKA_ENVELOPE                        58
#define KAFKA_FETCH_SHAPSHOT                  59
#define KAFKA_DESCRIBE_CLUSTER                60
#define KAFKA_DESCRIBE_PRODUCERS              61
#define KAFKA_BROKER_REGISTRATION             62
#define KAFKA_BROKER_HEARTBEAT                63
#define KAFKA_UNREGISTER_BROKER               64
#define KAFKA_DESCRIBE_TRANSACTIONS           65
#define KAFKA_LIST_TRANSACTIONS               66
#define KAFKA_ALLOCATE_PRODUCER_IDS           67

/*
 * Check for message changes here:
 * https://github.com/apache/kafka/tree/trunk/clients/src/main/resources/common/message
 * The values are:
 * - api key
 * - min supported version
 * - max supported version
 * - flexible since (new in 2.4) - drives if string fields are prefixed by short or varint (unsigned)
 * Flexible request header is 2 and response header id 1.
 * Note that request header version is hardcoded to 0 for ControlledShutdown v.0 and
 * response header version for ApiVersions is always 0.
 */
static const kafka_api_info_t kafka_apis[] = {
    { KAFKA_PRODUCE,                       "Produce",
      0, 10, 9 },
    { KAFKA_FETCH,                         "Fetch",
      0, 16, 12 },
    { KAFKA_OFFSETS,                       "Offsets",
      0, 8, 6 },
    { KAFKA_METADATA,                      "Metadata",
      0, 12, 9 },
    { KAFKA_LEADER_AND_ISR,                "LeaderAndIsr",
      0, 7, 4 },
    { KAFKA_STOP_REPLICA,                  "StopReplica",
      0, 4, 2 },
    { KAFKA_UPDATE_METADATA,               "UpdateMetadata",
      0, 8, 6 },
    { KAFKA_CONTROLLED_SHUTDOWN,           "ControlledShutdown",
      0, 3, 3 },
    { KAFKA_OFFSET_COMMIT,                 "OffsetCommit",
      0, 9, 8 },
    { KAFKA_OFFSET_FETCH,                  "OffsetFetch",
      0, 9, 6 },
    { KAFKA_FIND_COORDINATOR,              "FindCoordinator",
      0, 4, 3 },
    { KAFKA_JOIN_GROUP,                    "JoinGroup",
      0, 9, 6 },
    { KAFKA_HEARTBEAT,                     "Heartbeat",
      0, 4, 4 },
    { KAFKA_LEAVE_GROUP,                   "LeaveGroup",
      0, 5, 4 },
    { KAFKA_SYNC_GROUP,                    "SyncGroup",
      0, 5, 4 },
    { KAFKA_DESCRIBE_GROUPS,               "DescribeGroups",
      0, 5, 5 },
    { KAFKA_LIST_GROUPS,                   "ListGroups",
      0, 4, 3 },
    { KAFKA_SASL_HANDSHAKE,                "SaslHandshake",
      0, 1, -1 },
    { KAFKA_API_VERSIONS,                  "ApiVersions",
      0, 3, 3 },
    { KAFKA_CREATE_TOPICS,                 "CreateTopics",
      0, 7, 5 },
    { KAFKA_DELETE_TOPICS,                 "DeleteTopics",
      0, 6, 4 },
    { KAFKA_DELETE_RECORDS,                "DeleteRecords",
      0, 2, 2 },
    { KAFKA_INIT_PRODUCER_ID,              "InitProducerId",
      0, 4, 2 },
    { KAFKA_OFFSET_FOR_LEADER_EPOCH,       "OffsetForLeaderEpoch",
      0, 4, 4 },
    { KAFKA_ADD_PARTITIONS_TO_TXN,         "AddPartitionsToTxn",
      0, 3, 3 },
    { KAFKA_ADD_OFFSETS_TO_TXN,            "AddOffsetsToTxn",
      0, 3, 3 },
    { KAFKA_END_TXN,                       "EndTxn",
      0, 3, 3 },
    { KAFKA_WRITE_TXN_MARKERS,             "WriteTxnMarkers",
      0, 1, 1 },
    { KAFKA_TXN_OFFSET_COMMIT,             "TxnOffsetCommit",
      0, 3, 3 },
    { KAFKA_DESCRIBE_ACLS,                 "DescribeAcls",
      0, 3, 2 },
    { KAFKA_CREATE_ACLS,                   "CreateAcls",
      0, 3, 2 },
    { KAFKA_DELETE_ACLS,                   "DeleteAcls",
      0, 3, 2 },
    { KAFKA_DESCRIBE_CONFIGS,              "DescribeConfigs",
      0, 4, 4 },
    { KAFKA_ALTER_CONFIGS,                 "AlterConfigs",
      0, 2, 2 },
    { KAFKA_ALTER_REPLICA_LOG_DIRS,        "AlterReplicaLogDirs",
      0, 2, 2 },
    { KAFKA_DESCRIBE_LOG_DIRS,             "DescribeLogDirs",
      0, 4, 2 },
    { KAFKA_SASL_AUTHENTICATE,             "SaslAuthenticate",
      0, 2, 2 },
    { KAFKA_CREATE_PARTITIONS,             "CreatePartitions",
      0, 3, 2 },
    { KAFKA_CREATE_DELEGATION_TOKEN,       "CreateDelegationToken",
      0, 3, 2 },
    { KAFKA_RENEW_DELEGATION_TOKEN,        "RenewDelegationToken",
      0, 2, 2 },
    { KAFKA_EXPIRE_DELEGATION_TOKEN,       "ExpireDelegationToken",
      0, 2, 2 },
    { KAFKA_DESCRIBE_DELEGATION_TOKEN,     "DescribeDelegationToken",
      0, 3, 2 },
    { KAFKA_DELETE_GROUPS,                 "DeleteGroups",
      0, 2, 2 },
    { KAFKA_ELECT_LEADERS,                 "ElectLeaders",
      0, 2, 2 },
    { KAFKA_INC_ALTER_CONFIGS,             "IncrementalAlterConfigs",
      0, 1, 1 },
    { KAFKA_ALTER_PARTITION_REASSIGNMENTS, "AlterPartitionReassignments",
      0, 0, 0 },
    { KAFKA_LIST_PARTITION_REASSIGNMENTS,  "ListPartitionReassignments",
      0, 0, 0 },
    { KAFKA_OFFSET_DELETE,  "OffsetDelete",
      0, 0, -1 },
    { KAFKA_DESCRIBE_CLIENT_QUOTAS,  "DescribeClientQuotas",
      0, 1, 1 },
    { KAFKA_ALTER_CLIENT_QUOTAS,     "AlterClientQuotas",
      0, 1, 1 },
    { KAFKA_DESCRIBE_USER_SCRAM_CREDENTIALS, "DescribeUserScramCredentials",
      0, 0, 0 },
    { KAFKA_ALTER_USER_SCRAM_CREDENTIALS,   "AlterUserScramCredentials",
      0, 0, 0 },
    { KAFKA_VOTE,                           "Vote",
      0, 0, 0 },
    { KAFKA_BEGIN_QUORUM_EPOCH,             "BeginQuorumEpoch",
      0, 0, -1 },
    { KAFKA_END_QUORUM_EPOCH,               "EndQuorumEpoch",
      0, 0, -1 },
    { KAFKA_DESCRIBE_QUORUM,                "DescribeQuorum",
      0, 1, 0 },
    { KAFKA_ALTER_PARTITION,                "AlterPartition",
      0, 3, 0 },
    { KAFKA_UPDATE_FEATURES,                "UpdateFeatures",
      0, 1, 0 },
    { KAFKA_ENVELOPE,                       "Envelope",
      0, 0, 0 },
    { KAFKA_FETCH_SHAPSHOT,                 "FetchSnapshot",
      0, 0, 0 },
    { KAFKA_DESCRIBE_CLUSTER,               "DescribeCluster",
      0, 1, 0 },
    { KAFKA_DESCRIBE_PRODUCERS,             "DescribeProducers",
      0, 0, 0 },
    { KAFKA_BROKER_REGISTRATION,            "BrokerRegistration",
      0, 1, 0 },
    { KAFKA_BROKER_HEARTBEAT,               "BrokerHeartbeat",
      0, 0, 0 },
    { KAFKA_UNREGISTER_BROKER,              "UnregisterBroker",
      0, 0, 0 },
    { KAFKA_DESCRIBE_TRANSACTIONS,          "DescribeTransactions",
      0, 0, 0 },
    { KAFKA_LIST_TRANSACTIONS,              "ListTransactions",
      0, 1, 0 },
    { KAFKA_ALLOCATE_PRODUCER_IDS,          "AllocateProducerIds",
      0, 0, 0 },
};

/*
 * Generated from kafka_apis. Add 1 to length for last dummy element.
 */
static value_string kafka_api_names[array_length(kafka_apis) + 1];

/*
 * For the current list of error codes check here:
 * https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/protocol/Errors.java
 */
static const value_string kafka_errors[] = {
    { -1, "Unexpected Server Error" },
    { 0, "No Error" },
    { 1, "Offset Out Of Range" },
    { 2, "Invalid Message" },
    { 3, "Unknown Topic or Partition" },
    { 4, "Invalid Message Size" },
    { 5, "Leader Not Available" },
    { 6, "Not Leader For Partition" },
    { 7, "Request Timed Out" },
    { 8, "Broker Not Available" },
    { 9, "Replica Not Available" },
    { 10, "Message Size Too Large" },
    { 11, "Stale Controller Epoch Code" },
    { 12, "Offset Metadata Too Large" },
    { 13, "The server disconnected before a response was received" },
    { 14, "Offsets Load In Progress" },
    { 15, "The Coordinator is not Available" },
    { 16, "This is not the correct coordinator" },
    { 17, "Invalid topic" },
    { 18, "Message batch larger than configured server segment size" },
    { 19, "Not enough in-sync replicas" },
    { 20, "Message(s) written to insufficient number of in-sync replicas" },
    { 21, "Invalid required acks value" },
    { 22, "Specified group generation id is not valid" },
    { 23, "Inconsistent group protocol" },
    { 24, "Invalid group.id" },
    { 25, "Unknown member" },
    { 26, "Invalid session timeout" },
    { 27, "Group rebalance in progress" },
    { 28, "Commit offset data size is not valid" },
    { 29, "Topic authorization failed" },
    { 30, "Group authorization failed" },
    { 31, "Cluster authorization failed" },
    { 32, "Invalid timestamp" },
    { 33, "Unsupported SASL mechanism" },
    { 34, "Illegal SASL state" },
    { 35, "Unsupported version" },
    { 36, "Topic already exists" },
    { 37, "Invalid number of partitions" },
    { 38, "Invalid replication-factor" },
    { 39, "Invalid replica assignment" },
    { 40, "Invalid configuration" },
    { 41, "Not controller" },
    { 42, "Invalid request" },
    { 43, "Unsupported for Message Format" },
    { 44, "Policy Violation" },
    { 45, "Out of Order Sequence Number" },
    { 46, "Duplicate Sequence Number" },
    { 47, "Invalid Producer Epoch" },
    { 48, "Invalid Transaction State" },
    { 49, "Invalid Producer ID Mapping" },
    { 50, "Invalid Transaction Timeout" },
    { 51, "Concurrent Transactions" },
    { 52, "Transaction Coordinator Fenced" },
    { 53, "Transactional ID Authorization Failed" },
    { 54, "Security Disabled" },
    { 55, "Operation not Attempted" },
    { 56, "Kafka Storage Error" },
    { 57, "Log Directory not Found" },
    { 58, "SASL Authentication failed" },
    { 59, "Unknown Producer ID" },
    { 60, "Partition Reassignment in Progress" },
    { 61, "Delegation Token Auth Disabled" },
    { 62, "Delegation Token not Found" },
    { 63, "Delegation Token Owner Mismatch" },
    { 64, "Delegation Token Request not Allowed" },
    { 65, "Delegation Token Authorization Failed" },
    { 66, "Delegation Token Expired" },
    { 67, "Supplied Principal Type Unsupported" },
    { 68, "Not Empty Group" },
    { 69, "Group ID not Found" },
    { 70, "Fetch Session ID not Found" },
    { 71, "Invalid Fetch Session Epoch" },
    { 72, "Listener not Found" },
    { 73, "Topic Deletion Disabled" },
    { 74, "Fenced Leader Epoch" },
    { 75, "Unknown Leader Epoch" },
    { 76, "Unsupported Compression Type" },
    { 77, "Stale Broker Epoch" },
    { 78, "Offset not Available" },
    { 79, "Member ID Required" },
    { 80, "Preferred Leader not Available" },
    { 81, "Group Max Size Reached" },
    { 82, "Fenced Instance ID" },
    { 83, "Eligible topic partition leaders are not available" },
    { 84, "Leader election not needed for topic partition" },
    { 85, "No partition reassignment is in progress" },
    { 86, "Deleting offsets of a topic is forbidden while the consumer group is actively subscribed to it" },
    { 87, "This record has failed the validation on broker and hence will be rejected" },
    { 88, "There are unstable offsets that need to be cleared" },
    { 89, "The throttling quota has been exceeded." },
    { 90, "There is a newer producer with the same transactionalId which fences the current one." },
    { 91, "A request illegally referred to a resource that does not exist." },
    { 92, "A request illegally referred to the same resource twice." },
    { 93, "Requested credential would not meet criteria for acceptability." },
    { 94, "Indicates that the either the sender or recipient of a voter-only request is not one of the expected voters" },
    { 95, "The given update version was invalid." },
    { 96, "Unable to update finalized features due to an unexpected server error." },
    { 97, "Request principal deserialization failed during forwarding. This indicates an internal error on the broker cluster security setup." },
    { 98, "Requested snapshot was not found" },
    { 99, "Requested position is not greater than or equal to zero, and less than the size of the snapshot." },
    { 100, "This server does not host this topic ID." },
    { 101, "This broker ID is already in use." },
    { 102, "The given broker ID was not registered." },
    { 103, "The log's topic ID did not match the topic ID in the request" },
    { 104, "The clusterId in the request does not match that found on the server" },
    { 105, "The transactionalId could not be found" },
    { 106, "The fetch session encountered inconsistent topic ID usage" },
    { 107, "The new ISR contains at least one ineligible replica." },
    { 108, "The AlterPartition request successfully updated the partition state but the leader has changed." },
    { 109, "The requested offset is moved to tiered storage." },
    { 110, "The member epoch is fenced by the group coordinator. The member must abandon all its partitions and rejoin." },
    { 111, "The instance ID is still used by another member in the consumer group. That member must leave first." },
    { 112, "The assignor or its version range is not supported by the consumer group." },
    { 113, "The member epoch is stale. The member must retry after receiving its updated member epoch via the ConsumerGroupHeartbeat API." },
    { 114, "The request was sent to an endpoint of the wrong type." },
    { 115, "This endpoint type is not supported yet." },
    { 116, "This controller ID is not known." },
    { 117, "Client sent a push telemetry request with an invalid or outdated subscription ID." },
    { 118, "Client sent a push telemetry request larger than the maximum size the broker will accept." },
    { 119, "The controller has considered the broker registration to be invalid." },
    { 120, "The server encountered an error with the transaction. The client can abort the transaction to continue using this transactional ID." },
    { 0, NULL }
};

#define KAFKA_ACK_NOT_REQUIRED 0
#define KAFKA_ACK_LEADER       1
#define KAFKA_ACK_FULL_ISR     -1
static const value_string kafka_acks[] = {
    { KAFKA_ACK_NOT_REQUIRED, "Not Required" },
    { KAFKA_ACK_LEADER,       "Leader"       },
    { KAFKA_ACK_FULL_ISR,     "Full ISR"     },
    { 0, NULL }
};

#define KAFKA_MESSAGE_CODEC_MASK   0x07
#define KAFKA_MESSAGE_CODEC_NONE   0
#define KAFKA_MESSAGE_CODEC_GZIP   1
#define KAFKA_MESSAGE_CODEC_SNAPPY 2
#define KAFKA_MESSAGE_CODEC_LZ4    3
#define KAFKA_MESSAGE_CODEC_ZSTD   4
static const value_string kafka_message_codecs[] = {
    { KAFKA_MESSAGE_CODEC_NONE,   "None"   },
    { KAFKA_MESSAGE_CODEC_GZIP,   "Gzip"   },
    { KAFKA_MESSAGE_CODEC_SNAPPY, "Snappy" },
    { KAFKA_MESSAGE_CODEC_LZ4,    "LZ4"    },
    { KAFKA_MESSAGE_CODEC_ZSTD,   "Zstd"   },
    { 0, NULL }
};
#ifdef HAVE_SNAPPY
static const guint8 kafka_xerial_header[8] = {0x82, 0x53, 0x4e, 0x41, 0x50, 0x50, 0x59, 0x00};
#endif

#define KAFKA_MESSAGE_TIMESTAMP_MASK 0x08
static const value_string kafka_message_timestamp_types[] = {
    { 0, "CreateTime" },
    { 1, "LogAppendTime" },
    { 0, NULL }
};

#define KAFKA_BATCH_TRANSACTIONAL_MASK 0x10
static const value_string kafka_batch_transactional_values[] = {
    { 0, "Non-transactional" },
    { 1, "Transactional" },
    { 0, NULL }
};

#define KAFKA_BATCH_CONTROL_BATCH_MASK 0x20
static const value_string kafka_batch_control_batch_values[] = {
    { 0, "Data batch" },
    { 1, "Control batch" },
    { 0, NULL }
};

static const value_string kafka_coordinator_types[] = {
    { 0, "Group" },
    { 1, "Transaction" },
    { 0, NULL }
};

static const value_string kafka_lead_recovery_states[] = {
        { 0, "Clean" },
        { 1, "Unclean" },
        { 0, NULL }
};

static const value_string kafka_isr_request_types[] = {
        { 0, "All" },
        { 1, "Selected" },
        { 0, NULL }
};

static const value_string kafka_security_protocol_types[] = {
    { 0, "PLAINTEXT" },
    { 1, "SSL" },
    { 2, "SASL_PLAINTEXT" },
    { 3, "SASL_SSL" },
    { 0, NULL }
};

static const value_string kafka_isolation_levels[] = {
    { 0, "Read Uncommitted" },
    { 1, "Read Committed" },
    { 0, NULL }
};

static const value_string kafka_transaction_results[] = {
    { 0, "ABORT" },
    { 1, "COMMIT" },
    { 0, NULL }
};

static const value_string acl_resource_types[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "Topic" },
    { 3, "Group" },
    { 4, "Cluster" },
    { 5, "TransactionalId" },
    { 6, "DelegationToken" },
    { 7, "User" },
    { 0, NULL }
};

static const value_string acl_resource_pattern_types[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "Match" },
    { 3, "Literal" },
    { 4, "Prefixed" },
    { 0, NULL }
};

static const value_string acl_operations[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "All" },
    { 3, "Read" },
    { 4, "Write" },
    { 5, "Create" },
    { 6, "Delete" },
    { 7, "Alter" },
    { 8, "Describe" },
    { 9, "Cluster Action" },
    { 10, "Describe Configs" },
    { 11, "Alter Configs" },
    { 12, "Idempotent Write" },
    { 0, NULL }
};

static const value_string acl_permission_types[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "Deny" },
    { 3, "Allow" },
    { 0, NULL }
};

/*
 * https://github.com/apache/kafka/blob/3.6.0/clients/src/main/java/org/apache/kafka/common/config/ConfigResource.java#L35-L55
 */
static const value_string config_resource_types[] = {
    { 0, "Unknown" },
    { 2, "Topic" },
    { 4, "Broker" },
    { 8, "Broker Logger" },
    { 0, NULL }
};

/*
 * https://github.com/apache/kafka/blob/3.6.0/clients/src/main/java/org/apache/kafka/common/requests/DescribeConfigsResponse.java#L115-L148
 */
static const value_string config_sources[] = {
    { 0, "Unknown" },
    { 1, "Topic" },
    { 2, "Broker (Dynamic)" },
    { 3, "Broker (Dynamic/Default)" },
    { 4, "Broker (Static)" },
    { 5, "Default" },
    { 5, "Broker Logger (Dynamic)" },
    { 0, NULL }
};

/*
 * https://github.com/apache/kafka/blob/3.6.0/clients/src/main/java/org/apache/kafka/common/requests/DescribeConfigsResponse.java#L150-L186
 */
static const value_string config_types[] = {
    { 0, "Unknown" },
    { 1, "Boolean" },
    { 2, "String" },
    { 3, "Int" },
    { 4, "Short" },
    { 5, "Long" },
    { 6, "Double" },
    { 7, "List" },
    { 8, "Class" },
    { 9, "Password" },
    { 0, NULL }
};

static const value_string config_operations[] = {
    { 0, "Set" },
    { 1, "Delete" },
    { 2, "Append" },
    { 3, "Subtract" },
    { 0, NULL }
};

static const value_string election_types[] = {
    { 0, "Preferred" },
    { 1, "Unclean" },
    { 0, NULL }
};

static const value_string endpoint_types[] = {
    { 0, "Unknown" },
    { 1, "Brokers" },
    { 2, "Controllers" },
    { 0, NULL }
};

static const value_string quota_match_types[] = {
    { 0, "Exact name" },
    { 1, "Default Name" },
    { 2, "Any Specified Name" },
    { 0, NULL }
};

static const value_string scram_mechanisms[] = {
    { 0, "Unknown" },
    { 1, "SCRAM-SHA-256" },
    { 2, "SCRAM-SHA-512" },
    { 0, NULL }
};

static const value_string feature_upgrade_types[] = {
    { 0, "Unknown" },
    { 1, "Upgrade" },
    { 2, "Safe Downgrade" },
    { 3, "Unsafe Downgrade" },
    { 0, NULL }
};

/* Whether to show the lengths of string and byte fields in the protocol tree.
 * It can be useful to see these, but they do clutter up the display, so disable
 * by default */
static gboolean kafka_show_string_bytes_lengths = FALSE;

/* Forward declaration (dissect_kafka_message_set() and dissect_kafka_message() call each other...) */
static int
dissect_kafka_message_set(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, gint offset, guint len, guint8 codec);

/* HELPERS */

#ifdef HAVE_LZ4FRAME_H
/* Local copy of XXH32() algorithm as found in https://github.com/lz4/lz4/blob/v1.7.5/lib/xxhash.c
   as some packagers are not providing xxhash.h in liblz4 */
typedef struct {
    guint32 total_len_32;
    guint32 large_len;
    guint32 v1;
    guint32 v2;
    guint32 v3;
    guint32 v4;
    guint32 mem32[4];   /* buffer defined as U32 for alignment */
    guint32 memsize;
    guint32 reserved;   /* never read nor write, will be removed in a future version */
} XXH32_state_t;

typedef enum {
    XXH_bigEndian=0,
    XXH_littleEndian=1
} XXH_endianess;

static const int g_one = 1;
#define XXH_CPU_LITTLE_ENDIAN   (*(const char*)(&g_one))

static const guint32 PRIME32_1 = 2654435761U;
static const guint32 PRIME32_2 = 2246822519U;
static const guint32 PRIME32_3 = 3266489917U;
static const guint32 PRIME32_4 =  668265263U;
static const guint32 PRIME32_5 =  374761393U;

#define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))

static guint32 XXH_read32(const void* memPtr)
{
    guint32 val;
    memcpy(&val, memPtr, sizeof(val));
    return val;
}

static guint32 XXH_swap32(guint32 x)
{
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff );
}

#define XXH_readLE32(ptr, endian) (endian==XXH_littleEndian ? XXH_read32(ptr) : XXH_swap32(XXH_read32(ptr)))

static guint32 XXH32_round(guint32 seed, guint32 input)
{
    seed += input * PRIME32_2;
    seed  = XXH_rotl32(seed, 13);
    seed *= PRIME32_1;
    return seed;
}

static guint32 XXH32_endian(const void* input, size_t len, guint32 seed, XXH_endianess endian)
{
    const gint8* p = (const gint8*)input;
    const gint8* bEnd = p + len;
    guint32 h32;
#define XXH_get32bits(p) XXH_readLE32(p, endian)

    if (len>=16) {
        const gint8* const limit = bEnd - 16;
        guint32 v1 = seed + PRIME32_1 + PRIME32_2;
        guint32 v2 = seed + PRIME32_2;
        guint32 v3 = seed + 0;
        guint32 v4 = seed - PRIME32_1;

        do {
            v1 = XXH32_round(v1, XXH_get32bits(p)); p+=4;
            v2 = XXH32_round(v2, XXH_get32bits(p)); p+=4;
            v3 = XXH32_round(v3, XXH_get32bits(p)); p+=4;
            v4 = XXH32_round(v4, XXH_get32bits(p)); p+=4;
        } while (p<=limit);

        h32 = XXH_rotl32(v1, 1) + XXH_rotl32(v2, 7) + XXH_rotl32(v3, 12) + XXH_rotl32(v4, 18);
    } else {
        h32  = seed + PRIME32_5;
    }

    h32 += (guint32) len;

    while (p+4<=bEnd) {
        h32 += XXH_get32bits(p) * PRIME32_3;
        h32  = XXH_rotl32(h32, 17) * PRIME32_4 ;
        p+=4;
    }

    while (p<bEnd) {
        h32 += (*p) * PRIME32_5;
        h32 = XXH_rotl32(h32, 11) * PRIME32_1 ;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

static guint XXH32(const void* input, size_t len, guint seed)
{
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;
    if (endian_detected==XXH_littleEndian)
        return XXH32_endian(input, len, seed, XXH_littleEndian);
    else
        return XXH32_endian(input, len, seed, XXH_bigEndian);
}
#endif /* HAVE_LZ4FRAME_H */

static kafka_conv_info_t *
dissect_kafka_get_conv_info(packet_info *pinfo);

static const char *
kafka_error_to_str(kafka_error_t error)
{
    return val_to_str(error, kafka_errors, "Unknown %d");
}

static const char *
kafka_api_key_to_str(kafka_api_key_t api_key)
{
    return val_to_str(api_key, kafka_api_names, "Unknown %d");
}

static const kafka_api_info_t *
kafka_get_api_info(kafka_api_key_t api_key)
{
    if ((api_key >= 0) && (api_key < ((kafka_api_key_t) array_length(kafka_apis)))) {
        return &kafka_apis[api_key];
    } else {
        return NULL;
    }
}

/*
 * Check if the API version uses flexible coding. Flexible coding was introduced in Kafka 2.4.
 * The major changes in the flexible versions:
 * - string length is stored as varint instead of int16
 * - the header and message content may include additional flexible fields.
 * The flexible version affects also the header. Normally the header version is 1.
 * Flexible API headers are version 2. There are two hardcoded exceptions. ControlledShutdown
 * request always uses header version 0. Same applies for ApiVersions response. These cases
 * have to be covered in the message parsing.
 */
static gboolean
kafka_is_api_version_flexible(kafka_api_key_t api_key, kafka_api_version_t api_version)
{
    const kafka_api_info_t *api_info;
    api_info = kafka_get_api_info(api_key);
    return api_info != NULL && !(api_info->flexible_since == -1 || api_version < api_info->flexible_since);
}

static gboolean
kafka_is_api_version_supported(const kafka_api_info_t *api_info, kafka_api_version_t api_version)
{
    DISSECTOR_ASSERT(api_info);

    return !(api_info->min_version == -1 ||
             api_version < api_info->min_version ||
             api_version > api_info->max_version);
}

static void
kafka_check_supported_api_key(packet_info *pinfo, proto_item *ti, kafka_proto_data_t *proto_data)
{
    if (kafka_get_api_info(proto_data->api_key) == NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Unknown API key]");
        expert_add_info_format(pinfo, ti, &ei_kafka_unknown_api_key,
                               "%s API key", kafka_api_key_to_str(proto_data->api_key));
    }
}

static void
kafka_check_supported_api_version(packet_info *pinfo, proto_item *ti, kafka_proto_data_t *proto_data)
{
    const kafka_api_info_t *api_info;

    api_info = kafka_get_api_info(proto_data->api_key);
    if (api_info != NULL && !kafka_is_api_version_supported(api_info, proto_data->api_version)) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Unsupported API version]");
        if (api_info->min_version == -1) {
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version.",
                                   kafka_api_key_to_str(proto_data->api_key));
        }
        else if (api_info->min_version == api_info->max_version) {
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d.",
                                   kafka_api_key_to_str(proto_data->api_key), api_info->min_version);
        } else {
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d-%d.",
                                   kafka_api_key_to_str(proto_data->api_key),
                                   api_info->min_version, api_info->max_version);
        }
    }
}

static int
dissect_kafka_timestamp_delta(tvbuff_t *tvb, kafka_packet_info_t *kinfo _U_, proto_tree *tree, int hf_item, int offset, guint64 base_timestamp)
{
    nstime_t   nstime;
    guint64    milliseconds;
    guint64    val;
    guint      len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &val, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");

    milliseconds = base_timestamp + val;
    nstime.secs  = (time_t) (milliseconds / 1000);
    nstime.nsecs = (int) ((milliseconds % 1000) * 1000000);

    proto_tree_add_time(tree, hf_item, tvb, offset, len, &nstime);

    return offset + len;
}

static int
dissect_kafka_offset_delta(tvbuff_t *tvb, kafka_packet_info_t *kinfo _U_, proto_tree *tree, int hf_item, int offset, guint64 base_offset)
{
    gint64     val;
    guint      len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &val, ENC_VARINT_PROTOBUF);
    THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");

    proto_tree_add_int64(tree, hf_item, tvb, offset, len, base_offset + val);

    return offset + len;
}

/*
 * Function: dissect_kafka_string_new
 * ---------------------------------------------------
 * Decodes UTF-8 string using the new length encoding. This format is used
 * in the v2 message encoding, where the string length is encoded using
 * ProtoBuf's ZigZag integer format (inspired by Avro). The main advantage
 * of ZigZag is very compact representation for small numbers.
 *
 * tvb: actual data buffer
 * pinfo: packet information (unused)
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: offset in the buffer where the string length is to be found
 * p_display_string: pointer to a variable to store a pointer to the string value
 *
 * returns: offset of the next field in the message. If supplied, p_display_string
 * is guaranteed to be set to a valid value.
 */
static int
dissect_kafka_string_new(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int hf_item, int offset, char **p_display_string)
{
    gint64 val;
    guint len;
    proto_item *pi;

    if (p_display_string != NULL)
        *p_display_string = "<INVALID>";
    len = tvb_get_varint(tvb, offset, 5, &val, ENC_VARINT_ZIGZAG);

    if (len == 0) {
        pi = proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(kinfo->pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (val > 0) {
        // there is payload available, possibly with 0 octets
        if (p_display_string != NULL)
            proto_tree_add_item_ret_display_string(tree, hf_item, tvb, offset+len, (gint)val, ENC_UTF_8, wmem_packet_scope(), p_display_string);
        else
            proto_tree_add_item(tree, hf_item, tvb, offset+len, (gint)val, ENC_UTF_8);
    } else if (val == 0) {
        // there is empty payload (0 octets)
        proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<EMPTY>");
        if (p_display_string != NULL)
            *p_display_string = "<EMPTY>";
    } else if (val == -1) {
        // there is no payload (null)
        proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<NULL>");
        val = 0;
    } else {
        pi = proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(kinfo->pinfo, pi, &ei_kafka_bad_string_length);
        val = 0;
    }

    return offset+len+(gint)val;
}

/*
 * Function: dissect_kafka_bytes_new
 * ---------------------------------------------------
 * Decodes byte buffer using the new length encoding. This format is used
 * in the v2 message encoding, where the buffer length is encoded using
 * ProtoBuf's ZigZag integer format (inspired by Avro). The main advantage
 * of ZigZag is very compact representation for small numbers.
 *
 * tvb: actual data buffer
 * pinfo: packet information (unused)
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: offset in the buffer where the string length is to be found
 * p_bytes_offset: pointer to a variable to store the actual buffer begin
 * p_bytes_length: pointer to a variable to store the actual buffer length
 * p_invalid: pointer to a variable to store whether the length is valid
 *
 * returns: pointer to the next field in the message
 */
static int
dissect_kafka_bytes_new(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int hf_item, int offset, int *p_bytes_offset, int *p_bytes_length, gboolean *p_invalid)
{
    gint64     val;
    guint      len;
    proto_item *pi;

    *p_invalid = FALSE;

    len = tvb_get_varint(tvb, offset, 5, &val, ENC_VARINT_ZIGZAG);

    if (len == 0) {
        pi = proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(kinfo->pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (val > 0) {
        // there is payload available, possibly with 0 octets
        proto_tree_add_item(tree, hf_item, tvb, offset+len, (gint)val, ENC_NA);
    } else if (val == 0) {
        // there is empty payload (0 octets)
        proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<EMPTY>");
    } else if (val == -1) {
        // there is no payload (null)
        proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<NULL>");
        val = 0;
    } else {
        pi = proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(kinfo->pinfo, pi, &ei_kafka_bad_bytes_length);
        val = 0;
        *p_invalid = TRUE;
    }

    if (p_bytes_offset != NULL) {
        *p_bytes_offset = offset+len;
    }
    if (p_bytes_length != NULL) {
        *p_bytes_length = (gint)val;
    }
    return offset+len+(gint)val;
}

/* Calculate and show the reduction in transmitted size due to compression */
static void
show_compression_reduction(tvbuff_t *tvb, proto_tree *tree, guint compressed_size, guint uncompressed_size)
{
    proto_item *ti;
    /* Not really expecting a message to compress down to nothing, but defend against dividing by 0 anyway */
    if (uncompressed_size != 0) {
        ti = proto_tree_add_float(tree, hf_kafka_message_compression_reduction, tvb, 0, 0,
                                  (float)compressed_size / (float)uncompressed_size);
        proto_item_set_generated(ti);
    }
}

static int
dissect_kafka_record_headers_header
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, gboolean *p_invalid)
{
    proto_item *header_ti;
    proto_tree *subtree;
    char *key_display_string;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record_headers_header, &header_ti, "Header");

    offset = dissect_kafka_string_new(tvb, kinfo, subtree, hf_kafka_record_header_key, offset, &key_display_string);
    offset = dissect_kafka_bytes_new(tvb, kinfo, subtree, hf_kafka_record_header_value, offset, NULL, NULL, p_invalid);

    proto_item_append_text(header_ti, " (Key: %s)", key_display_string);

    proto_item_set_end(header_ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_record_headers
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    proto_item *record_headers_ti;
    proto_tree *subtree;
    gint64     count;
    guint      len;
    int        i;
    gboolean   invalid = FALSE;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record_headers, &record_headers_ti, "Headers");

    len = tvb_get_varint(tvb, offset, 5, &count, ENC_VARINT_ZIGZAG);
    if (len == 0) {
        expert_add_info(kinfo->pinfo, record_headers_ti, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (count < -1) { // -1 means null array
        expert_add_info(kinfo->pinfo, record_headers_ti, &ei_kafka_bad_array_length);
    }

    offset += len;
    for (i = 0; i < count && !invalid; i++) {
        offset = dissect_kafka_record_headers_header(tvb, kinfo, subtree, offset, &invalid);
    }

    proto_item_set_end(record_headers_ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_record(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int start_offset, guint64 base_offset, guint64 first_timestamp)
{
    proto_item *record_ti;
    proto_tree *subtree;

    gint64     size;
    guint      len;

    int offset, end_offset;
    gboolean   invalid;

    offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record, &record_ti, "Record");

    len = tvb_get_varint(tvb, offset, 5, &size, ENC_VARINT_ZIGZAG);
    if (len == 0) {
        expert_add_info(kinfo->pinfo, record_ti, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (size < 6) {
        expert_add_info(kinfo->pinfo, record_ti, &ei_kafka_bad_record_length);
        return offset + len;
    }

    end_offset = offset + len + (gint)size;
    offset += len;

    offset = dissect_kafka_int8(tvb, kinfo, subtree, offset, hf_kafka_record_attributes);
    offset = dissect_kafka_timestamp_delta(tvb, kinfo, subtree, hf_kafka_message_timestamp, offset, first_timestamp);
    offset = dissect_kafka_offset_delta(tvb, kinfo, subtree, hf_kafka_offset, offset, base_offset);

    offset = dissect_kafka_bytes_new(tvb, kinfo, subtree, hf_kafka_message_key, offset, NULL, NULL, &invalid);
    if (invalid)
        return end_offset;
    offset = dissect_kafka_bytes_new(tvb, kinfo, subtree, hf_kafka_message_value, offset, NULL, NULL, &invalid);
    if (invalid)
        return end_offset;

    offset = dissect_kafka_record_headers(tvb, kinfo, subtree, offset);

    if (offset != end_offset) {
        expert_add_info(kinfo->pinfo, record_ti, &ei_kafka_bad_record_length);
    }

    proto_item_set_end(record_ti, tvb, end_offset);

    return end_offset;
}

static gboolean
decompress_none(tvbuff_t *tvb, kafka_packet_info_t *kinfo _U_, int offset, guint32 length _U_, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    *decompressed_tvb = tvb;
    *decompressed_offset = offset;
    return TRUE;
}

static gboolean
decompress_gzip(tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset, guint32 length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    *decompressed_tvb = tvb_child_uncompress(tvb, tvb, offset, length);
    *decompressed_offset = 0;
    if (*decompressed_tvb) {
        return TRUE;
    } else {
        col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [gzip decompression failed] ");
        return FALSE;
    }
}

#define MAX_LOOP_ITERATIONS 100

#ifdef HAVE_LZ4FRAME_H
static gboolean
decompress_lz4(tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset, guint32 length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    LZ4F_decompressionContext_t lz4_ctxt = NULL;
    LZ4F_frameInfo_t lz4_info;
    LZ4F_errorCode_t rc = 0;
    size_t src_offset = 0, src_size = 0, dst_size = 0;
    guchar *decompressed_buffer = NULL;
    tvbuff_t *composite_tvb = NULL;

    gboolean ret = FALSE;

    /* Prepare compressed data buffer */
    guint8 *data = (guint8*)tvb_memdup(kinfo->pinfo->pool, tvb, offset, length);
    /* Override header checksum to workaround buggy Kafka implementations */
    if (length > 7) {
        guint32 hdr_end = 6;
        if (data[4] & 0x08) {
            hdr_end += 8;
        }
        if (hdr_end < length) {
            data[hdr_end] = (XXH32(&data[4], hdr_end - 4, 0) >> 8) & 0xff;
        }
    }

    /* Allocate output buffer */
    rc = LZ4F_createDecompressionContext(&lz4_ctxt, LZ4F_VERSION);
    if (LZ4F_isError(rc)) {
        goto end;
    }

    src_offset = length;
    rc = LZ4F_getFrameInfo(lz4_ctxt, &lz4_info, data, &src_offset);
    if (LZ4F_isError(rc)) {
        goto end;
    }

    switch (lz4_info.blockSizeID) {
        case LZ4F_max64KB:
            dst_size = 1 << 16;
            break;
        case LZ4F_max256KB:
            dst_size = 1 << 18;
            break;
        case LZ4F_max1MB:
            dst_size = 1 << 20;
            break;
        case LZ4F_max4MB:
            dst_size = 1 << 22;
            break;
        default:
            goto end;
    }

    if (lz4_info.contentSize && lz4_info.contentSize < dst_size) {
        dst_size = (size_t)lz4_info.contentSize;
    }

    size_t out_size;
    int count = 0;

    do {
        src_size = length - src_offset; // set the number of available octets
        if (src_size == 0) {
            goto end;
        }

        decompressed_buffer = wmem_alloc(kinfo->pinfo->pool, dst_size);
        out_size = dst_size;
        rc = LZ4F_decompress(lz4_ctxt, decompressed_buffer, &out_size,
                              &data[src_offset], &src_size, NULL);
        if (LZ4F_isError(rc)) {
            goto end;
        }
        if (out_size != dst_size) {
            decompressed_buffer = (guint8 *)wmem_realloc(kinfo->pinfo->pool, decompressed_buffer, out_size);
        }
        if (out_size == 0) {
            goto end;
        }
        if (!composite_tvb) {
            composite_tvb = tvb_new_composite();
        }
        tvb_composite_append(composite_tvb,
                             tvb_new_child_real_data(tvb, (guint8*)decompressed_buffer, (guint)out_size, (gint)out_size));
        src_offset += src_size; // bump up the offset for the next iteration
        DISSECTOR_ASSERT_HINT(count < MAX_LOOP_ITERATIONS, "MAX_LOOP_ITERATIONS exceeded");
    } while (rc > 0 && count++ < MAX_LOOP_ITERATIONS);

    ret = TRUE;
end:
    if (composite_tvb) {
        tvb_composite_finalize(composite_tvb);
    }
    LZ4F_freeDecompressionContext(lz4_ctxt);
    if (ret == 1) {
        *decompressed_tvb = composite_tvb;
        *decompressed_offset = 0;
    }
    else {
        col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [lz4 decompression failed]");
    }
    return ret;
}
#else
static gboolean
decompress_lz4(tvbuff_t *tvb _U_, kafka_packet_info_t *kinfo, int offset _U_, guint32 length _U_, tvbuff_t **decompressed_tvb _U_, int *decompressed_offset _U_)
{
    col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [lz4 decompression unsupported]");
    return FALSE;
}
#endif /* HAVE_LZ4FRAME_H */

#ifdef HAVE_SNAPPY
static gboolean
decompress_snappy(tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset, guint32 length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    guint8 *data = (guint8*)tvb_memdup(kinfo->pinfo->pool, tvb, offset, length);
    size_t uncompressed_size, out_size;
    snappy_status rc = SNAPPY_OK;
    tvbuff_t *composite_tvb = NULL;
    gboolean ret = FALSE;

    if (tvb_memeql(tvb, offset, kafka_xerial_header, sizeof(kafka_xerial_header)) == 0) {

        /* xerial framing format */
        guint32 chunk_size, pos = 16;
        int count = 0;

        while (pos < length && count < MAX_LOOP_ITERATIONS) {
            if (pos > length-4) {
                // XXX - this is presumably an error, as the chunk size
                // doesn't fully fit in the data, so an error should be
                // reported.
                goto end;
            }
            chunk_size = tvb_get_ntohl(tvb, offset+pos);
            pos += 4;
            if (chunk_size > length) {
                // XXX - this is presumably an error, as the chunk to be
                // decompressed doesn't fully fit in the data, so an error
                // should be reported.
                goto end;
            }
            if (pos > length-chunk_size) {
                // XXX - this is presumably an error, as the chunk to be
                // decompressed doesn't fully fit in the data, so an error
                // should be reported.
                goto end;
            }
            rc = snappy_uncompressed_length(&data[pos], chunk_size, &uncompressed_size);
            if (rc != SNAPPY_OK) {
                goto end;
            }
            guint8 *decompressed_buffer = (guint8*)wmem_alloc(kinfo->pinfo->pool, uncompressed_size);
            out_size = uncompressed_size;
            rc = snappy_uncompress(&data[pos], chunk_size, decompressed_buffer, &out_size);
            if (rc != SNAPPY_OK) {
                goto end;
            }
            if (out_size != uncompressed_size) {
                decompressed_buffer = (guint8 *)wmem_realloc(kinfo->pinfo->pool, decompressed_buffer, out_size);
            }

            if (!composite_tvb) {
                composite_tvb = tvb_new_composite();
            }
            tvb_composite_append(composite_tvb,
                      tvb_new_child_real_data(tvb, decompressed_buffer, (guint)out_size, (gint)out_size));
            pos += chunk_size;
            count++;
            DISSECTOR_ASSERT_HINT(count < MAX_LOOP_ITERATIONS, "MAX_LOOP_ITERATIONS exceeded");
        }

    } else {

        /* unframed format */
        rc = snappy_uncompressed_length(data, length, &uncompressed_size);
        if (rc != SNAPPY_OK) {
            goto end;
        }

        guint8 *decompressed_buffer = (guint8*)wmem_alloc(kinfo->pinfo->pool, uncompressed_size);

        out_size = uncompressed_size;
        rc = snappy_uncompress(data, length, decompressed_buffer, &out_size);
        if (rc != SNAPPY_OK) {
            goto end;
        }
        if (out_size != uncompressed_size) {
            decompressed_buffer = (guint8 *)wmem_realloc(kinfo->pinfo->pool, decompressed_buffer, out_size);
        }

        *decompressed_tvb = tvb_new_child_real_data(tvb, decompressed_buffer, (guint)out_size, (gint)out_size);
        *decompressed_offset = 0;

    }
    ret = TRUE;
end:
    if (composite_tvb) {
        tvb_composite_finalize(composite_tvb);
        if (ret == 1) {
            *decompressed_tvb = composite_tvb;
            *decompressed_offset = 0;
        }
    }
    if (ret == FALSE) {
        col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [snappy decompression failed]");
    }
    return ret;
}
#else
static gboolean
decompress_snappy(tvbuff_t *tvb _U_, kafka_packet_info_t *kinfo, int offset _U_, int length _U_, tvbuff_t **decompressed_tvb _U_, int *decompressed_offset _U_)
{
    col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [snappy decompression unsupported]");
    return FALSE;
}
#endif /* HAVE_SNAPPY */

#ifdef HAVE_ZSTD
static gboolean
decompress_zstd(tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset, guint32 length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    *decompressed_tvb = tvb_child_uncompress_zstd(tvb, tvb, offset, length);
    *decompressed_offset = 0;
    if (*decompressed_tvb) {
        return TRUE;
    } else {
        col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [zstd decompression failed] ");
        return FALSE;
    }
}
#else
static gboolean
decompress_zstd(tvbuff_t *tvb _U_, kafka_packet_info_t *kinfo, int offset _U_, guint32 length _U_, tvbuff_t **decompressed_tvb _U_, int *decompressed_offset _U_)
{
    col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [zstd compression unsupported]");
    return FALSE;
}
#endif /* HAVE_ZSTD */

// Max is currently 2^22 in
// https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/record/KafkaLZ4BlockOutputStream.java
#define MAX_DECOMPRESSION_SIZE (1 << 22)
static gboolean
decompress(tvbuff_t *tvb, kafka_packet_info_t *kinfo, int offset, guint32 length, int codec, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    if (length > MAX_DECOMPRESSION_SIZE) {
        expert_add_info(kinfo->pinfo, NULL, &ei_kafka_bad_decompression_length);
        return FALSE;
    }
    if (length == 0) {
        expert_add_info(kinfo->pinfo, NULL, &ei_kafka_zero_decompression_length);
        return FALSE;
    }
    switch (codec) {
        case KAFKA_MESSAGE_CODEC_SNAPPY:
            return decompress_snappy(tvb, kinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_LZ4:
            return decompress_lz4(tvb, kinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_ZSTD:
            return decompress_zstd(tvb, kinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_GZIP:
            return decompress_gzip(tvb, kinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_NONE:
            return decompress_none(tvb, kinfo, offset, length, decompressed_tvb, decompressed_offset);
        default:
            col_append_str(kinfo->pinfo->cinfo, COL_INFO, " [unsupported compression type]");
            return FALSE;
    }
}

/*
 * Function: dissect_kafka_message_old
 * ---------------------------------------------------
 * Handles decoding of pre-0.11 message format. In the old format
 * only the message payload was the subject of compression
 * and the batches were special kind of message payload.
 *
 * https://kafka.apache.org/0100/documentation/#messageformat
 *
 * tvb: actual data buffer
 * pinfo: packet information
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: pointer to the message
 * end_offset: last possible offset in this batch
 *
 * returns: pointer to the next message/batch
 */
static int
dissect_kafka_message_old
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, int end_offset _U_)
{
    proto_item  *message_ti;
    proto_tree  *subtree;
    tvbuff_t    *decompressed_tvb;
    int         decompressed_offset;
    int         start_offset = offset;
    gint8       magic_byte;
    guint8      codec;
    guint32     message_size;
    guint32     length;

    message_size = tvb_get_guint32(tvb, start_offset + 8, ENC_BIG_ENDIAN);

    subtree = proto_tree_add_subtree(tree, tvb, start_offset, message_size + 12, ett_kafka_message, &message_ti, "Message");

    offset = dissect_kafka_int64(tvb, kinfo, subtree, offset, hf_kafka_offset);

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_message_size);

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_message_crc);

    offset = dissect_kafka_int8_ret(tvb, kinfo, subtree, offset, hf_kafka_message_magic, &magic_byte);

    offset = dissect_kafka_int8_ret(tvb, kinfo, subtree, offset, hf_kafka_message_codec, &codec);
    codec &= KAFKA_MESSAGE_CODEC_MASK;

    offset = dissect_kafka_int8(tvb, kinfo, subtree, offset, hf_kafka_message_timestamp_type);

    if (magic_byte == 1) {
        offset = dissect_kafka_timestamp(tvb, kinfo, subtree, offset, hf_kafka_message_timestamp);
    }

    offset = dissect_kafka_regular_bytes_ret(tvb, kinfo, subtree, offset, hf_kafka_message_key, NULL);

    /*
     * depending on the compression codec, the payload is the actual message payload (codes=none)
     * or compressed set of messages (otherwise). In the new format (since Kafka 1.0) there
     * is no such duality.
     */
    if (codec == 0) {
        offset = dissect_kafka_regular_bytes_ret(tvb, kinfo, subtree, offset, hf_kafka_message_value, NULL);
    } else {
        length = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (decompress(tvb, kinfo, offset, length, codec, &decompressed_tvb, &decompressed_offset)==1) {
            add_new_data_source(kinfo->pinfo, decompressed_tvb, "Decompressed content");
            show_compression_reduction(tvb, subtree, length, tvb_captured_length(decompressed_tvb));
            dissect_kafka_message_set(decompressed_tvb, kinfo, subtree, decompressed_offset,
                tvb_reported_length_remaining(decompressed_tvb, decompressed_offset), codec);
            offset += length;
        } else {
            proto_item_append_text(subtree, " [Cannot decompress records]");
        }
    }

    proto_item_set_end(message_ti, tvb, offset);

    return offset;
}

/*
 * Function: dissect_kafka_message_new
 * ---------------------------------------------------
 * Handles decoding of the new message format. In the new format
 * there is no difference between compressed and plain batch.
 *
 * https://kafka.apache.org/documentation/#messageformat
 *
 * tvb: actual data buffer
 * pinfo: packet information
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: pointer to the message
 * end_offset: last possible offset in this batch
 *
 * returns: pointer to the next message/batch
 */
static int
dissect_kafka_message_new
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, int end_offset _U_)
{
    proto_item *batch_ti;
    proto_tree *subtree;
    int         start_offset = offset;
    gint8       magic_byte;
    guint16     codec;
    guint32     message_size;
    guint32     count, i, length;
    guint64     base_offset, first_timestamp;

    tvbuff_t    *decompressed_tvb;
    int         decompressed_offset;

    message_size = tvb_get_guint32(tvb, offset + 8, ENC_BIG_ENDIAN);

    subtree = proto_tree_add_subtree(tree, tvb, offset, message_size + 12, ett_kafka_batch, &batch_ti, "Record Batch");

    offset = dissect_kafka_int64_ret(tvb, kinfo, subtree, offset, hf_kafka_offset, &base_offset);

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_message_size);

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_leader_epoch);

    offset = dissect_kafka_int8_ret(tvb, kinfo, subtree, offset, hf_kafka_message_magic, &magic_byte);

    if (magic_byte != 2) {
        proto_item_append_text(subtree, "[Unknown message magic]");
        expert_add_info_format(kinfo->pinfo, batch_ti, &ei_kafka_unknown_message_magic,
                               "message magic: %d", magic_byte);
        return start_offset + 8 /*base offset*/ + 4 /*message size*/ + message_size;
    }

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_batch_crc);

    dissect_kafka_int16_ret(tvb, kinfo, subtree, offset, hf_kafka_batch_codec, &codec);
    codec &= KAFKA_MESSAGE_CODEC_MASK;
    dissect_kafka_int16(tvb, kinfo, subtree, offset, hf_kafka_batch_timestamp_type);
    dissect_kafka_int16(tvb, kinfo, subtree, offset, hf_kafka_batch_transactional);
    dissect_kafka_int16(tvb, kinfo, subtree, offset, hf_kafka_batch_control_batch);
    // next octet is reserved
    offset += 2;

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_batch_last_offset_delta);

    offset = dissect_kafka_timestamp_ret(tvb, kinfo, subtree, offset, hf_kafka_batch_first_timestamp, &first_timestamp);
    offset = dissect_kafka_timestamp(tvb, kinfo, subtree, offset, hf_kafka_batch_last_timestamp);

    offset = dissect_kafka_int64(tvb, kinfo, subtree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, subtree, offset, hf_kafka_producer_epoch);

    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_batch_base_sequence);

    offset = dissect_kafka_int32_ret(tvb, kinfo, subtree, offset, hf_kafka_batch_size, &count);

    length = start_offset + 8 /*base offset*/ + 4 /*message size*/ + message_size - offset;

    if (decompress(tvb, kinfo, offset, length, codec, &decompressed_tvb, &decompressed_offset)==1) {
        if (codec != 0) {
            add_new_data_source(kinfo->pinfo, decompressed_tvb, "Decompressed Records");
            show_compression_reduction(tvb, subtree, length, tvb_captured_length(decompressed_tvb));
        }
        for (i=0;i<count;i++) {
            decompressed_offset = dissect_kafka_record(decompressed_tvb, kinfo, subtree, decompressed_offset, base_offset, first_timestamp);
        }
    } else {
        proto_item_append_text(subtree, " [Cannot decompress records]");
    }

    return start_offset + 8 /*base offset*/ + 4 /*message size*/ + message_size;
}

static int
dissect_kafka_message
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, int end_offset)
{
    gint8       magic_byte;
    guint32     message_size;

    if (offset + 12 > end_offset) {
        // in this case we deal with truncated message, where the size part may be also truncated
        // actually we may add truncated info
        proto_tree_add_item(tree, hf_kafka_truncated_content, tvb, offset, end_offset-offset, ENC_NA);
        return end_offset;
    }
    message_size = tvb_get_guint32(tvb, offset + 8, ENC_BIG_ENDIAN);
    if (offset + 12 + message_size > (guint32)end_offset) {
        // in this case we deal with truncated message, where the truncation point falls somewhere
        // in the message body
        proto_tree_add_item(tree, hf_kafka_truncated_content, tvb, offset, end_offset-offset, ENC_NA);
        return end_offset;
    }

    magic_byte = tvb_get_guint8(tvb, offset + 16);
    if (magic_byte < 2) {
        return dissect_kafka_message_old(tvb, kinfo, tree, offset, end_offset);
    } else {
        return dissect_kafka_message_new(tvb, kinfo, tree, offset, end_offset);
    }
}

static int
dissect_kafka_message_set(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, gint offset, guint len, guint8 codec)
{
    proto_item *ti;
    proto_tree *subtree;
    gint        end_offset = offset + len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_message_set, &ti, "Message Set");
    /* If set came from a compressed message, make it obvious in tree root */
    if (codec != KAFKA_MESSAGE_CODEC_NONE) {
        proto_item_append_text(subtree, " [from compressed %s message]", val_to_str_const(codec, kafka_message_codecs, "Unknown"));
    }

    while (offset < end_offset) {
        offset = dissect_kafka_message(tvb, kinfo, subtree, offset, end_offset);
    }

    if (offset != end_offset) {
        expert_add_info(kinfo->pinfo, ti, &ei_kafka_bad_message_set_length);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_records(proto_tree *tree, tvbuff_t *tvb, kafka_packet_info_t *kinfo, gint offset, void  *ret _U_)
{
    guint message_set_size;

    if (kinfo->flexible_api)
    {
        guint64    val;
        guint64    len;
        len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &val, ENC_VARINT_PROTOBUF);
        THROW_MESSAGE_ON(len == 0, ReportedBoundsError, "Invalid varint content");
        message_set_size = (guint)val - 1;
        offset += len;
    }
    else
    {
        message_set_size = tvb_get_ntohl(tvb, offset);
        offset += 4;
    }

    if (message_set_size <= 0) {
        return offset;
    }

    offset = dissect_kafka_message_set(tvb, kinfo, tree, offset, message_set_size, KAFKA_MESSAGE_CODEC_NONE);

    return offset;

}


/* OFFSET FETCH REQUEST/RESPONSE */

static int
dissect_kafka_offset_time(tvbuff_t *tvb, kafka_packet_info_t *kinfo _U_, proto_tree *tree, int offset)
{
    proto_item *ti;
    gint64 message_offset_time;

    message_offset_time = tvb_get_ntoh64(tvb, offset);

    ti = proto_tree_add_item(tree, hf_kafka_offset_time, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    // The query for offset at given time takes the time in milliseconds since epoch.
    // It has two additional special values:
    // * -1 - the latest offset (to consume new messages only)
    // * -2 - the oldest offset (to consume all available messages)
    if (message_offset_time == -1) {
        proto_item_append_text(ti, " (latest)");
    } else if (message_offset_time == -2) {
        proto_item_append_text(ti, " (earliest)");
    }

    return offset;
}

static int
dissect_kafka_offset_fetch_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_offset_fetch_request_group
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    __KAFKA_SINCE_VERSION__(9)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(9)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_member_epoch);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_fetch_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_offset_fetch_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    __KAFKA_UNTIL_VERSION__(7)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    __KAFKA_UNTIL_VERSION__(7)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_fetch_request_topic);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_group, "Group",
                                        &dissect_kafka_offset_fetch_request_group);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_require_stable_offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_error_ret
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, kafka_error_t *ret)
{
    kafka_error_t error;

    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_error, &error);

    if (error != 0) {

        proto_item_append_text(proto_tree_get_parent(tree), " [%s]", kafka_error_to_str(error));
        expert_add_info_format(kinfo->pinfo, proto_tree_get_parent(tree), &ei_kafka_error_response, "%s",
                               kafka_error_to_str(error));
    }

    if (ret) {
        *ret = error;
    }

    return offset;
}

static int
dissect_kafka_error
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_error_ret(tvb, kinfo, tree, offset, NULL);
}

static int
dissect_kafka_offset_fetch_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_metadata);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_offset_fetch_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_group
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_fetch_response_topic);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_fetch_response_partition_node_endpoint
        (tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_response_tagged_fields
        (tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                            -1, NULL, ett_kafka_brokers, "Node Endpoints",
                                            &dissect_kafka_fetch_response_partition_node_endpoint);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_offset_fetch_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    __KAFKA_UNTIL_VERSION__(7)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_fetch_response_topic);
    __KAFKA_SINCE_VERSION__(3)
    __KAFKA_UNTIL_VERSION__(7)
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_group, "Group",
                                        &dissect_kafka_offset_fetch_response_group);

    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, &dissect_kafka_fetch_response_tagged_fields);

    return offset;
}

/* METADATA REQUEST/RESPONSE */

static int
dissect_kafka_metadata_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(10)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_metadata_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_metadata_request_topic);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_allow_auto_topic_creation);
    __KAFKA_SINCE_VERSION__(8)
    __KAFKA_UNTIL_VERSION__(10)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_include_cluster_authorized_ops);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_include_topic_authorized_ops);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_metadata_broker
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    guint32     node_id;
    kafka_buffer_ref host;
    guint32     broker_port;

    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid, &node_id);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_broker_host, &host);
    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_broker_port, &broker_port);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    proto_item_append_text(proto_tree_get_parent(tree), " (node %u: %s:%u)", node_id, __KAFKA_STRING__(host), broker_port);

    return offset;
}

static int
dissect_kafka_metadata_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_partition_t partition;

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_partition_id, &partition);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Caught-Up Replicas",
                                        &dissect_kafka_int32, hf_kafka_isr);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Offline Replicas",
                                        &dissect_kafka_int32, hf_kafka_offline);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    proto_item_append_text(proto_tree_get_parent(tree), " (ID=%u)", partition);

    return offset;
}

static int
dissect_kafka_metadata_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref name;

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &name);
    __KAFKA_SINCE_VERSION__(10)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_is_internal);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_metadata_partition);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_topic_authorized_ops);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(name));

    return offset;
}

static int
dissect_kafka_metadata_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_brokers, "Broker Metadata",
                                        ett_kafka_broker, "Broker",
                                        &dissect_kafka_metadata_broker);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_topics, "Topic Metadata",
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_metadata_topic);
    __KAFKA_SINCE_VERSION__(8)
    __KAFKA_UNTIL_VERSION__(10)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_cluster_authorized_ops);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* LEADER_AND_ISR REQUEST/RESPONSE */

static int
dissect_kafka_leader_and_isr_request_partition_state
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_UNTIL_VERSION__(1)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_epoch);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_isrs, "ISRs",
                                        &dissect_kafka_int32, hf_kafka_isr);
    /* PartitionEpoch corresponds to ZK version */
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_zk_version);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Current Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Adding Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Removing Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_is_new_replica);
    __KAFKA_SINCE_VERSION__(6)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_lead_recovery_state);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_leader_and_isr_request_topic_state
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_leader_and_isr_request_partition_state);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_leader_and_isr_request_live_leader
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_leader_and_isr_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_id);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_is_kraft_controller);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_epoch);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_isr_request_type);
    __KAFKA_UNTIL_VERSION__(1)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_leader_and_isr_request_partition_state);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_leader_and_isr_request_topic_state);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_broker, "Live Leader",
                                        &dissect_kafka_leader_and_isr_request_live_leader);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_leader_and_isr_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    __KAFKA_UNTIL_VERSION__(4)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_leader_and_isr_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_leader_and_isr_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_leader_and_isr_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_UNTIL_VERSION__(4)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_leader_and_isr_response_partition);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_leader_and_isr_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* STOP_REPLICA REQUEST/RESPONSE */

static int
dissect_kafka_stop_replica_request_partition_state
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_delete_partitions);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_stop_replica_request_topic_state
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_stop_replica_request_partition_state);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_stop_replica_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_stop_replica_request_ungrouped_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_stop_replica_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_id);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_is_kraft_controller);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_epoch);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    __KAFKA_UNTIL_VERSION__(2)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_delete_partitions);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_stop_replica_request_ungrouped_partition);
    __KAFKA_SINCE_VERSION__(1)
    __KAFKA_UNTIL_VERSION__(2)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_stop_replica_request_topic);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_stop_replica_request_topic_state);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_stop_replica_response_partition_error
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_stop_replica_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition Error",
                                        &dissect_kafka_stop_replica_response_partition_error);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* FETCH REQUEST/RESPONSE */

static int
dissect_kafka_fetch_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_partition_t fetch_partition;
    kafka_offset_t    fetch_offset;

    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_partition_id, &fetch_partition);
    __KAFKA_SINCE_VERSION__(9)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_int64_ret(tvb, kinfo, tree, offset, hf_kafka_offset, &fetch_offset);
    __KAFKA_SINCE_VERSION__(12)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_last_fetched_epoch);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_log_start_offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_max_bytes);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    proto_item_append_text(proto_tree_get_parent(tree), " (ID=%u, Offset=%" PRIi64 ")", fetch_partition, fetch_offset);

    return offset;
}

static int
dissect_kafka_fetch_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    int topic_id_offset = offset;
    __KAFKA_UNTIL_VERSION__(12)
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    __KAFKA_SINCE_VERSION__(13)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_fetch_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    __KAFKA_UNTIL_VERSION__(12)
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    __KAFKA_SINCE_VERSION__(13)
    proto_item_append_text(proto_tree_get_parent(tree), " (ID=%s)", __KAFKA_UUID__(topic_id_offset));
    return offset;
}

static int
dissect_kafka_fetch_request_forgotten_topics_data
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(7)
    __KAFKA_UNTIL_VERSION__(12)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    __KAFKA_SINCE_VERSION__(13)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_forgotten_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_fetch_request_replica_state
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(15)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_replica);
    __KAFKA_SINCE_VERSION__(15)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_replica_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_request_tagged_fields
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset,
                                          guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
        return 1;
    } if (tag == 1) {
        offset = dissect_kafka_object(tvb, kinfo, tree, offset,
                                      ett_kafka_replica_state, "Replica State",
                                      dissect_kafka_fetch_request_replica_state);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_fetch_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    __KAFKA_UNTIL_VERSION__(14)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_replica);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_max_wait_time);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_min_bytes);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_max_bytes);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_isolation_level);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_fetch_session_id);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_fetch_session_epoch);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_fetch_request_topic);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Forgotten Topic",
                                        &dissect_kafka_fetch_request_forgotten_topics_data);
    __KAFKA_SINCE_VERSION__(11)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, &dissect_kafka_fetch_request_tagged_fields);

    return offset;
}

static int
dissect_kafka_aborted_transaction
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_first_offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_fetch_response_partition_tagged_fields
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    proto_item *ti;
    proto_tree *subtree;

    if (tag == 0) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_diverging_epoch, &ti, "Diverging Epoch");
        offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
        offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_end_offset);
        offset = dissect_kafka_tagged_fields(tvb, kinfo, subtree, offset, NULL);
        proto_item_set_end(ti, tvb, offset);
        return 1;
    }
    else if (tag == 1)
    {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_current_leader, &ti, "Current Leader");
        offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
        offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
        offset = dissect_kafka_tagged_fields(tvb, kinfo, subtree, offset, NULL);
        proto_item_set_end(ti, tvb, offset);
        return 1;
    }
    else if (tag == 2)
    {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_snapshot_id, &ti, "Snapshot ID");
        offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_end_offset);
        offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
        offset = dissect_kafka_tagged_fields(tvb, kinfo, subtree, offset, NULL);
        proto_item_set_end(ti, tvb, offset);
        return 1;
    }
    else
    {
        return 0;
    }
}

static int
dissect_kafka_fetch_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    kafka_partition_t partition_id;
    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_partition_id, &partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_high_watermark);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_last_stable_offset);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_log_start_offset);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_aborted_transactions, "Aborted Transactions",
                                        ett_kafka_aborted_transaction, "Transaction",
                                        &dissect_kafka_aborted_transaction);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_preferred_read_replica);
    offset = dissect_kafka_records(tree, tvb, kinfo, offset, NULL);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, &dissect_kafka_fetch_response_partition_tagged_fields);

    proto_item_append_text(proto_tree_get_parent(tree), " (ID=%u)", partition_id);

    return offset;
}

static int
dissect_kafka_fetch_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    int topic_id_offset = offset;
    __KAFKA_UNTIL_VERSION__(12)
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    __KAFKA_SINCE_VERSION__(13)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_partition, "Partition",
                                        &dissect_kafka_fetch_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    __KAFKA_UNTIL_VERSION__(12)
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    __KAFKA_SINCE_VERSION__(13)
    proto_item_append_text(proto_tree_get_parent(tree), " (ID=%s)", __KAFKA_UUID__(topic_id_offset));
    return offset;
}

static int
dissect_kafka_fetch_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_fetch_session_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        ett_kafka_topic, "Topic",
                                        &dissect_kafka_fetch_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* PRODUCE REQUEST/RESPONSE */

static int
dissect_kafka_produce_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_records(tree, tvb, kinfo, offset, NULL);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_produce_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_produce_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_produce_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_required_acks);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_produce_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_produce_response_partition_current_leader
        (tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    // https://github.com/apache/kafka/blob/3.7.0/clients/src/main/resources/common/message/ProduceResponse.json#L65-L69
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
//    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_current_leader_id);
//    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_current_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_produce_response_partition_tagged_fields
        (tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_produce_response_partition_current_leader(tvb, kinfo, tree, offset);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_produce_response_partition_record_error
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_batch_index);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_batch_index_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_produce_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_offset_time(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_log_start_offset);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_record, "Record Error",
                                        &dissect_kafka_produce_response_partition_record_error);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, &dissect_kafka_produce_response_partition_tagged_fields);
    return offset;
}

static int
dissect_kafka_produce_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_produce_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_produce_response_partition_node_endpoint
        (tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    // https://github.com/apache/kafka/blob/3.7.0/clients/src/main/resources/common/message/ProduceResponse.json#L74-L84
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_produce_response_tagged_fields
        (tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                            -1, NULL, ett_kafka_brokers, "Node Endpoints",
                                            &dissect_kafka_produce_response_partition_node_endpoint);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_produce_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_produce_response_topic);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, &dissect_kafka_produce_response_tagged_fields);
    return offset;
}

/* OFFSETS REQUEST/RESPONSE */

static int
dissect_kafka_offsets_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_offset_time(tvb, kinfo, tree, offset);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_max_offsets);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offsets_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offsets_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offsets_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_replica);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_isolation_level);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offsets_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offsets_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int64, hf_kafka_offset);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_offset_time(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offsets_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offsets_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offsets_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offsets_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* API_VERSIONS REQUEST/RESPONSE */

static int
dissect_kafka_api_versions_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_client_software_name);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_client_software_version);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_api_versions_response_api_version
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_api_key_t api_key;
    kafka_api_version_t min_version, max_version;
    const kafka_api_info_t *api_info;

    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_api_versions_api_key, &api_key);
    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_api_versions_min_version, &min_version);
    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_api_versions_max_version, &max_version);

    if (max_version != min_version) {
        /* Range of versions supported. */
        proto_item_append_text(proto_tree_get_parent(tree), " %s (v%d-%d)",
                               kafka_api_key_to_str(api_key),
                               min_version, max_version);
    }
    else {
        /* Only one version. */
        proto_item_append_text(proto_tree_get_parent(tree), " %s (v%d)",
                               kafka_api_key_to_str(api_key),
                               min_version);
    }

    api_info = kafka_get_api_info(api_key);
    if (api_info == NULL) {
        proto_item_append_text(proto_tree_get_parent(tree), " [Unknown API key]");
        expert_add_info_format(kinfo->pinfo, proto_tree_get_parent(tree), &ei_kafka_unknown_api_key,
                               "%s API key", kafka_api_key_to_str(api_key));
    }
    else if (!kafka_is_api_version_supported(api_info, min_version) ||
             !kafka_is_api_version_supported(api_info, max_version)) {
        if (api_info->min_version == -1) {
            proto_item_append_text(proto_tree_get_parent(tree), " [Unsupported API version]");
            expert_add_info_format(kinfo->pinfo, proto_tree_get_parent(tree), &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version.",
                                   kafka_api_key_to_str(api_key));
        }
        else if (api_info->min_version == api_info->max_version) {
            proto_item_append_text(proto_tree_get_parent(tree), " [Unsupported API version. Supports v%d]",
                                   api_info->min_version);
            expert_add_info_format(kinfo->pinfo, proto_tree_get_parent(tree), &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d.",
                                   kafka_api_key_to_str(api_key), api_info->min_version);
        } else {
            proto_item_append_text(proto_tree_get_parent(tree), " [Unsupported API version. Supports v%d-%d]",
                                   api_info->min_version, api_info->max_version);
            expert_add_info_format(kinfo->pinfo, proto_tree_get_parent(tree), &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d-%d.",
                                   kafka_api_key_to_str(api_key),
                                   api_info->min_version, api_info->max_version);
        }
    }
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_api_versions_response_supported_feature
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref name;
    gint16 min_version, max_version;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_feature_name, &name);
    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_feature_min_version, &min_version);
    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_feature_max_version, &max_version);
    if (max_version != min_version) {
        /* Range of versions supported. */
        proto_item_append_text(proto_tree_get_parent(tree), " %s (v%d-%d)", __KAFKA_STRING__(name), min_version, max_version);
    }
    else {
        /* Only one version. */
        proto_item_append_text(proto_tree_get_parent(tree), " %s (v%d)", __KAFKA_STRING__(name), min_version);
    }
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_api_versions_response_finalized_feature
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref name;
    gint16 min_version, max_version;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_feature_name, &name);
    // unlike in api version and supported feature, max comes first
    // https://github.com/apache/kafka/blob/3.1/clients/src/main/resources/common/message/ApiVersionsResponse.json
    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_feature_max_version, &max_version);
    offset = dissect_kafka_int16_ret(tvb, kinfo, tree, offset, hf_kafka_feature_min_version, &min_version);

    if (max_version != min_version) {
        /* Range of versions supported. */
        proto_item_append_text(proto_tree_get_parent(tree), " %s (v%d-%d)", __KAFKA_STRING__(name), min_version, max_version);
    }
    else {
        /* Only one version. */
        proto_item_append_text(proto_tree_get_parent(tree), " %s (v%d)", __KAFKA_STRING__(name), min_version);
    }
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_api_versions_response_tagged_fields
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                            -1, NULL, ett_kafka_feature, "Supported Feature",
                                            &dissect_kafka_api_versions_response_supported_feature);
        return 1;
    } else if (tag == 1) {
        offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_finalized_features_epoch);
        return 1;
    } else if (tag == 2) {
        offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                            -1, NULL, ett_kafka_feature, "Finalized Feature",
                                            &dissect_kafka_api_versions_response_finalized_feature);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_api_versions_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_api_version, "API Version",
                                        &dissect_kafka_api_versions_response_api_version);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, dissect_kafka_api_versions_response_tagged_fields);

    return offset;
}

/* UPDATE_METADATA REQUEST/RESPONSE */

static int
dissect_kafka_update_metadata_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_UNTIL_VERSION__(4)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_epoch);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Insync Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_zk_version);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "All Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Offline Replicas",
                                        &dissect_kafka_int32, hf_kafka_replica);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_metadata_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_update_metadata_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_metadata_request_endpoint
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_listener_name);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_broker_security_protocol_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_metadata_request_broker
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_broker_endpoint, "Endpoint",
                                        &dissect_kafka_update_metadata_request_endpoint);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_metadata_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_id);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_is_kraft_controller);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_epoch);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    __KAFKA_UNTIL_VERSION__(4)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_update_metadata_request_partition);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_update_metadata_request_topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_broker, "Live Broker",
                                        &dissect_kafka_update_metadata_request_broker);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_update_metadata_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* CONTROLLED_SHUTDOWN REQUEST/RESPONSE */

static int
dissect_kafka_controlled_shutdown_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    gint32 broker_id;

    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid, &broker_id);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    col_append_fstr(kinfo->pinfo->cinfo, COL_INFO, " (Broker-ID=%d)", broker_id);

    return offset;
}

static int
dissect_kafka_controlled_shutdown_response_remaining_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    kafka_partition_t partition;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_partition_id, &partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Topic=%s, Partition-ID=%d)", __KAFKA_STRING__(topic), partition);
    return offset;
}

static int
dissect_kafka_controlled_shutdown_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_partitions, "Remaning Partitions", ett_kafka_partition, "Partition",
                                        &dissect_kafka_controlled_shutdown_response_remaining_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* OFFSET_COMMIT REQUEST/RESPONSE */

static int
dissect_kafka_offset_commit_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    __KAFKA_SINCE_VERSION__(6)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    __KAFKA_SINCE_VERSION__(1)
    __KAFKA_UNTIL_VERSION__(1)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_commit_timestamp);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_metadata);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_commit_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offset_commit_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_commit_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_generation_id);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    __KAFKA_SINCE_VERSION__(2)
    __KAFKA_UNTIL_VERSION__(4)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_retention_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_commit_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_commit_response_partition_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_commit_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offset_commit_response_partition_response);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_commit_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_commit_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* GROUP_COORDINATOR REQUEST/RESPONSE */

static int
dissect_kafka_find_coordinator_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_UNTIL_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_coordinator_key);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_coordinator_type);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_coordinator_key);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_find_coordinator_response_coordinator
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_coordinator_key);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_find_coordinator_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    __KAFKA_UNTIL_VERSION__(3)
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(1)
    __KAFKA_UNTIL_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    __KAFKA_UNTIL_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    __KAFKA_UNTIL_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    __KAFKA_UNTIL_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_broker, "Coordinator",
                                        &dissect_kafka_find_coordinator_response_coordinator);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* JOIN_GROUP REQUEST/RESPONSE */

static int
dissect_kafka_join_group_request_group_protocol
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref protocol;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_protocol_name, &protocol);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_protocol_metadata);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Protocol=%s)", __KAFKA_STRING__(protocol));
    return offset;
}

static int
dissect_kafka_join_group_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref group;
    kafka_buffer_ref member;

    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_consumer_group, &group);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_session_timeout);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_rebalance_timeout);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_member_id, &member);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_type);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_group_protocols, "Group Protocols", ett_kafka_group_protocol, "Group Protocol",
                                        &dissect_kafka_join_group_request_group_protocol);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_group_operation_reason);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    col_append_fstr(kinfo->pinfo->cinfo, COL_INFO, " (Group=%s, Member=%s)", __KAFKA_STRING__(group), __KAFKA_STRING__(member));
    return offset;
}

static int
dissect_kafka_join_group_response_member
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_member_metadata);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_join_group_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref member;
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_generation_id);
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_name);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_group_leader_id);
    __KAFKA_SINCE_VERSION__(8)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_skip_assignments);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_member_id, &member);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_group_members, "Group Members", ett_kafka_group_member, "Member",
                                        &dissect_kafka_join_group_response_member);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    col_append_fstr(kinfo->pinfo->cinfo, COL_INFO, " (Member=%s)", __KAFKA_STRING__(member));
    return offset;
}

/* HEARTBEAT REQUEST/RESPONSE */

static int
dissect_kafka_heartbeat_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_generation_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_heartbeat_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* LEAVE_GROUP REQUEST/RESPONSE */

static int
dissect_kafka_leave_group_request_member
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_group_operation_reason);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_leave_group_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    __KAFKA_UNTIL_VERSION__(2)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1,  NULL, ett_kafka_group_member, "Member",
                                        &dissect_kafka_leave_group_request_member);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_leave_group_response_member
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_leave_group_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1,  NULL, ett_kafka_group_member, "Member",
                                        &dissect_kafka_leave_group_response_member);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* SYNC_GROUP REQUEST/RESPONSE */

static int
dissect_kafka_sync_group_request_group_assignment
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_member_assignment);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_sync_group_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_generation_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_type);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1,  NULL, ett_kafka_group_member, "Group Assignment",
                                        &dissect_kafka_sync_group_request_group_assignment);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_sync_group_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_type);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_name);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_member_assignment);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_GROUPS REQUEST/RESPONSE */

static int
dissect_kafka_describe_groups_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset, -1, NULL, &dissect_kafka_string, hf_kafka_consumer_group);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_include_group_authorized_ops);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_describe_groups_response_member
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_client_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_client_host);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_member_metadata);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_member_assignment);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_groups_response_group
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref group;

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_consumer_group, &group);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_group_state);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_group_member, "Member",
                                        &dissect_kafka_describe_groups_response_member);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_group_authorized_ops);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    proto_item_append_text(proto_tree_get_parent(tree), " (Group=%s)", __KAFKA_STRING__(group));

    return offset;
}

static int
dissect_kafka_describe_groups_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_group, "Group",
                                        &dissect_kafka_describe_groups_response_group);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* LIST_GROUPS REQUEST/RESPONSE */

static int
dissect_kafka_list_groups_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset, -1, NULL, &dissect_kafka_string, hf_kafka_group_state);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset, -1, NULL, &dissect_kafka_string, hf_kafka_group_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_groups_response_group
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_protocol_type);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_group_state);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_group_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_groups_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_group, "Group",
                                        &dissect_kafka_list_groups_response_group);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* SASL_HANDSHAKE REQUEST/RESPONSE */

static int
dissect_kafka_sasl_handshake_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref auth_mechanism;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_sasl_mechanism, &auth_mechanism);
    if (auth_mechanism.length >= 0) {
        dissect_kafka_get_conv_info(kinfo->pinfo)->sasl_auth_mech =
                tvb_get_string_enc(wmem_file_scope(), tvb, auth_mechanism.offset, auth_mechanism.length, ENC_UTF_8);
    }
    return offset;
}

static int
dissect_kafka_sasl_handshake_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_sasl_enabled_mechanisms, "Enabled SASL Mechanisms",
                                        &dissect_kafka_string, hf_kafka_sasl_mechanism);
    return offset;
}

/* CREATE_TOPICS REQUEST/RESPONSE */

static int
dissect_kafka_create_topics_request_replica_assignment
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_partition_t partition;
    offset = dissect_kafka_int32_ret(tvb, kinfo, tree, offset, hf_kafka_partition_id, &partition);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_replica);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Partition-ID=%d)", partition);
    return offset;
}

static int
dissect_kafka_create_topics_request_config
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref key;
    kafka_buffer_ref val;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_config_key, &key);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_config_value, &val);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Key=%s, Value=%s)", __KAFKA_STRING__(key), __KAFKA_STRING__(val));
    return offset;
}

static int
dissect_kafka_create_topics_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_num_partitions);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_replication_factor);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Replica Assignment",
                                        &dissect_kafka_create_topics_request_replica_assignment);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_config_entry, "Config",
                                        &dissect_kafka_create_topics_request_config);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_create_topics_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_create_topics_request_topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_validate_only);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_topics_response_topic_config
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref key;
    kafka_buffer_ref val;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_config_key, &key);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_config_value, &val);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_readonly);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_source);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_sensitive);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Key=%s, Value=%s)", __KAFKA_STRING__(key), __KAFKA_STRING__(val));
    return offset;
}

static int
dissect_kafka_create_topics_response_topic_tagged_fields
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_config_error_code);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_create_topics_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    int topic_id_offset = 0;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    topic_id_offset = offset;
    __KAFKA_SINCE_VERSION__(7)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_num_partitions);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_replication_factor);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_config_entry, "Config",
                                        &dissect_kafka_create_topics_response_topic_config);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset,
                                         &dissect_kafka_create_topics_response_topic_tagged_fields);
    __KAFKA_UNTIL_VERSION__(6)
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    __KAFKA_SINCE_VERSION__(7)
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s, ID=%s)",
                           __KAFKA_STRING__(topic), __KAFKA_UUID__(topic_id_offset));
    return offset;
}

static int
dissect_kafka_create_topics_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_create_topics_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DELETE_TOPICS REQUEST/RESPONSE */

static int
dissect_kafka_delete_topics_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_topics_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    __KAFKA_SINCE_VERSION__(6)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_delete_topics_request_topic);
    __KAFKA_UNTIL_VERSION__(5)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_topic_name);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_delete_topics_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    __KAFKA_SINCE_VERSION__(6)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    __KAFKA_SINCE_VERSION__(5)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;

}

static int
dissect_kafka_delete_topics_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_delete_topics_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DELETE_RECORDS REQUEST/RESPONSE */

static int
dissect_kafka_delete_records_request_topic_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_records_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_delete_records_request_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_records_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_delete_records_request_topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_records_response_topic_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_error);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_records_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_delete_records_response_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_records_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_delete_records_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* INIT_PRODUCER_ID REQUEST/RESPONSE */

static int
dissect_kafka_init_producer_id_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_transaction_timeout);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}


static int
dissect_kafka_init_producer_id_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* OFFSET_FOR_LEADER_EPOCH REQUEST/RESPONSE */

static int
dissect_kafka_offset_for_leader_epoch_request_topic_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_current_leader_epoch);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offset_for_leader_epoch_request_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_replica_id(tvb, kinfo, tree, offset, hf_kafka_replica);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_for_leader_epoch_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_response_topic_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offset_for_leader_epoch_response_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}


static int
dissect_kafka_offset_for_leader_epoch_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_for_leader_epoch_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ADD_PARTITIONS_TO_TXN REQUEST/RESPONSE */

static int
dissect_kafka_add_partitions_to_txn_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_add_partitions_to_txn_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_response_topic_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_error);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_add_partitions_to_txn_response_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_add_partitions_to_txn_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ADD_OFFSETS_TO_TXN REQUEST/RESPONSE */

static int
dissect_kafka_add_offsets_to_txn_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_add_offsets_to_txn_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* END_TXN REQUEST/RESPONSE */

static int
dissect_kafka_end_txn_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_transaction_result);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_end_txn_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* WRITE_TXN_MARKERS REQUEST/RESPONSE */

static int
dissect_kafka_write_txn_markers_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL, &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_write_txn_markers_request_marker
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_transaction_result);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_write_txn_markers_request_topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_coordinator_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_write_txn_markers_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_marker, "Marker",
                                        &dissect_kafka_write_txn_markers_request_marker);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_write_txn_markers_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_error);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_write_txn_markers_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_write_txn_markers_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_write_txn_markers_response_marker
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_write_txn_markers_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_write_txn_markers_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_marker, "Marker",
                                        &dissect_kafka_write_txn_markers_response_marker);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* TXN_OFFSET_COMMIT REQUEST/RESPONSE */

static int
dissect_kafka_txn_offset_commit_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    guint32 partition_id;
    gint64 partition_offset;
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    offset = dissect_kafka_int32_ret(tvb, kinfo, subtree, offset, hf_kafka_partition_id, &partition_id);
    offset = dissect_kafka_int64_ret(tvb, kinfo, subtree, offset, hf_kafka_offset, &partition_offset);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_int32(tvb, kinfo, subtree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_string(tvb, kinfo, subtree, offset, hf_kafka_metadata);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, subtree, offset, NULL);

    proto_item_set_end(subti, tvb, offset);

    proto_item_append_text(subti, " (ID=%u, Offset=%" PRIi64 ")", partition_id, partition_offset);

    return offset;
}

static int
dissect_kafka_txn_offset_commit_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_txn_offset_commit_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_txn_offset_commit_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_generation_id);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_member_id);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group_instance);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_txn_offset_commit_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_txn_offset_commit_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_error);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_txn_offset_commit_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_txn_offset_commit_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}


static int
dissect_kafka_txn_offset_commit_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_txn_offset_commit_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_ACLS REQUEST/RESPONSE */

static int
dissect_kafka_describe_acls_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_resource_name);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_pattern_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_principal);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_host);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_operation);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_permission_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

static int
dissect_kafka_describe_acls_response_resource_acl
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_principal);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_host);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_operation);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_permission_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_acls_response_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_resource_name);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_pattern_type);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_acl, "ACL Entry",
                                        &dissect_kafka_describe_acls_response_resource_acl);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_acls_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_describe_acls_response_resource);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* CREATE_ACLS REQUEST/RESPONSE */

static int
dissect_kafka_create_acls_request_acl
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_resource_name);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_pattern_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_principal);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_host);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_operation);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_permission_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_acls_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_acl, "ACL Entry",
                                        &dissect_kafka_create_acls_request_acl);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_acls_response_acl
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_acls_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_acl, "ACL Entry",
                                        &dissect_kafka_create_acls_response_acl);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DELETE_ACLS REQUEST/RESPONSE */

static int
dissect_kafka_delete_acls_request_filter
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_resource_name);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_pattern_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_principal);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_host);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_operation);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_permission_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
   return offset;
}

static int
dissect_kafka_delete_acls_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_acl_filter, "Filter",
                                        &dissect_kafka_delete_acls_request_filter);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_acls_response_match
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_resource_name);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_resource_pattern_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_principal);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_acl_host);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_operation);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_acl_permission_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_acls_response_filter
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_acl_filter_match, "Match",
                                        &dissect_kafka_delete_acls_response_match);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_acls_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_acl_filter, "Filter",
                                        &dissect_kafka_delete_acls_response_filter);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_CONFIGS REQUEST/RESPONSE */

static int
dissect_kafka_describe_config_request_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_resource_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_config_key);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_configs_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_describe_config_request_resource);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_include_synonyms);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_include_documentation);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_configs_response_synonym
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref key;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_config_key, &key);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_value);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_source);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Key=%s)", __KAFKA_STRING__(key));
    return offset;
}

static int
dissect_kafka_describe_configs_response_entry
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref key;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_config_key, &key);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_value);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_readonly);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_default);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_source);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_sensitive);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_config_synonym, "Synonym",
                                        &dissect_kafka_describe_configs_response_synonym);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_type);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_documentation);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Key=%s)", __KAFKA_STRING__(key));
    return offset;
}

static int
dissect_kafka_describe_configs_response_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_resource_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_config_entry, "Entry",
                                        &dissect_kafka_describe_configs_response_entry);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_configs_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_describe_configs_response_resource);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* ALTER_CONFIGS REQUEST/RESPONSE */

static int
dissect_kafka_alter_config_request_entry
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_key);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_value);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_config_request_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_resource_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_config_entry, "Entry",
                                        &dissect_kafka_alter_config_request_entry);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_configs_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_alter_config_request_resource);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_validate_only);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_configs_response_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_resource_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_configs_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_alter_configs_response_resource);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ALTER_REPLICA_LOG_DIRS REQUEST/RESPONSE */

static int
dissect_kafka_alter_replica_log_dirs_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_request_log_dir
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref dir;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_log_dir, &dir);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_alter_replica_log_dirs_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Dir=%s)", __KAFKA_STRING__(dir));
    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_log_dir, "Log Directory",
                                        &dissect_kafka_alter_replica_log_dirs_request_log_dir);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_log_dir, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_alter_replica_log_dirs_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_alter_replica_log_dirs_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* DESCRIBE_LOG_DIRS REQUEST/RESPONSE */

static int
dissect_kafka_describe_log_dirs_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_describe_log_dirs_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_log_dirs_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_log_dirs_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_segment_size);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_offset_lag);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_future);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_log_dirs_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_describe_log_dirs_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_describe_log_dirs_response_log_dir
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref dir;
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_log_dir, &dir);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_log_dirs_response_topic);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_dir_total_bytes);
    __KAFKA_SINCE_VERSION__(4)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_dir_usable_bytes);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Dir=%s)", __KAFKA_STRING__(dir));
    return offset;
}

static int
dissect_kafka_describe_log_dirs_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_log_dir, "Log Directory",
                                        &dissect_kafka_describe_log_dirs_response_log_dir);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* CREATE_PARTITIONS REQUEST/RESPONSE */

static int
dissect_kafka_create_partitions_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_count);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));

    return offset;
}

static int
dissect_kafka_create_partitions_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_create_partitions_request_topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_validate_only);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_partitions_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_create_partitions_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_create_partitions_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* SASL_AUTHENTICATE REQUEST/RESPONSE */

static int
dissect_kafka_sasl_authenticate_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_conv_info_t *kafka_conv_info;
    kafka_buffer_ref token;
    tvbuff_t *token_tvb;
    proto_item *sasl_token_item;
    proto_tree *sasl_token_tree;

    kafka_conv_info = dissect_kafka_get_conv_info(kinfo->pinfo);

    offset = dissect_kafka_bytes_ret(tvb, kinfo, tree, offset, hf_kafka_sasl_auth_bytes, &token);
    if (token.length > 0) {
        token_tvb = tvb_new_subset_length(tvb, token.offset, token.length);
        if (!kafka_conv_info->sasl_auth_mech) {
            // no-op
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "PLAIN") == 0) {

            sasl_token_tree = proto_tree_add_subtree(tree, token_tvb, 0, -1, ett_kafka_sasl_token, &sasl_token_item, "SASL PLAIN");

            // https://www.rfc-editor.org/rfc/rfc4616
            int authzid_offset, authzid_length;
            int authcid_offset, authcid_length;
            int passwd_offset, passwd_length;
            int i = 0;
            authzid_offset = i;
            while (i<token.length && tvb_get_gint8(token_tvb, i++));
            THROW_MESSAGE_ON(i >= token.length, ReportedBoundsError, "Invalid SASL PLAIN token");
            authzid_length = i - authzid_offset - 1;
            authcid_offset = i;
            while (i<token.length && tvb_get_gint8(token_tvb, i++));
            THROW_MESSAGE_ON(i >= token.length, ReportedBoundsError, "Invalid SASL PLAIN token");
            authcid_length = i - authcid_offset - 1;
            passwd_offset = i;
            while (i<token.length && tvb_get_gint8(token_tvb, i++));
            THROW_MESSAGE_ON(i < token.length, ReportedBoundsError, "Invalid SASL PLAIN token");
            passwd_length = i - passwd_offset;
            proto_tree_add_string(sasl_token_tree, hf_sasl_plain_authzid, token_tvb, authzid_offset, authzid_length,
                      tvb_get_string_enc(kinfo->pinfo->pool, token_tvb, authzid_offset, authzid_length, ENC_UTF_8));
            proto_tree_add_string(sasl_token_tree, hf_sasl_plain_authcid, token_tvb, authcid_offset, authcid_length,
                      tvb_get_string_enc(kinfo->pinfo->pool, token_tvb, authcid_offset, authcid_length, ENC_UTF_8));
            proto_tree_add_string(sasl_token_tree, hf_sasl_plain_passwd, token_tvb, passwd_offset, passwd_length,
                      tvb_get_string_enc(kinfo->pinfo->pool, token_tvb, passwd_offset, passwd_length, ENC_UTF_8));
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "GSSAPI") == 0) {
            sasl_token_tree = proto_tree_add_subtree(tree, token_tvb, 0, -1, ett_kafka_sasl_token, &sasl_token_item, "SASL GSSAPI");
            call_dissector(gssapi_handle, token_tvb, kinfo->pinfo, sasl_token_tree);
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "SCRAM-SHA-256") == 0) {
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "SCRAM-SHA-512") == 0) {
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "OAUTHBEARER") == 0) {
        } else {
        }
    }
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_sasl_authenticate_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_conv_info_t *kafka_conv_info;
    kafka_buffer_ref token;
    tvbuff_t *token_tvb;
    proto_item *sasl_token_item;
    proto_tree *sasl_token_tree;

    kafka_conv_info = dissect_kafka_get_conv_info(kinfo->pinfo);

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_bytes_ret(tvb, kinfo, tree, offset, hf_kafka_sasl_auth_bytes, &token);
    if (token.length > 0) {
        token_tvb = tvb_new_subset_length(tvb, token.offset, token.length);
        if (!kafka_conv_info->sasl_auth_mech) {
            // no-op
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "PLAIN") == 0) {
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "GSSAPI") == 0) {
            sasl_token_tree = proto_tree_add_subtree(tree, token_tvb, 0, -1, ett_kafka_sasl_token, &sasl_token_item, "SASL GSSAPI");
            call_dissector(gssapi_handle, token_tvb, kinfo->pinfo, sasl_token_tree);
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "SCRAM-SHA-256") == 0) {
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "SCRAM-SHA-512") == 0) {
        } else if (strcmp(kafka_conv_info->sasl_auth_mech, "OAUTHBEARER") == 0) {
        } else {
        }
    }
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_session_lifetime_ms);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* CREATE_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_create_delegation_token_request_renewer
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_delegation_token_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_requester_principal_type);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_requester_principal_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_principal, "Renewer",
                                        &dissect_kafka_create_delegation_token_request_renewer);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_token_max_life_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_create_delegation_token_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_name);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_requester_principal_type);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_requester_principal_name);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_issue_timestamp);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_expiry_timestamp);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_max_timestamp);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_id);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_token_hmac);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* RENEW_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_renew_delegation_token_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_token_hmac);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_token_renew_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_renew_delegation_token_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_expiry_timestamp);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* EXPIRE_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_expire_delegation_token_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_token_hmac);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_token_expiry_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_expire_delegation_token_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_expiry_timestamp);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_describe_delegation_token_request_owner
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_delegation_token_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_principal, "Owner",
                                        &dissect_kafka_describe_delegation_token_request_owner);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_delegation_token_response_renewer
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_delegation_token_response_token
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_principal_name);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_requester_principal_type);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_requester_principal_name);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_issue_timestamp);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_expiry_timestamp);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_token_max_timestamp);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_token_id);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_token_hmac);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_principal, "Renewer",
                                        &dissect_kafka_describe_delegation_token_response_renewer);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_delegation_token_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_token, "Token",
                                        &dissect_kafka_describe_delegation_token_response_token);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DELETE_GROUPS REQUEST/RESPONSE */

static int
dissect_kafka_delete_groups_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_consumer_group);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_groups_response_group
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_delete_groups_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_group, "Group",
                                        &dissect_kafka_delete_groups_response_group);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ELECT_LEADERS REQUEST/RESPONSE */

static int
dissect_kafka_elect_leaders_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_elect_leaders_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_election_type);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_elect_leaders_request_topic);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_elect_leaders_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_elect_leaders_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    kafka_buffer_ref topic;
    offset = dissect_kafka_string_ret(tvb, kinfo, tree, offset, hf_kafka_topic_name, &topic);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_elect_leaders_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    proto_item_append_text(proto_tree_get_parent(tree), " (Name=%s)", __KAFKA_STRING__(topic));
    return offset;
}

static int
dissect_kafka_elect_leaders_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_elect_leaders_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* INCREMENTAL_ALTER_CONFIGS REQUEST/RESPONSE */

static int
dissect_kafka_inc_alter_config_request_entry
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_key);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_operation);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_value);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_inc_alter_config_request_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_resource_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_config_entry, "Entry",
                                        &dissect_kafka_inc_alter_config_request_entry);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_inc_alter_configs_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_inc_alter_config_request_resource);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_validate_only);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_inc_alter_configs_response_resource
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_config_resource_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_config_resource_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_inc_alter_configs_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_resource, "Resource",
                                        &dissect_kafka_inc_alter_configs_response_resource);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ALTER_PARTITION_REASSIGNMENTS REQUEST/RESPONSE */

static int
dissect_kafka_alter_partition_reassignments_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Replicas",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_alter_partition_reassignments_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_alter_partition_reassignments_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_alter_partition_reassignments_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_alter_partition_reassignments_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* LIST_PARTITION_REASSIGNMENTS REQUEST/RESPONSE */

static int
dissect_kafka_list_partition_reassignments_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_partition_reassignments_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_list_partition_reassignments_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Current Replicas",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Adding Replicas",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Removing Replicas",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_list_partition_reassignments_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_list_partition_reassignments_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* OFFSET_DELETE REQUEST/RESPONSE */

static int
dissect_kafka_offset_delete_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_delete_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_consumer_group);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_delete_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_delete_response_topic_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_delete_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_offset_delete_response_topic_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_offset_delete_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_offset_delete_response_topic);
    return offset;
}

/* DESCRIBE_CLIENT_QUOTAS REQUEST/RESPONSE */

static int
dissect_kafka_describe_client_quotas_request_component
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_name);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_quota_match_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_match_text);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_client_quotas_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_component, "Component",
                                        &dissect_kafka_describe_client_quotas_request_component);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_quota_strict_match);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_client_quotas_response_value
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_key);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_quota_value);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_client_quotas_response_entity
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_client_quotas_response_entry
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_entity, "Entity",
                                        &dissect_kafka_describe_client_quotas_response_entity);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_value, "Value",
                                        &dissect_kafka_describe_client_quotas_response_value);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_client_quotas_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_entry, "Entry",
                                        &dissect_kafka_describe_client_quotas_response_entry);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ALTER_CLIENT_QUOTAS REQUEST/RESPONSE */

static int
dissect_kafka_alter_client_quotas_request_entity
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_client_quotas_request_operation
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_key);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_quota_value);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_quota_remove);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_client_quotas_request_entry
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_entity, "Entity",
                                        &dissect_kafka_alter_client_quotas_request_entity);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_operation, "Operation",
                                        &dissect_kafka_alter_client_quotas_request_operation);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_client_quotas_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_entry, "Entry",
                                        &dissect_kafka_alter_client_quotas_request_entry);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_quota_validate_only);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_client_quotas_response_entity
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_quota_entity_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_client_quotas_response_entry
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_entity, "Entity",
                                        &dissect_kafka_alter_client_quotas_response_entity);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_client_quotas_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_quota_entry, "Entry",
                                        &dissect_kafka_alter_client_quotas_response_entry);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_USER_SCRAM_CREDENTIALS REQUEST/RESPONSE */

static int
dissect_kafka_describe_user_scram_credentials_request_user
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_scram_user_name);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_user_scram_credentials_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_scram_user, "User",
                                        &dissect_kafka_describe_user_scram_credentials_request_user);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_user_scram_credentials_response_credential_info
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_scram_mechanism);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_scram_iterations);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_user_scram_credentials_response_user
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_scram_user_name);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_scram_credential_info, "Credential Info",
                                        &dissect_kafka_describe_user_scram_credentials_response_credential_info);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_user_scram_credentials_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_scram_user, "User",
                                        &dissect_kafka_describe_user_scram_credentials_response_user);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ALTER_USER_SCRAM_CREDENTIALS REQUEST/RESPONSE */

static int
dissect_kafka_alter_user_scram_credentials_request_delete
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_scram_user_name);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_scram_mechanism);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_user_scram_credentials_request_upsert
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_scram_user_name);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_scram_mechanism);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_scram_iterations);
    offset = dissect_kafka_base64(tvb, kinfo, tree, offset, hf_kafka_scram_salt);
    offset = dissect_kafka_base64(tvb, kinfo, tree, offset, hf_kafka_scram_salted_password);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_user_scram_credentials_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_scram_operation, "Delete",
                                        &dissect_kafka_alter_user_scram_credentials_request_delete);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_scram_operation, "Upsert",
                                        &dissect_kafka_alter_user_scram_credentials_request_upsert);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_user_scram_credentials_response_result
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_scram_user_name);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_user_scram_credentials_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_scram_operation, "Result",
                                        &dissect_kafka_alter_user_scram_credentials_response_result);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* VOTE REQUEST/RESPONSE */

static int
dissect_kafka_vote_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_candidate_epoch);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_candidate_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_last_offset_epoch);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_last_offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_vote_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_vote_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_vote_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_vote_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_vote_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_vote_granted);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_vote_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_vote_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_vote_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_vote_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* BEGIN_QUORUM_EPOCH REQUEST/RESPONSE */

static int
dissect_kafka_begin_quorum_epoch_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_begin_quorum_epoch_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_begin_quorum_epoch_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_begin_quorum_epoch_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_begin_quorum_epoch_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_begin_quorum_epoch_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_begin_quorum_epoch_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_begin_quorum_epoch_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_begin_quorum_epoch_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_begin_quorum_epoch_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ENDs_QUORUM_EPOCH REQUEST/RESPONSE */

static int
dissect_kafka_end_quorum_epoch_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "Preferred Successors",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_end_quorum_epoch_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_end_quorum_epoch_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_end_quorum_epoch_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_end_quorum_epoch_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_end_quorum_epoch_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_end_quorum_epoch_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_end_quorum_epoch_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_end_quorum_epoch_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_end_quorum_epoch_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_QUORUM REQUEST/RESPONSE */

static int
dissect_kafka_describe_quorum_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_describe_quorum_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_quorum_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_response_current_voter
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_replica);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_end_offset);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_last_fetch_timestamp);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_last_caught_up_timestamp);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_response_observer
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_replica);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_end_offset);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_last_fetch_timestamp);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_last_caught_up_timestamp);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_high_watermark);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_voter, "Current Voter",
                                        &dissect_kafka_describe_quorum_response_current_voter);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_voter, "Observer",
                                        &dissect_kafka_describe_quorum_response_observer);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_describe_quorum_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_quorum_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_quorum_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);

    return offset;
}

/* ALTER_PARTITION REQUEST/RESPONSE */

static int
dissect_kafka_alter_partition_request_partition_broker
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    __KAFKA_UNTIL_VERSION__(2)
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "New ISR",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    __KAFKA_SINCE_VERSION__(3)
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "New ISR", ett_kafka_broker, "Broker",
                                        &dissect_kafka_alter_partition_request_partition_broker);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_lead_recovery_state);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_zk_version);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_UNTIL_VERSION__(1)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_alter_partition_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{

    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_alter_partition_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        ett_kafka_replicas, "ISR",
                                        &dissect_kafka_int32, hf_kafka_broker_nodeid);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_lead_recovery_state);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_zk_version);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    __KAFKA_UNTIL_VERSION__(1)
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    __KAFKA_SINCE_VERSION__(2)
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_topic_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_alter_partition_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_alter_partition_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_alter_partition_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* UPDATE_FEATURES REQUEST/RESPONSE */

static int
dissect_kafka_update_features_request_feature
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_feature_name);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_feature_max_version);
    __KAFKA_UNTIL_VERSION__(0)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_feature_allow_downgrade);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_feature_upgrade_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_features_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_timeout);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_feature, "Feature",
                                        &dissect_kafka_update_features_request_feature);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_validate_only);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_features_response_feature
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_feature_name);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_update_features_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_feature, "Feature",
                                        &dissect_kafka_update_features_response_feature);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ENVELOPE REQUEST/RESPONSE */

static int
dissect_kafka_envelope_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_envelope_data);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_envelope_request_principal);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_envelope_client_host);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_envelope_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_envelope_data);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* FETCH_SNAPSHOT REQUEST/RESPONSE */

static int
dissect_kafka_fetch_snapshot_request_snapshot_id
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_end_offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_request_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_current_leader_epoch);
    offset = dissect_kafka_object(tvb, kinfo, tree, offset,
                                  ett_kafka_snapshot_id, "Snapshot ID",
                                  &dissect_kafka_fetch_snapshot_request_snapshot_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_snapshot_position);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_fetch_snapshot_request_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_request_tagged_fields
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_fetch_snapshot_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_replica);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_max_bytes);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_fetch_snapshot_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, &dissect_kafka_fetch_snapshot_request_tagged_fields);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_response_current_leader
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_response_snapshot_id
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_end_offset);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_leader_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_response_partition_tagged_fields
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset, guint64 tag)
{
    if (tag == 0) {
        offset = dissect_kafka_object(tvb, kinfo, tree, offset,
                                      ett_kafka_snapshot_id, "Current Leader",
                                      &dissect_kafka_fetch_snapshot_response_current_leader);
        return 1;
    } else {
        return 0;
    }
}

static int
dissect_kafka_fetch_snapshot_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_object(tvb, kinfo, tree, offset,
                                  ett_kafka_snapshot_id, "Snapshot ID",
                                  &dissect_kafka_fetch_snapshot_response_snapshot_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_snapshot_size);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_snapshot_position);
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_snapshot_unaligned_records);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset,
                                         &dissect_kafka_fetch_snapshot_response_partition_tagged_fields);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_bytes(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_fetch_snapshot_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_fetch_snapshot_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_fetch_snapshot_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_CLUSTER REQUEST/RESPONSE */

static int
dissect_kafka_describe_cluster_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_include_cluster_authorized_ops);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_endpoint_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_cluster_response_broker
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_cluster_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_endpoint_type);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_controller_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        ett_kafka_brokers, "Brokers", ett_kafka_broker, "Broker",
                                        &dissect_kafka_describe_cluster_response_broker);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_cluster_authorized_ops);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_PRODUCERS REQUEST/RESPONSE */

static int
dissect_kafka_describe_producers_request_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_producers_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_producers_request_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_producers_response_producer
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_last_sequence);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_last_timestamp);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_coordinator_epoch);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_current_txn_start_offset);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_producers_response_partition
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_partition_id);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_producer, "Producer",
                                        &dissect_kafka_describe_producers_response_producer);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_producers_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_partition, "Partition",
                                        &dissect_kafka_describe_producers_response_partition);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_producers_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_producers_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* BROKER_REGISTRATION REQUEST/RESPONSE */

static int
dissect_kafka_broker_registration_request_listener
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_listener_name);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_broker_host);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_broker_port);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_broker_security_protocol_type);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_broker_registration_request_feature
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_feature_name);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_feature_min_version);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_feature_max_version);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_broker_registration_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_cluster_id);
    offset = dissect_kafka_uuid(tvb, kinfo, tree, offset, hf_kafka_incarnation_id);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_listener, "Listener",
                                        &dissect_kafka_broker_registration_request_listener);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_feature, "Feature",
                                        &dissect_kafka_broker_registration_request_feature);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_rack);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_is_migrating_zk_broker);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_broker_registration_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* BROKER_HEARTBEAT REQUEST/RESPONSE */

static int
dissect_kafka_broker_heartbeat_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_metadata_offset);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_broker_want_fence);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_broker_want_shutdown);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_broker_heartbeat_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_broker_is_caught_up);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_broker_is_fenced);
    offset = dissect_kafka_int8(tvb, kinfo, tree, offset, hf_kafka_broker_should_shutdown);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* UNREGISTER_BROKER REQUEST/RESPONSE */

static int
dissect_kafka_unregister_broker_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_unregister_broker_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_error_message);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* DESCRIBE_TRANSACTIONS REQUEST/RESPONSE */

static int
dissect_kafka_describe_transactions_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_transactional_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_transactions_response_topic
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_topic_name);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int32, hf_kafka_partition_id);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_transactions_response_transaction
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transaction_state);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_transaction_timeout);
    offset = dissect_kafka_timestamp(tvb, kinfo, tree, offset, hf_kafka_transaction_start_time);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_int16(tvb, kinfo, tree, offset, hf_kafka_producer_epoch);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_topic, "Topic",
                                        &dissect_kafka_describe_transactions_response_topic);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_describe_transactions_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_transaction, "Transaction",
                                        &dissect_kafka_describe_transactions_response_transaction);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* LIST_TRANSACTIONS REQUEST/RESPONSE */

static int
dissect_kafka_list_transactions_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_transaction_state_filter);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_int64, hf_kafka_producer_id_filter);
    __KAFKA_SINCE_VERSION__(1)
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_duration_filter);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_transactions_response_transaction
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transactional_id);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id);
    offset = dissect_kafka_string(tvb, kinfo, tree, offset, hf_kafka_transaction_state);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_list_transactions_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_array_simple(tvb, kinfo, tree, offset,
                                        -1, NULL,
                                        &dissect_kafka_string, hf_kafka_unknown_transaction_state_filter);
    offset = dissect_kafka_array_object(tvb, kinfo, tree, offset,
                                        -1, NULL, ett_kafka_transaction, "Transaction",
                                        &dissect_kafka_list_transactions_response_transaction);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* ALLOCATE_PRODUCER_IDS REQUEST/RESPONSE */

static int
dissect_kafka_allocate_producer_ids_request
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_broker_nodeid);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_broker_epoch);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

static int
dissect_kafka_allocate_producer_ids_response
(tvbuff_t *tvb, kafka_packet_info_t *kinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_throttle_time);
    offset = dissect_kafka_error(tvb, kinfo, tree, offset);
    offset = dissect_kafka_int64(tvb, kinfo, tree, offset, hf_kafka_producer_id_start);
    offset = dissect_kafka_int32(tvb, kinfo, tree, offset, hf_kafka_producer_id_length);
    offset = dissect_kafka_tagged_fields(tvb, kinfo, tree, offset, NULL);
    return offset;
}

/* MAIN */

static wmem_multimap_t *
dissect_kafka_get_match_map(packet_info *pinfo)
{
    return dissect_kafka_get_conv_info(pinfo)->match_map;
}

static gboolean
dissect_kafka_insert_match(packet_info *pinfo, guint32 correlation_id, kafka_proto_data_t *proto_data)
{
    if (wmem_multimap_lookup32(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num)) {
        return 0;
    }
    wmem_multimap_insert32(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num, proto_data);
    return 1;
}

static kafka_proto_data_t *
dissect_kafka_lookup_match(packet_info *pinfo, guint32 correlation_id)
{
    kafka_proto_data_t *match = (kafka_proto_data_t*)wmem_multimap_lookup32(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num);
    return match;
}

static kafka_proto_data_t *
dissect_kafka_lookup_match_le(packet_info *pinfo, guint32 correlation_id)
{
    kafka_proto_data_t *match = (kafka_proto_data_t*)wmem_multimap_lookup32_le(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num);
    return match;
}

static kafka_conv_info_t *
dissect_kafka_get_conv_info(packet_info *pinfo)
{
    conversation_t         *conversation;
    kafka_conv_info_t      *conv_info;

    conversation = find_or_create_conversation(pinfo);
    conv_info    = (kafka_conv_info_t *) conversation_get_proto_data(conversation, proto_kafka);
    if (conv_info == NULL) {
        conv_info = wmem_new(wmem_file_scope(), kafka_conv_info_t);
        conv_info->sasl_auth_mech = NULL;
        conv_info->match_map = wmem_multimap_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conversation_add_proto_data(conversation, proto_kafka, conv_info);
    }
    return conv_info;
}

kafka_packet_info_t *
get_kafka_packet_info(packet_info *pinfo, kafka_proto_data_t *proto_data)
{
    kafka_packet_info_t *packet_info;
    packet_info = wmem_new(pinfo->pool, kafka_packet_info_t);
    packet_info->pinfo = pinfo;
    packet_info->api_key = proto_data->api_key;
    packet_info->api_version = proto_data->api_version;
    packet_info->correlation_id = proto_data->correlation_id;
    packet_info->request_frame = proto_data->request_frame;
    packet_info->response_frame = proto_data->response_frame;
    packet_info->flexible_api = proto_data->flexible_api;
    packet_info->client_id = proto_data->client_id;
    return packet_info;
}

static int
dissect_kafka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item             *root_ti, *ti;
    proto_tree             *kafka_tree;
    int                     offset  = 0;
    guint32                 pdu_length;
    guint32                 pdu_correlation_id;
    kafka_proto_data_t     *proto_data;
    kafka_packet_info_t    *kinfo;
    kafka_buffer_ref        client_id;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kafka");
    col_clear(pinfo->cinfo, COL_INFO);

    root_ti = proto_tree_add_item(tree, proto_kafka, tvb, 0, -1, ENC_NA);

    kafka_tree = proto_item_add_subtree(root_ti, ett_kafka);

    pdu_length = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(kafka_tree, hf_kafka_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (pinfo->destport == pinfo->match_uint) {

        /* Request (as directed towards server port) */

        /* in the request PDU the correlation id comes after api_key and api_version */
        pdu_correlation_id = tvb_get_ntohl(tvb, offset+4);

        proto_data = dissect_kafka_lookup_match(pinfo, pdu_correlation_id);
        if (!proto_data) {
            proto_data = wmem_new(wmem_file_scope(), kafka_proto_data_t);
            proto_data->correlation_id = pdu_correlation_id;
            proto_data->response_frame = 0;
            proto_data->request_frame  = pinfo->num;
            proto_data->api_key        = tvb_get_ntohs(tvb, offset);
            proto_data->api_version    = tvb_get_ntohs(tvb, offset+2);
            proto_data->flexible_api   = kafka_is_api_version_flexible(proto_data->api_key, proto_data->api_version);
            proto_data->client_id      = NULL;
            dissect_kafka_insert_match(pinfo, pdu_correlation_id, proto_data);
        } else if (proto_data->request_frame != pinfo->num) {
            col_add_fstr(pinfo->cinfo, COL_INFO, " (Other request frame in %d)", proto_data->request_frame);
            expert_add_info(pinfo, root_ti, &ei_kafka_duplicate_correlation_id);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s v%d Request",
                     kafka_api_key_to_str(proto_data->api_key),
                     proto_data->api_version);

        /* Also add to protocol root */
        proto_item_append_text(root_ti, " (%s v%d Request)",
                               kafka_api_key_to_str(proto_data->api_key),
                               proto_data->api_version);

        if (!proto_data->request_frame) {
            proto_data->request_frame = pinfo->num;
        } else if (proto_data->request_frame != pinfo->num) {
            col_add_fstr(pinfo->cinfo, COL_INFO, " (Other request frame in %d)", proto_data->request_frame);
            expert_add_info(pinfo, root_ti, &ei_kafka_duplicate_correlation_id);
        }

        kinfo = get_kafka_packet_info(pinfo, proto_data);

        /* for the header implementation check RequestHeaderData class */

        ti = proto_tree_add_item(kafka_tree, hf_kafka_request_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(ti);

        ti = proto_tree_add_item(kafka_tree, hf_kafka_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        kafka_check_supported_api_key(pinfo, ti, proto_data);

        ti = proto_tree_add_item(kafka_tree, hf_kafka_request_api_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(ti);

        ti = proto_tree_add_item(kafka_tree, hf_kafka_api_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        kafka_check_supported_api_version(pinfo, ti, proto_data);

        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (proto_data->response_frame) {
            ti = proto_tree_add_uint(kafka_tree, hf_kafka_response_frame, tvb,
                                     0, 0, proto_data->response_frame);
            proto_item_set_generated(ti);
        }

        if (proto_data->api_key == KAFKA_CONTROLLED_SHUTDOWN && proto_data->api_version == 0) {
            /*
             * Special case for ControlledShutdownRequest.
             * https://github.com/apache/kafka/blob/2.5.0/generator/src/main/java/org/apache/kafka/message/ApiMessageTypeGenerator.java#L268-L277
             * The code is materialized in ApiMessageTypes class.
             */
        } else {
            /* even if flexible API is used, clientId is still using gint16 string length prefix */
            offset = dissect_kafka_regular_string_ret(tvb, kinfo, kafka_tree, offset, hf_kafka_client_id, &client_id);
            if (! proto_data->client_id && offset >= 0 && client_id.length >= 0) {
                proto_data->client_id = tvb_get_string_enc(wmem_file_scope(), tvb, client_id.offset, client_id.length, ENC_UTF_8);
            }
        }

        if (proto_data->flexible_api) {
            /* version 2 request header (flexible API) contains list of tagged fields, last param is ignored */
            offset = dissect_kafka_tagged_fields(tvb, kinfo, kafka_tree, offset, NULL);
        }

        switch (proto_data->api_key) {
            case KAFKA_PRODUCE:
                /* The kafka server always responds, except in the case of a produce
                 * request whose RequiredAcks field is 0. This field is at a dynamic
                 * offset into the request, so to avoid too much prefetch logic we
                 * simply don't queue produce requests here. If it is a produce
                 * request with a non-zero RequiredAcks field it gets queued later.
                 */
                offset = dissect_kafka_produce_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_FETCH:
                offset = dissect_kafka_fetch_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSETS:
                offset = dissect_kafka_offsets_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_METADATA:
                offset = dissect_kafka_metadata_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LEADER_AND_ISR:
                offset = dissect_kafka_leader_and_isr_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_STOP_REPLICA:
                offset = dissect_kafka_stop_replica_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_UPDATE_METADATA:
                offset = dissect_kafka_update_metadata_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CONTROLLED_SHUTDOWN:
                offset = dissect_kafka_controlled_shutdown_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_COMMIT:
                offset = dissect_kafka_offset_commit_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_FETCH:
                offset = dissect_kafka_offset_fetch_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_FIND_COORDINATOR:
                offset = dissect_kafka_find_coordinator_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_JOIN_GROUP:
                offset = dissect_kafka_join_group_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_HEARTBEAT:
                offset = dissect_kafka_heartbeat_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LEAVE_GROUP:
                offset = dissect_kafka_leave_group_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_SYNC_GROUP:
                offset = dissect_kafka_sync_group_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_GROUPS:
                offset = dissect_kafka_describe_groups_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LIST_GROUPS:
                offset = dissect_kafka_list_groups_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_SASL_HANDSHAKE:
                offset = dissect_kafka_sasl_handshake_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_API_VERSIONS:
                offset = dissect_kafka_api_versions_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_TOPICS:
                offset = dissect_kafka_create_topics_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_TOPICS:
                offset = dissect_kafka_delete_topics_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_RECORDS:
                offset = dissect_kafka_delete_records_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_INIT_PRODUCER_ID:
                offset = dissect_kafka_init_producer_id_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_FOR_LEADER_EPOCH:
                offset = dissect_kafka_offset_for_leader_epoch_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ADD_PARTITIONS_TO_TXN:
                offset = dissect_kafka_add_partitions_to_txn_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ADD_OFFSETS_TO_TXN:
                offset = dissect_kafka_add_offsets_to_txn_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_END_TXN:
                offset = dissect_kafka_end_txn_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_WRITE_TXN_MARKERS:
                offset = dissect_kafka_write_txn_markers_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_TXN_OFFSET_COMMIT:
                offset = dissect_kafka_txn_offset_commit_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_ACLS:
                offset = dissect_kafka_describe_acls_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_ACLS:
                offset = dissect_kafka_create_acls_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_ACLS:
                offset = dissect_kafka_delete_acls_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_CONFIGS:
                offset = dissect_kafka_describe_configs_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_CONFIGS:
                offset = dissect_kafka_alter_configs_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_REPLICA_LOG_DIRS:
                offset = dissect_kafka_alter_replica_log_dirs_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_LOG_DIRS:
                offset = dissect_kafka_describe_log_dirs_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_PARTITIONS:
                offset = dissect_kafka_create_partitions_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_SASL_AUTHENTICATE:
                offset = dissect_kafka_sasl_authenticate_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_DELEGATION_TOKEN:
                offset = dissect_kafka_create_delegation_token_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_RENEW_DELEGATION_TOKEN:
                offset = dissect_kafka_renew_delegation_token_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_EXPIRE_DELEGATION_TOKEN:
                offset = dissect_kafka_expire_delegation_token_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_DELEGATION_TOKEN:
                offset = dissect_kafka_describe_delegation_token_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_GROUPS:
                offset = dissect_kafka_delete_groups_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ELECT_LEADERS:
                offset = dissect_kafka_elect_leaders_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_INC_ALTER_CONFIGS:
                offset = dissect_kafka_inc_alter_configs_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_alter_partition_reassignments_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LIST_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_list_partition_reassignments_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_DELETE:
                offset = dissect_kafka_offset_delete_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_CLIENT_QUOTAS:
                offset = dissect_kafka_describe_client_quotas_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_CLIENT_QUOTAS:
                offset = dissect_kafka_alter_client_quotas_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_USER_SCRAM_CREDENTIALS:
                offset = dissect_kafka_describe_user_scram_credentials_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_USER_SCRAM_CREDENTIALS:
                offset = dissect_kafka_alter_user_scram_credentials_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_VOTE:
                offset = dissect_kafka_vote_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_BEGIN_QUORUM_EPOCH:
                offset = dissect_kafka_begin_quorum_epoch_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_END_QUORUM_EPOCH:
                offset = dissect_kafka_end_quorum_epoch_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_QUORUM:
                offset = dissect_kafka_describe_quorum_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_PARTITION:
                offset = dissect_kafka_alter_partition_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_UPDATE_FEATURES:
                offset = dissect_kafka_update_features_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ENVELOPE:
                offset = dissect_kafka_envelope_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_FETCH_SHAPSHOT:
                offset = dissect_kafka_fetch_snapshot_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_CLUSTER:
                offset = dissect_kafka_describe_cluster_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_PRODUCERS:
                offset = dissect_kafka_describe_producers_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_BROKER_REGISTRATION:
                offset = dissect_kafka_broker_registration_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_BROKER_HEARTBEAT:
                offset = dissect_kafka_broker_heartbeat_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_UNREGISTER_BROKER:
                offset = dissect_kafka_unregister_broker_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_TRANSACTIONS:
                offset = dissect_kafka_describe_transactions_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LIST_TRANSACTIONS:
                offset = dissect_kafka_list_transactions_request(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALLOCATE_PRODUCER_IDS:
                offset = dissect_kafka_allocate_producer_ids_request(tvb, kinfo, kafka_tree, offset);
                break;
        }

    }
    else {
        /* Response */

        /* in the response PDU the correlation id comes directly after frame length */
        pdu_correlation_id = tvb_get_ntohl(tvb, offset);

        proto_data = dissect_kafka_lookup_match_le(pinfo, pdu_correlation_id);
        if (proto_data == NULL) {
            proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            col_set_str(pinfo->cinfo, COL_INFO, "Kafka Response (Undecoded, Request Missing)");
            expert_add_info(pinfo, root_ti, &ei_kafka_request_missing);
            return tvb_captured_length(tvb);
        }
        if (!proto_data->response_frame) {
            proto_data->response_frame = pinfo->num;
        } else if (proto_data->response_frame != pinfo->num) {
            col_add_fstr(pinfo->cinfo, COL_INFO, " (Other response frame in %d)", proto_data->response_frame);
            expert_add_info(pinfo, root_ti, &ei_kafka_duplicate_correlation_id);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s v%d Response",
                     kafka_api_key_to_str(proto_data->api_key),
                     proto_data->api_version);
        /* Also add to protocol root */
        proto_item_append_text(root_ti, " (%s v%d Response)",
                               kafka_api_key_to_str(proto_data->api_key),
                               proto_data->api_version);

        /* Show api key (message type) */
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_key, tvb,
                                0, 0, proto_data->api_key);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
        ti = proto_tree_add_int(kafka_tree, hf_kafka_api_key, tvb,
                                0, 0, proto_data->api_key);
        proto_item_set_generated(ti);
        kafka_check_supported_api_key(pinfo, ti, proto_data);

        /* Also show api version from request */
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_version, tvb,
                                0, 0, proto_data->api_version);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_version, tvb,
                                0, 0, proto_data->api_version);
        proto_item_set_generated(ti);
        kafka_check_supported_api_version(pinfo, ti, proto_data);

        /* display after API key and version */
        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* Show request frame */
        if (proto_data->request_frame) {
            ti = proto_tree_add_uint(kafka_tree, hf_kafka_request_frame, tvb,
                                     0, 0, proto_data->request_frame);
            proto_item_set_generated(ti);
        }

        if (proto_data->client_id) {
            ti = proto_tree_add_string(kafka_tree, hf_kafka_client_id, tvb,
                                       0, 0, proto_data->client_id);
            proto_item_set_generated(ti);
        }

        kinfo = get_kafka_packet_info(pinfo, proto_data);

        if (proto_data->api_key == KAFKA_API_VERSIONS) {
            /*
             * Special case for ApiVersions.
             * https://cwiki.apache.org/confluence/display/KAFKA/KIP-511%3A+Collect+and+Expose+Client%27s+Name+and+Version+in+the+Brokers
             * https://github.com/apache/kafka/blob/2.5.0/generator/src/main/java/org/apache/kafka/message/ApiMessageTypeGenerator.java#L261-L267
             * The code is materialized in ApiMessageTypes class.
             */
        } else if (proto_data->flexible_api) {
            /* version 1 response header (flexible API) contains list of tagged fields, last param is ignored */
            offset = dissect_kafka_tagged_fields(tvb, kinfo, kafka_tree, offset, NULL);
        }

        switch (proto_data->api_key) {
            case KAFKA_PRODUCE:
                offset = dissect_kafka_produce_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_FETCH:
                offset = dissect_kafka_fetch_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSETS:
                offset = dissect_kafka_offsets_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_METADATA:
                offset = dissect_kafka_metadata_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LEADER_AND_ISR:
                offset = dissect_kafka_leader_and_isr_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_STOP_REPLICA:
                offset = dissect_kafka_stop_replica_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_UPDATE_METADATA:
                offset = dissect_kafka_update_metadata_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CONTROLLED_SHUTDOWN:
                offset = dissect_kafka_controlled_shutdown_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_COMMIT:
                offset = dissect_kafka_offset_commit_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_FETCH:
                offset = dissect_kafka_offset_fetch_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_FIND_COORDINATOR:
                offset = dissect_kafka_find_coordinator_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_JOIN_GROUP:
                offset = dissect_kafka_join_group_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_HEARTBEAT:
                offset = dissect_kafka_heartbeat_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LEAVE_GROUP:
                offset = dissect_kafka_leave_group_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_SYNC_GROUP:
                offset = dissect_kafka_sync_group_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_GROUPS:
                offset = dissect_kafka_describe_groups_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LIST_GROUPS:
                offset = dissect_kafka_list_groups_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_SASL_HANDSHAKE:
                offset = dissect_kafka_sasl_handshake_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_API_VERSIONS:
                offset = dissect_kafka_api_versions_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_TOPICS:
                offset = dissect_kafka_create_topics_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_TOPICS:
                offset = dissect_kafka_delete_topics_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_RECORDS:
                offset = dissect_kafka_delete_records_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_INIT_PRODUCER_ID:
                offset = dissect_kafka_init_producer_id_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_FOR_LEADER_EPOCH:
                offset = dissect_kafka_offset_for_leader_epoch_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ADD_PARTITIONS_TO_TXN:
                offset = dissect_kafka_add_partitions_to_txn_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ADD_OFFSETS_TO_TXN:
                offset = dissect_kafka_add_offsets_to_txn_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_END_TXN:
                offset = dissect_kafka_end_txn_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_WRITE_TXN_MARKERS:
                offset = dissect_kafka_write_txn_markers_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_TXN_OFFSET_COMMIT:
                offset = dissect_kafka_txn_offset_commit_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_ACLS:
                offset = dissect_kafka_describe_acls_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_ACLS:
                offset = dissect_kafka_create_acls_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_ACLS:
                offset = dissect_kafka_delete_acls_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_CONFIGS:
                offset = dissect_kafka_describe_configs_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_CONFIGS:
                offset = dissect_kafka_alter_configs_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_REPLICA_LOG_DIRS:
                offset = dissect_kafka_alter_replica_log_dirs_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_LOG_DIRS:
                offset = dissect_kafka_describe_log_dirs_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_PARTITIONS:
                offset = dissect_kafka_create_partitions_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_SASL_AUTHENTICATE:
                offset = dissect_kafka_sasl_authenticate_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_CREATE_DELEGATION_TOKEN:
                offset = dissect_kafka_create_delegation_token_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_RENEW_DELEGATION_TOKEN:
                offset = dissect_kafka_renew_delegation_token_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_EXPIRE_DELEGATION_TOKEN:
                offset = dissect_kafka_expire_delegation_token_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_DELEGATION_TOKEN:
                offset = dissect_kafka_describe_delegation_token_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DELETE_GROUPS:
                offset = dissect_kafka_delete_groups_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ELECT_LEADERS:
                offset = dissect_kafka_elect_leaders_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_INC_ALTER_CONFIGS:
                offset = dissect_kafka_inc_alter_configs_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_alter_partition_reassignments_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LIST_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_list_partition_reassignments_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_DELETE:
                offset = dissect_kafka_offset_delete_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_CLIENT_QUOTAS:
                offset = dissect_kafka_describe_client_quotas_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_CLIENT_QUOTAS:
                offset = dissect_kafka_alter_client_quotas_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_USER_SCRAM_CREDENTIALS:
                offset = dissect_kafka_describe_user_scram_credentials_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_USER_SCRAM_CREDENTIALS:
                offset = dissect_kafka_alter_user_scram_credentials_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_VOTE:
                offset = dissect_kafka_vote_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_BEGIN_QUORUM_EPOCH:
                offset = dissect_kafka_begin_quorum_epoch_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_END_QUORUM_EPOCH:
                offset = dissect_kafka_end_quorum_epoch_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_QUORUM:
                offset = dissect_kafka_describe_quorum_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALTER_PARTITION:
                offset = dissect_kafka_alter_partition_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_UPDATE_FEATURES:
                offset = dissect_kafka_update_features_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ENVELOPE:
                offset = dissect_kafka_envelope_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_FETCH_SHAPSHOT:
                offset = dissect_kafka_fetch_snapshot_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_CLUSTER:
                offset = dissect_kafka_describe_cluster_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_PRODUCERS:
                offset = dissect_kafka_describe_producers_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_BROKER_REGISTRATION:
                offset = dissect_kafka_broker_registration_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_BROKER_HEARTBEAT:
                offset = dissect_kafka_broker_heartbeat_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_UNREGISTER_BROKER:
                offset = dissect_kafka_unregister_broker_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_DESCRIBE_TRANSACTIONS:
                offset = dissect_kafka_describe_transactions_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_LIST_TRANSACTIONS:
                offset = dissect_kafka_list_transactions_response(tvb, kinfo, kafka_tree, offset);
                break;
            case KAFKA_ALLOCATE_PRODUCER_IDS:
                offset = dissect_kafka_allocate_producer_ids_response(tvb, kinfo, kafka_tree, offset);
                break;
        }

    }

    if (offset != (int)pdu_length + 4) {
        expert_add_info(pinfo, root_ti, &ei_kafka_pdu_length_mismatch);
    }

    return offset;
}

/*
 * Compute the length of a Kafka protocol frame (PDU) from the minimal fragment.
 * The datastream in TCP (and TLS) is and abstraction of continuous stream of octets.
 * On the network level these are transported in chunks (packets). On the application
 * protocol level we do also deal with discrete chunks (PDUs). Ideally these should
 * match. In the real life the boundaries are different. In Kafka case a PDU may span
 * multiple network packets. A PDU starts with 32 bit unsigned integer that specifies
 * remaining protocol frame length. Fortunatelly protocol implementations execute
 * flush between subsequent PDUs, therefore we should not expect PDU starting in the middle
 * of TCP data packet or TLS data frame.
 */
static guint
get_kafka_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return 4 + tvb_get_ntohl(tvb, offset);
}

/*
 * Attempt to dissect Kafka protocol frames.
 */
static int
dissect_kafka_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4,
                     get_kafka_pdu_len, dissect_kafka, data);
    return tvb_captured_length(tvb);
}

static void
compute_kafka_api_names(void)
{
    guint i;
    guint len = array_length(kafka_apis);

    for (i = 0; i < len; ++i) {
        kafka_api_names[i].value  = kafka_apis[i].api_key;
        kafka_api_names[i].strptr = kafka_apis[i].name;
    }

    kafka_api_names[len].value  = 0;
    kafka_api_names[len].strptr = NULL;
}

static void
proto_register_kafka_protocol_fields(int protocol)
{
    static hf_register_info hf[] = {
        { &hf_kafka_len,
            { "Length", "kafka.len",
               FT_INT32, BASE_DEC, 0, 0,
              "The length of this Kafka packet.", HFILL }
        },
        { &hf_kafka_offset,
            { "Offset", "kafka.offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_offset_time,
            { "Time", "kafka.offset_time",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_log_start_offset,
            { "Log Start Offset", "kafka.log_start_offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_last_fetched_epoch,
            { "Last Fetched Epoch", "kafka.last_fetched_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_candidate_id,
                { "Candidate ID", "kafka.candidate_id",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_candidate_epoch,
                { "Candidate Epoch", "kafka.candidate_epoch",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_preferred_successor,
                { "Preferred Successor", "kafka.preferred_successor",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },

        { &hf_kafka_last_offset,
                { "Last Offset", "kafka.last_offset",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_last_offset_epoch,
                { "Candidate Epoch", "kafka.last_offset_epoch",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_high_watermark,
            { "High Watermark", "kafka.high_watermark",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_last_stable_offset,
            { "Last Stable Offset", "kafka.last_stable_offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_first_offset,
            { "First Offset", "kafka.first_offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_preferred_read_replica,
            { "Preferred Read Replica", "kafka.preferred_read_replica",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_max_offsets,
            { "Max Offsets", "kafka.max_offsets",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_metadata,
            { "Metadata", "kafka.metadata",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_error,
            { "Error", "kafka.error",
               FT_INT16, BASE_DEC, VALS(kafka_errors), 0,
               NULL, HFILL }
        },
        { &hf_kafka_error_message,
            { "Error Message", "kafka.error_message",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_api_key,
            { "API Key", "kafka.api_key",
                FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
                "Request API Key.", HFILL }
        },
        { &hf_kafka_api_version,
            { "API Version", "kafka.api_version",
                FT_INT16, BASE_DEC, 0, 0,
                "Request API Version.", HFILL }
        },
        // these should be deprecated
        // --- begin ---
        { &hf_kafka_request_api_key,
            { "API Key", "kafka.request_key",
               FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
              "Request API.", HFILL }
        },
        { &hf_kafka_response_api_key,
            { "API Key", "kafka.response_key",
               FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
              "Response API.", HFILL }
        },
        { &hf_kafka_request_api_version,
            { "API Version", "kafka.request.version",
               FT_INT16, BASE_DEC, 0, 0,
              "Request API Version.", HFILL }
        },
        { &hf_kafka_response_api_version,
            { "API Version", "kafka.response.version",
               FT_INT16, BASE_DEC, 0, 0,
              "Response API Version.", HFILL }
        },
        // --- end ---
        { &hf_kafka_correlation_id,
            { "Correlation ID", "kafka.correlation_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_client_id,
            { "Client ID", "kafka.client_id",
               FT_STRING, BASE_NONE, 0, 0,
              "The ID of the sending client.", HFILL }
        },
        { &hf_kafka_client_host,
            { "Client Host", "kafka.client_host",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_transactional_id,
                { "Transactional ID", "kafka.transactional_id",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_transaction_result,
                { "Transaction Result", "kafka.transaction_result",
                        FT_INT8, BASE_DEC, VALS(kafka_transaction_results), 0,
                        NULL, HFILL }
        },
        { &hf_kafka_transaction_timeout,
                { "Transaction Timeout", "kafka.transaction_timeout",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_transaction_state,
                { "Transaction State", "kafka.transaction_state",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_transaction_state_filter,
                { "Transaction State Filter", "kafka.transaction_state_filter",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_unknown_transaction_state_filter,
                { "Unknown Transaction State Filter", "kafka.transaction_state_filter",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_transaction_start_time,
                { "Transaction Start Time", "kafka.transaction_start_time",
                        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_required_acks,
            { "Required Acks", "kafka.required_acks",
               FT_INT16, BASE_DEC, VALS(kafka_acks), 0,
               NULL, HFILL }
        },
        { &hf_kafka_timeout,
            { "Timeout", "kafka.timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_topic_name,
            { "Topic Name", "kafka.topic_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        // topic_id is in fact UUID, but tools refer to it formatted using base64 with no padding
        { &hf_kafka_topic_id,
            { "Topic ID", "kafka.topic_id",
              FT_STRING, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_producer_id,
            { "Producer ID", "kafka.producer_id",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_producer_id_filter,
                { "Producer ID", "kafka.producer_id_filter",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_duration_filter,
                { "Min Duration", "kafka.transaction_duration_filter",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_producer_id_start,
                { "Producer ID Pool Start", "kafka.producer_id_start",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_producer_id_length,
                { "Producer ID Pool Size", "kafka.producer_id_length",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_producer_epoch,
            { "Producer Epoch", "kafka.producer_epoch",
                FT_INT16, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_partition_id,
            { "Partition ID", "kafka.partition_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_replica,
            { "Replica ID", "kafka.replica_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_replica_epoch,
            { "Replica Epoch", "kafka.replica_epoch",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_replication_factor,
            { "Replication Factor", "kafka.replication_factor",
               FT_INT16, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_isr,
            { "Caught-Up Replica ID", "kafka.isr_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_offline,
            { "Offline Replica ID", "kafka.offline_id",
                FT_INT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_message_size,
            { "Message Size", "kafka.message_size",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_crc,
            { "CRC32", "kafka.message_crc",
               FT_UINT32, BASE_HEX, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_magic,
            { "Magic Byte", "kafka.message_magic",
               FT_INT8, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_codec,
            { "Compression Codec", "kafka.message_codec",
               FT_UINT8, BASE_DEC, VALS(kafka_message_codecs), KAFKA_MESSAGE_CODEC_MASK,
               NULL, HFILL }
        },
        { &hf_kafka_message_timestamp_type,
            { "Timestamp Type", "kafka.message_timestamp_type",
               FT_UINT8, BASE_DEC, VALS(kafka_message_timestamp_types), KAFKA_MESSAGE_TIMESTAMP_MASK,
               NULL, HFILL }
        },
        { &hf_kafka_batch_crc,
            { "CRC32", "kafka.batch_crc",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_codec,
            { "Compression Codec", "kafka.batch_codec",
                FT_UINT16, BASE_DEC, VALS(kafka_message_codecs), KAFKA_MESSAGE_CODEC_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_timestamp_type,
            { "Timestamp Type", "kafka.batch_timestamp_type",
                FT_UINT16, BASE_DEC, VALS(kafka_message_timestamp_types), KAFKA_MESSAGE_TIMESTAMP_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_transactional,
            { "Transactional", "kafka.batch_transactional",
                FT_UINT16, BASE_DEC, VALS(kafka_batch_transactional_values), KAFKA_BATCH_TRANSACTIONAL_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_control_batch,
            { "Control Batch", "kafka.batch_control_batch",
                FT_UINT16, BASE_DEC, VALS(kafka_batch_control_batch_values), KAFKA_BATCH_CONTROL_BATCH_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_last_offset_delta,
            { "Last Offset Delta", "kafka.batch_last_offset_delta",
               FT_UINT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_batch_first_timestamp,
            { "First Timestamp", "kafka.batch_first_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_last_timestamp,
            { "Last Timestamp", "kafka.batch_last_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_base_sequence,
            { "Base Sequence", "kafka.batch_base_sequence",
                FT_INT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_size,
            { "Size", "kafka.batch_size",
                FT_UINT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_index,
            { "Batch Index", "kafka.batch_index",
                FT_UINT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_index_error_message,
            { "Batch Index Error Message", "kafka.batch_index_error_message",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_message_timestamp,
            { "Timestamp", "kafka.message_timestamp",
               FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_key,
            { "Key", "kafka.message_key",
               FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_value,
            { "Value", "kafka.message_value",
               FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_compression_reduction,
            { "Compression Reduction (compressed/uncompressed)", "kafka.message_compression_reduction",
               FT_FLOAT, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_truncated_content,
            { "Truncated Content", "kafka.truncated_content",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_consumer_group,
            { "Consumer Group", "kafka.consumer_group",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_consumer_group_instance,
            { "Consumer Group Instance", "kafka.consumer_group_instance",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_coordinator_key,
            { "Coordinator Key", "kafka.coordinator_key",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_coordinator_type,
            { "Coordinator Type", "kafka.coordinator_type",
               FT_INT8, BASE_DEC, VALS(kafka_coordinator_types), 0,
               NULL, HFILL }
        },
        { &hf_kafka_group_operation_reason,
            { "Group Operation Reason", "kafka.group_operation_reason",
              FT_STRING, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_request_frame,
            { "Request Frame", "kafka.request_frame",
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_nodeid,
            { "Node ID", "kafka.node_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_epoch,
            { "Broker Epoch", "kafka.broker_epoch",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_host,
            { "Host", "kafka.host",
              FT_STRING, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_broker_metadata_offset,
                { "Metadata Offset", "kafka.broker_metadata_offset",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_broker_want_fence,
                { "Want Fence", "kafka.broker_want_fence",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_broker_want_shutdown,
                { "Want Shutdown", "kafka.broker_want_shutdown",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_broker_is_caught_up,
                { "Is Caught Up", "kafka.broker_is_caught_up",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_broker_is_fenced,
                { "Is Fenced", "kafka.broker_is_fenced",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_broker_should_shutdown,
                { "Should Shutdown", "kafka.broker_should_shutdown",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_leader_and_isr_type,
                { "Type", "kafka.leader_and_isr_type",
                        FT_INT8, BASE_DEC, 0, 0,
                        "The type that indicates whether all topics are included in the request", HFILL }
        },
        { &hf_kafka_lead_recovery_state,
            { "Lead Recovery State", "kafka.lead_recovery_state",
              FT_INT8, BASE_DEC, VALS(kafka_lead_recovery_states), 0,
              NULL, HFILL }
        },
        { &hf_kafka_is_kraft_controller,
            { "Is KRaft Controller", "kafka.is_kraft_controller",
               FT_BOOLEAN, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_is_migrating_zk_broker,
            { "Is Migrating ZK Broker", "kafka.is_migrating_zk_broker",
               FT_BOOLEAN, BASE_NONE, 0, 0,
               "If the required configurations for ZK migration are present, this value is set to true", HFILL }
        },
        { &hf_kafka_isr_request_type,
            { "ISR Request Type", "kafka.isr_request_type",
              FT_INT8, BASE_DEC, VALS(kafka_isr_request_types), 0,
              NULL, HFILL }
        },
        { &hf_kafka_listener_name,
            { "Listener", "kafka.listener_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_port,
            { "Port", "kafka.port",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_rack,
            { "Rack", "kafka.rack",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_security_protocol_type,
            { "Security Protocol Type", "kafka.broker_security_protocol_type",
               FT_INT16, BASE_DEC, VALS(kafka_security_protocol_types), 0,
               NULL, HFILL }
        },
        { &hf_kafka_cluster_id,
            { "Cluster ID", "kafka.cluster_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_controller_id,
            { "Controller ID", "kafka.node_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_controller_epoch,
            { "Controller Epoch", "kafka.controller_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_delete_partitions,
            { "Delete Partitions", "kafka.delete_partitions",
               FT_BOOLEAN, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_group_leader_id,
            { "Leader ID", "kafka.group_leader_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_skip_assignments,
            { "Skip Assignments", "kafka.skip_assignments",
              FT_BOOLEAN, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_leader_id,
            { "Leader ID", "kafka.leader_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_leader_epoch,
            { "Leader Epoch", "kafka.leader_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_current_leader_epoch,
            { "Leader Epoch", "kafka.current_leader_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_end_offset,
            { "End Offset", "kafka.end_offset",
              FT_INT64, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_last_fetch_timestamp,
            { "Last Fetch Timestamp", "kafka.last_fetch_timestamp",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_kafka_last_caught_up_timestamp,
            { "Last Caught Up Timestamp", "kafka.last_caught_up_timestamp",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_kafka_is_internal,
            { "Is Internal", "kafka.is_internal",
               FT_BOOLEAN, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_min_bytes,
            { "Min Bytes", "kafka.min_bytes",
               FT_INT32, BASE_DEC, 0, 0,
               "The minimum number of bytes of messages that must be available"
                   " to give a response.",
               HFILL }
        },
        { &hf_kafka_max_bytes,
            { "Max Bytes", "kafka.max_bytes",
               FT_INT32, BASE_DEC, 0, 0,
               "The maximum bytes to include in the message set for this"
                   " partition. This helps bound the size of the response.",
               HFILL }
        },
        { &hf_kafka_isolation_level,
            { "Isolation Level", "kafka.isolation_level",
               FT_INT8, BASE_DEC, VALS(kafka_isolation_levels), 0,
               NULL, HFILL }
        },
        { &hf_kafka_max_wait_time,
            { "Max Wait Time", "kafka.max_wait_time",
               FT_INT32, BASE_DEC, 0, 0,
               "The maximum amount of time in milliseconds to block waiting if"
                   " insufficient data is available at the time the request is"
                   " issued.",
               HFILL }
        },
        { &hf_kafka_throttle_time,
            { "Throttle time", "kafka.throttle_time",
               FT_INT32, BASE_DEC, 0, 0,
               "Duration in milliseconds for which the request was throttled"
                   " due to quota violation."
                   " (Zero if the request did not violate any quota.)",
               HFILL }
        },
        { &hf_kafka_response_frame,
            { "Response Frame", "kafka.response_frame",
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
               NULL, HFILL }
        },
        { &hf_kafka_api_versions_api_key,
            { "API Key", "kafka.api_versions.api_key",
               FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
              "API Key.", HFILL }
        },
        { &hf_kafka_api_versions_min_version,
            { "Min Version", "kafka.api_versions.min_version",
               FT_INT16, BASE_DEC, 0, 0,
              "Minimal version which supports api key.", HFILL }
        },
        { &hf_kafka_api_versions_max_version,
            { "Max Version", "kafka.api_versions.max_version",
              FT_INT16, BASE_DEC, 0, 0,
              "Maximal version which supports api key.", HFILL }
        },
        { &hf_kafka_feature_name,
            { "Feature Name", "kafka.feature.name",
              FT_STRING, BASE_NONE, 0, 0,
              "The name of the feature.", HFILL }
        },
        { &hf_kafka_feature_min_version,
            { "Min Version", "kafka.feature.min_version",
              FT_INT16, BASE_DEC, 0, 0,
              "The minimum supported version for the feature.", HFILL }
        },
        { &hf_kafka_feature_max_version,
            { "Max Version", "kafka.feature.max_version",
              FT_INT16, BASE_DEC, 0, 0,
              "The maximum supported version for the feature.", HFILL }
        },
        { &hf_kafka_finalized_features_epoch,
            { "Finalized Features Epoch", "kafka.api_versions.finalized_features_epoch",
              FT_INT64, BASE_DEC, 0, 0,
              "The monotonically increasing epoch for the finalized features information. "
              "Valid values are >= 0. A value of -1 is special and represents unknown epoch.", HFILL }
        },
        { &hf_kafka_session_timeout,
            { "Session Timeout", "kafka.session_timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_rebalance_timeout,
            { "Rebalance Timeout", "kafka.rebalance_timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_group_state,
            { "State", "kafka.group_state",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_group_type,
            { "Type", "kafka.group_type",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_id,
            { "Consumer Group Member ID", "kafka.member_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_epoch,
            { "Consumer Group Member Epoch", "kafka.member_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_protocol_type,
            { "Protocol Type", "kafka.protocol_type",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_protocol_name,
            { "Protocol Name", "kafka.protocol_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_protocol_metadata,
            { "Protocol Metadata", "kafka.protocol_metadata",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_metadata,
            { "Member Metadata", "kafka.member_metadata",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_generation_id,
            { "Generation ID", "kafka.generation_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_assignment,
            { "Member Assignment", "kafka.member_assignment",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_sasl_mechanism,
            { "SASL Mechanism", "kafka.sasl_mechanism",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_num_partitions,
            { "Number of Partitions", "kafka.num_partitions",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_zk_version,
            { "Zookeeper Version", "kafka.zk_version",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_is_new_replica,
            { "New Replica", "kafka.is_new_replica",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_key,
            { "Key", "kafka.config_key",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_config_value,
            { "Value", "kafka.config_value",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_config_error_code,
            { "Error", "kafka.config_error_code",
               FT_INT16, BASE_DEC, 0, 0,
               "Optional topic config error returned if configs are not returned in the response.", HFILL }
        },
        { &hf_kafka_config_operation,
            { "Operation", "kafka.config_operation",
               FT_INT8, BASE_DEC, VALS(config_operations), 0,
               NULL, HFILL }
        },
        { &hf_kafka_config_documentation,
            { "Documentation", "kafka.config_documentation",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_commit_timestamp,
            { "Timestamp", "kafka.commit_timestamp",
               FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
               NULL, HFILL }
        },
        { &hf_kafka_retention_time,
            { "Retention Time", "kafka.retention_time",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_forgotten_topic_name,
            { "Forgotten Topic Name", "kafka.forgotten_topic_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_forgotten_topic_partition,
            { "Forgotten Topic Partition", "kafka.forgotten_topic_partition",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_fetch_session_id,
            { "Fetch Session ID", "kafka.fetch_session_id",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_fetch_session_epoch,
            { "Fetch Session Epoch", "kafka.fetch_session_epoch",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_require_stable_offset,
            { "Require Stable Offset", "kafka.require_stable_offset",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_record_header_key,
            { "Header Key", "kafka.header_key",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_record_header_value,
            { "Header Value", "kafka.header_value",
                FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_record_attributes,
            { "Record Attributes (reserved)", "kafka.record_attributes",
                FT_INT8, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_allow_auto_topic_creation,
            { "Allow Auto Topic Creation", "kafka.allow_auto_topic_creation",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_validate_only,
            { "Only Validate the Request", "kafka.validate_only",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_coordinator_epoch,
            { "Coordinator Epoch", "kafka.coordinator_epoch",
                FT_INT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_sasl_auth_bytes,
            { "SASL Authentication Bytes", "kafka.sasl_authentication",
                FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_session_lifetime_ms,
            { "Session Lifetime (ms)", "kafka.session_lifetime_ms",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_resource_type,
            { "Resource Type", "kafka.acl_resource_type",
                FT_INT8, BASE_DEC, VALS(acl_resource_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_resource_name,
            { "Resource Name", "kafka.acl_resource_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_resource_pattern_type,
            { "Resource Pattern Type", "kafka.acl_resource_pattern_type",
                FT_INT8, BASE_DEC, VALS(acl_resource_pattern_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_principal,
            { "Principal", "kafka.acl_principal",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_host,
            { "Host", "kafka.acl_host",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_operation,
            { "Operation", "kafka.acl_operation",
                FT_INT8, BASE_DEC, VALS(acl_operations), 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_permission_type,
            { "Permission Type", "kafka.acl_permission_type",
                FT_INT8, BASE_DEC, VALS(acl_permission_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_resource_type,
            { "Resource Type", "kafka.config_resource_type",
                FT_INT8, BASE_DEC, VALS(config_resource_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_resource_name,
            { "Resource Name", "kafka.config_resource_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_include_synonyms,
            { "Include Synonyms", "kafka.config_include_synonyms",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_include_documentation,
            { "Include Documentations", "kafka.config_include_documentation",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_default,
            { "Default", "kafka.config_default",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_readonly,
            { "Readonly", "kafka.config_readonly",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_sensitive,
            { "Sensitive", "kafka.config_sensitive",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_source,
            { "Source", "kafka.config_source",
                FT_INT8, BASE_DEC, VALS(config_sources), 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_type,
            { "Type", "kafka.config_type",
                FT_INT8, BASE_DEC, VALS(config_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_log_dir,
            { "Log Directory", "kafka.log_dir",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_segment_size,
            { "Segment Size", "kafka.segment_size",
                FT_UINT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_offset_lag,
            { "Offset Lag", "kafka.offset_lag",
                FT_UINT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_future,
            { "Future", "kafka.future",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_dir_total_bytes,
            { "Total Bytes", "kafka.dir_total_bytes",
                FT_UINT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_dir_usable_bytes,
            { "Usable Bytes", "kafka.dir_usable_bytes",
                FT_UINT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_partition_count,
            { "Partition Count", "kafka.partition_count",
                FT_UINT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_max_life_time,
            { "Max Life Time", "kafka.token_max_life_time",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_renew_time,
            { "Renew Time", "kafka.renew_time",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_expiry_time,
            { "Expiry Time", "kafka.expiry_time",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_principal_type,
            { "Principal Type", "kafka.principal_type",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_principal_name,
            { "Principal Name", "kafka.principal_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_requester_principal_type,
            { "Requester Principal Type", "kafka.requester_principal_type",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_requester_principal_name,
            { "Requester Principal Name", "kafka.requester_principal_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_issue_timestamp,
            { "Issue Timestamp", "kafka.token_issue_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_expiry_timestamp,
            { "Expiry Timestamp", "kafka.token_expiry_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_max_timestamp,
            { "Max Timestamp", "kafka.token_max_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_id,
            { "ID", "kafka.token_id",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_hmac,
            { "HMAC", "kafka.token_hmac",
                FT_BYTES, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_include_cluster_authorized_ops,
            { "Include Cluster Authorized Operations", "kafka.include_cluster_authorized_ops",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_endpoint_type,
            { "The endpoint type to describe", "kafka.endpoint_type",
                FT_INT8, BASE_DEC, VALS(endpoint_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_include_topic_authorized_ops,
            { "Include Topic Authorized Operations", "kafka.include_topic_authorized_ops",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_cluster_authorized_ops,
            { "Cluster Authorized Operations", "kafka.cluster_authorized_ops",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_topic_authorized_ops,
            { "Topic Authorized Operations", "kafka.topic_authorized_ops",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_include_group_authorized_ops,
            { "Include Group Authorized Operations", "kafka.include_group_authorized_ops",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_group_authorized_ops,
            { "Group Authorized Operations", "kafka.group_authorized_ops",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_election_type,
            { "Election Type", "kafka.election_type",
                FT_INT8, BASE_DEC, VALS(election_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_unknown_tagged_field_tag,
                { "Tag Value", "kafka.unknown_tagged_field_tag",
                        FT_UINT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_unknown_tagged_field_data,
                { "Tag Data", "kafka.unknown_tagged_field_data",
                        FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_client_software_name,
            { "Client Software Name", "kafka.client_software_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_client_software_version,
            { "Client Software Version", "kafka.client_software_version",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_quota_entity_name,
                { "Entity Name", "kafka.quota_entity_name",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_entity_type,
                { "Entity Type", "kafka.quota_entity_type",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_key,
                { "Key", "kafka.quota_key",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_value,
                { "Value", "kafka.quota_value",
                        FT_FLOAT, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_remove,
                { "Remove", "kafka.quota_remove",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_match_text,
                { "Match Text", "kafka.quota_match_text",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_match_type,
                { "Match Type", "kafka.quota_match_type",
                        FT_INT8, BASE_DEC, VALS(quota_match_types), 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_strict_match,
                { "Strict Match", "kafka.quota_strict_match",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_quota_validate_only,
                { "Validate Only", "kafka.quota_validate_only",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_scram_user_name,
                { "User Name", "kafka.scram_user_name",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_scram_mechanism,
                { "Mechanism", "kafka.scram_mechanism",
                        FT_INT8, BASE_DEC, VALS(scram_mechanisms), 0,
                        NULL, HFILL }
        },
        { &hf_kafka_scram_iterations,
                { "Iterations", "kafka.scram_iterations",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_scram_salt,
                { "Salt", "kafka.scram_salt",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_scram_salted_password,
                { "Salted Password", "kafka.scram_salted_password",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_isr_version,
                { "ISR Version", "kafka.isr_version",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_feature_allow_downgrade,
                { "Allow Downgrade", "kafka.feature_allow_downgrade",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_feature_upgrade_type,
                { "Upgrade Type", "kafka.feature_upgrade_type",
                        FT_INT8, BASE_DEC, VALS(feature_upgrade_types), 0,
                        NULL, HFILL }
        },
        { &hf_kafka_envelope_data,
                { "Data", "kafka.envelope_data",
                        FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_envelope_request_principal,
                { "Data", "kafka.envelope_request_principal",
                        FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_envelope_client_host,
                { "Data", "kafka.envelope_client_host",
                        FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_snapshot_size,
                { "Size", "kafka.snapshot_size",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_snapshot_position,
                { "Position", "kafka.snapshot_position",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_snapshot_unaligned_records,
                { "Unaligned Records", "kafka.snapshot_unaligned_records",
                        FT_BYTES, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_last_sequence,
                { "Last Sequence", "kafka.last_sequence",
                        FT_INT32, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_last_timestamp,
                { "Last Timestamp", "kafka.last_timestamp",
                        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_current_txn_start_offset,
                { "Current Txn Start Offset", "kafka.current_txn_start_offset",
                        FT_INT64, BASE_DEC, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_incarnation_id,
                { "Incarnation ID", "kafka.broker.incarnation_id",
                        FT_STRING, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_kafka_vote_granted,
                { "Vote Granted", "kafka.vote_granted",
                        FT_BOOLEAN, BASE_NONE, 0, 0,
                        NULL, HFILL }
        },
        { &hf_sasl_plain_authzid,
                { "authzid", "kafka.sasl_authzid",
                        FT_STRING, BASE_NONE, 0, 0,
                        "Authorization Identity", HFILL }
        },
        { &hf_sasl_plain_authcid,
                { "authcid", "kafka.sasl_authcid",
                        FT_STRING, BASE_NONE, 0, 0,
                        "Authentication Identity", HFILL }
        },
        { &hf_sasl_plain_passwd,
                { "passwd", "kafka.sasl_passwd",
                        FT_STRING, BASE_NONE, 0, 0,
                        "Password", HFILL }
        },
    };

    proto_register_field_array(protocol, hf, array_length(hf));

}

static void
proto_register_kafka_protocol_subtrees(const int proto _U_)
{
    static int *ett[] = {
        &ett_kafka,
        &ett_kafka_batch,
        &ett_kafka_message,
        &ett_kafka_message_set,
        &ett_kafka_offline,
        &ett_kafka_isrs,
        &ett_kafka_replicas,
        &ett_kafka_replica_state,
        &ett_kafka_broker,
        &ett_kafka_brokers,
        &ett_kafka_broker_endpoint,
        &ett_kafka_markers,
        &ett_kafka_marker,
        &ett_kafka_topics,
        &ett_kafka_topic,
        &ett_kafka_partitions,
        &ett_kafka_partition,
        &ett_kafka_api_version,
        &ett_kafka_group_protocols,
        &ett_kafka_group_protocol,
        &ett_kafka_group_members,
        &ett_kafka_group_member,
        &ett_kafka_group_assignments,
        &ett_kafka_group_assignment,
        &ett_kafka_groups,
        &ett_kafka_group,
        &ett_kafka_sasl_enabled_mechanisms,
        &ett_kafka_replica_assignment,
        &ett_kafka_configs,
        &ett_kafka_config,
        &ett_kafka_request_forgotten_topic,
        &ett_kafka_record,
        &ett_kafka_record_headers,
        &ett_kafka_record_headers_header,
        &ett_kafka_aborted_transactions,
        &ett_kafka_aborted_transaction,
        &ett_kafka_resources,
        &ett_kafka_resource,
        &ett_kafka_acls,
        &ett_kafka_acl,
        &ett_kafka_acl_creations,
        &ett_kafka_acl_creation,
        &ett_kafka_acl_filters,
        &ett_kafka_acl_filter,
        &ett_kafka_acl_filter_matches,
        &ett_kafka_acl_filter_match,
        &ett_kafka_config_synonyms,
        &ett_kafka_config_synonym,
        &ett_kafka_config_entries,
        &ett_kafka_config_entry,
        &ett_kafka_log_dirs,
        &ett_kafka_log_dir,
        &ett_kafka_principals,
        &ett_kafka_principal,
        &ett_kafka_owners,
        &ett_kafka_owner,
        &ett_kafka_tokens,
        &ett_kafka_token,
        &ett_kafka_unknown_tagged_field,
        &ett_kafka_record_errors,
        &ett_kafka_record_error,
        &ett_kafka_states_filter,
        &ett_kafka_quota_component,
        &ett_kafka_quota_entity,
        &ett_kafka_quota_entry,
        &ett_kafka_quota_value,
        &ett_kafka_quota_operation,
        &ett_kafka_diverging_epoch,
        &ett_kafka_current_leader,
        &ett_kafka_snapshot_id,
        &ett_kafka_scram_user,
        &ett_kafka_scram_credential_info,
        &ett_kafka_scram_operation,
        &ett_kafka_scram_result,
        &ett_kafka_voter,
        &ett_kafka_feature,
        &ett_kafka_producer,
        &ett_kafka_listener,
        &ett_kafka_transaction,
        &ett_kafka_sasl_token,
    };
    proto_register_subtree_array(ett, array_length(ett));
}

static void
proto_register_kafka_expert_module(const int proto) {
    expert_module_t* expert_kafka;
    static ei_register_info ei[] = {
            { &ei_kafka_request_missing,
                    { "kafka.request_missing", PI_UNDECODED, PI_WARN, "Request missing", EXPFILL }},
            { &ei_kafka_duplicate_correlation_id,
                    { "kafka.duplicate_correlation_id", PI_UNDECODED, PI_WARN, "Duplicate correlation ID", EXPFILL }},
            { &ei_kafka_unknown_api_key,
                    { "kafka.unknown_api_key", PI_UNDECODED, PI_WARN, "Unknown API key", EXPFILL }},
            { &ei_kafka_unsupported_api_version,
                    { "kafka.unsupported_api_version", PI_UNDECODED, PI_WARN, "Unsupported API version", EXPFILL }},
            { &ei_kafka_error_response,
                    { "kafka.error_response", PI_RESPONSE_CODE, PI_NOTE, "Error code in response", EXPFILL }},
            { &ei_kafka_bad_string_length,
                    { "kafka.bad_string_length", PI_MALFORMED, PI_WARN, "Invalid string length field", EXPFILL }},
            { &ei_kafka_bad_bytes_length,
                    { "kafka.bad_bytes_length", PI_MALFORMED, PI_WARN, "Invalid byte length field", EXPFILL }},
            { &ei_kafka_bad_array_length,
                    { "kafka.bad_array_length", PI_MALFORMED, PI_WARN, "Invalid array length field", EXPFILL }},
            { &ei_kafka_bad_record_length,
                    { "kafka.bad_record_length", PI_MALFORMED, PI_WARN, "Invalid record length field", EXPFILL }},
            { &ei_kafka_bad_varint,
                    { "kafka.bad_varint", PI_MALFORMED, PI_WARN, "Invalid varint bytes", EXPFILL }},
            { &ei_kafka_bad_message_set_length,
                    { "kafka.ei_kafka_bad_message_set_length", PI_MALFORMED, PI_WARN, "Message set size does not match content", EXPFILL }},
            { &ei_kafka_bad_decompression_length,
                    { "kafka.ei_kafka_bad_decompression_length", PI_MALFORMED, PI_WARN, "Decompression size too large", EXPFILL }},
            { &ei_kafka_zero_decompression_length,
                    { "kafka.ei_kafka_zero_decompression_length", PI_PROTOCOL, PI_NOTE, "Decompression size zero", EXPFILL }},
            { &ei_kafka_unknown_message_magic,
                    { "kafka.unknown_message_magic", PI_MALFORMED, PI_WARN, "Invalid message magic field", EXPFILL }},
            { &ei_kafka_pdu_length_mismatch,
                    { "kafka.pdu_length_mismatch", PI_MALFORMED, PI_WARN, "Dissected message does not end at the pdu length offset", EXPFILL }},
    };
    expert_kafka = expert_register_protocol(proto);
    expert_register_field_array(expert_kafka, ei, array_length(ei));
}

static void
proto_register_kafka_preferences(const int proto)
{
    module_t *kafka_module;
    kafka_module = prefs_register_protocol(proto, NULL);
    /* unused; kept for backward compatibility */
    prefs_register_bool_preference(kafka_module, "show_string_bytes_lengths",
                                   "Show length for string and bytes fields in the protocol tree",
                                   "",
                                   &kafka_show_string_bytes_lengths);
}


/*
 * Dissector entry points, contract for dissection plugin.
 */

void
proto_register_kafka(void)
{

    int protocol_handle;

    compute_kafka_api_names();

    protocol_handle = proto_register_protocol("Kafka", "Kafka", "kafka");
    proto_register_kafka_protocol_fields(protocol_handle);
    proto_register_kafka_protocol_subtrees(protocol_handle);
    proto_register_kafka_expert_module(protocol_handle);
    proto_register_kafka_preferences(protocol_handle);

    proto_kafka = protocol_handle;

}

void
proto_reg_handoff_kafka(void)
{

    kafka_handle = register_dissector("kafka", dissect_kafka_tcp, proto_kafka);
    gssapi_handle = find_dissector_add_dependency("gssapi", proto_kafka);

    dissector_add_uint_range_with_preference("tcp.port", KAFKA_TCP_DEFAULT_RANGE, kafka_handle);
    ssl_dissector_add(0, kafka_handle);

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
