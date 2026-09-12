/* Generated table accessors for the Matter dissector. */
#ifndef PACKET_MATTER_CLUSTERS_H
#define PACKET_MATTER_CLUSTERS_H
#include <wsutil/value_string.h>
#include <stdbool.h>
#include <stdint.h>
extern const value_string matter_cluster_id_vals[];
const char *matter_cluster_attribute_name(uint32_t cluster_id, uint32_t id);
const char *matter_cluster_command_name(uint32_t cluster_id, uint32_t id, bool is_response);
#endif
