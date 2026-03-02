/* Generated table accessors for the Matter dissector. */
#ifndef PACKET_MATTER_CLUSTERS_H
#define PACKET_MATTER_CLUSTERS_H
#include <wsutil/value_string.h>
#include <stdbool.h>
#include <stdint.h>
extern const value_string matter_cluster_id_vals[];
const char *matter_cluster_member_name(uint32_t cluster_id, bool is_command, uint32_t id);
#endif
