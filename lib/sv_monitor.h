/**
 * \file sv_monitor.h
 *
 * \brief Library to monitor IEC61850 Sample Value sent on an interface. When
 * such packets are sent or received, the monitor_handler is called.
 *
 * \copyright Copyright (C) 2024 Savoir-faire Linux, Inc
 * \license SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <pcap.h>
#include <stdint.h>

/**
 * \brief Callback function type "sv_handler"
 *
 * \param header Header of a packet in the dump file
 * \param packet Received packet
 */
typedef void (*sv_handler)(const struct pcap_pkthdr *header,
                           const uint8_t *packet);

/**
 * \struct sv_monitor
 * \brief Pcap monitor
 *
 * \param handle pcap handle
 * \param handler callback to apply on each packet
 */
struct sv_monitor {
    pcap_t * handle;
    sv_handler handler;
};

struct sv_monitor * init_monitor(char * device, int enable_hardware_ts);
void free_monitor(struct sv_monitor * monitor);

void set_sv_handler(struct sv_monitor * monitor, sv_handler handler);
int run_monitor(struct sv_monitor * monitor);
void stop_monitor(struct sv_monitor * monitor);
