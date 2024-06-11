/**
 * \file sv_monitor.c
 *
 * \brief Library to monitor IEC61850 Sample Value sent on an interface. When
 * such packets are sent or received, the monitor_handler is called.
 *
 * \copyright Copyright (C) 2024 Savoir-faire Linux, Inc
 * \license SPDX-License-Identifier: Apache-2.0
 */

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/if_ether.h>

#include "sv_monitor.h"

#define PCAP_READ_TIMEOUT 1000 // 1s
#define IEC_61850_SV_PROTOCOL "(ether proto 0x88ba) or (vlan and ether proto 0x88ba)"

static void print_pcap_timestamp_type_error(int err)
{
        fprintf(stderr, "Couldn't set timestamp type: ");
        switch(err) {
        case PCAP_ERROR_CANTSET_TSTAMP_TYPE:
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
                fprintf(stderr, "not supported by the capture device\n");
                break;
        case PCAP_ERROR_ACTIVATED:
                fprintf(stderr, "device already active\n");
                break;
        }
}

static int configure_pcap(pcap_t *handle,
                          int enable_hardware_ts)
{
        if (pcap_set_promisc(handle, 1)) {
                pcap_perror(handle, "Couldn't set promisc to 1");
                return -1;
        }

        /* Default snap len */
        if (pcap_set_snaplen(handle, BUFSIZ)) {
                pcap_perror(handle, "Couldn't set snaplen to BUFSIZ");
                return -1;
        }

        if (enable_hardware_ts) {
                int ret = pcap_set_tstamp_type(handle, PCAP_TSTAMP_ADAPTER_UNSYNCED);
                if (ret) {
                        print_pcap_timestamp_type_error(ret);
                        return -1;
                }
        }

        if (pcap_set_timeout(handle, PCAP_READ_TIMEOUT)) {
                pcap_perror(handle, "Couldn't set timeout to 1000");
                return -1;
        }

        return 0;
}

static void packet_handler(uint8_t *args,
                           const struct pcap_pkthdr *header,
                           const uint8_t *packet)
{
        struct sv_monitor * monitor = (struct sv_monitor *) args;
        if(monitor->handler) {
                return monitor->handler(header, packet);
        } else {
                fprintf(stderr, "Unhandled SV");
        }
}

/**
 * \brief Configure the monitor
 *
 * \param device network device to listen to
 * \param enable_hardare_ts choose or not hardware timestamping
 *
 * \return initialized monitor
 * */
struct sv_monitor* init_monitor(char * device, int enable_hardware_ts)
{
        struct sv_monitor * monitor = calloc(1,sizeof(struct sv_monitor));
        if(!monitor) {
                fprintf(stderr, "Failed to allocate monitor");
                goto exit;
        }

        char errbuf[PCAP_ERRBUF_SIZE];

        monitor->handle = pcap_create(device, errbuf);
        if (monitor->handle == NULL) {
                fprintf(stderr, "Failed to create pcap handle: %s", errbuf);
                goto cleanup_monitor;
        }

        // set packets to be packets delivered as soon as they arrive,
        // with no buffering
        if (pcap_set_immediate_mode(monitor->handle, 1) != 0) {
                fprintf(stderr, "Failed to set immediate mode");
                goto cleanup_handle;
        }

        if (configure_pcap(monitor->handle, enable_hardware_ts)) {
                goto cleanup_handle;
        }

        if (pcap_activate(monitor->handle)) {
                pcap_perror(monitor->handle, "Couldn't activate the capture");
                goto cleanup_handle;
        }

        /* Filter packets to only get sv ones */
        struct bpf_program bpf_config;

        if (pcap_compile(monitor->handle,
                         &bpf_config,
                         IEC_61850_SV_PROTOCOL,
                         0,
                         PCAP_NETMASK_UNKNOWN) == -1) {
                pcap_perror(monitor->handle, "Couldn't compile filter");
                goto cleanup_handle;
        }

        if (pcap_setfilter(monitor->handle, &bpf_config) == -1) {
                pcap_perror(monitor->handle, "Couldn't install filter");
                goto cleanup_bpf;
        }

        pcap_freecode(&bpf_config);
        return monitor;

cleanup_bpf:
        pcap_freecode(&bpf_config);

cleanup_handle:
        pcap_close(monitor->handle);

cleanup_monitor:
        free(monitor);

exit:
        return NULL;
}

/**
 * \brief monitor destructor
 *
 * \param monitor monitor to free
 * */
void free_monitor(struct sv_monitor * monitor)
{
        pcap_close(monitor->handle);
        free(monitor);
}

/**
 * \brief start processing received packets
 *
 * \param monitor
 * */
int run_monitor(struct sv_monitor * monitor)
{
        int ret = pcap_loop(monitor->handle, -1, packet_handler,
                            (uint8_t *) monitor);
        if(ret == -1) {
                pcap_perror(monitor->handle, "Failed to run pcap loop");
        }
        return ret;
}

/**
 * \brief Stop the monitor
 *
 * \param monitor monitor to stop
 */
void stop_monitor(struct sv_monitor * monitor)
{
        pcap_breakloop(monitor->handle);
}

/**
 * \brief Choose the callback that will process the received packet(s)
 *
 * \param monitor
 * \param handler callback that will process the packet(s)
 * */
void set_sv_handler(struct sv_monitor * monitor, sv_handler handler)
{
        monitor->handler = handler;
}
