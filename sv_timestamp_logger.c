/**
 * \file sv_timestamp_logger.c
 * \brief Tool to timstamp received SV pcaps
 *
 * \copyright Copyright (C) 2024 Savoir-faire Linux, Inc
 * \license SPDX-License-Identifier: Apache-2.0
 */

#include <linux/if_ether.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <time.h>
#define __USE_GNU
#include <sys/time.h>
#include <sched.h>

#include "sv_timestamp_logger.h"
#include "lib/sv_parser.h"
#include "lib/sv_monitor.h"

static const struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "device", required_argument, 0, 'd' },
        { "stream", required_argument, 0, 's'},
        { "filename", required_argument, 0, 'f'},
        { "hardware_timestamping", no_argument, 0, 't' },
        { "first_SV_cnt", required_argument, 0, 'c'},
        { "max_SV_cnt", required_argument, 0, 'm' },
        { "log_only_SV_cnt_0", no_argument, 0, 'l'},
        { 0, 0, 0, 0 }
};

static const char * const HELP_MSG_FMT =
        "Usage: %s <-d|--device <device>> [s|--stream <name>] [-t|--hardware_timestamping] [-f| --filename] [--first_SV_cnt <cnt>] [--max_SV_cnt <cnt>] [-l --log_only_SV_cnt_0]\n"
        "\n"
        "Get the timestamp of sample values.\n"
        "\n"
        "Options:\n"
        "\tdevice: the device to listen on.\n"
        "\tstream: the number of the stream on which to look for sample values. If not set, use all streams\n"
        "\tfilename: the file to write the timestamps. If not set, use stdout\n"
        "\thardware_timestamping: enable NIC hardware timestamping (PTP must be setup)\n"
        "\tfirst_SV_cnt: counter of the first SV to be sent. If not set, SV drop will not be computed.\n"
        "\tmax_SV_cnt: max counter of SV in the chosen IEC 61850 configuration. If not set, SV drop will not be computed.\n"
        "\tlog_only_SV_cnt_0: if set, log only the SV number 0.\n"
;

/*  Global Variables */
static struct sv_timestamp_logger_opts opts;
static struct sv_monitor * volatile monitor; // volatile because may be used
                                             // from a signal handler
static FILE * SV_timestamp_file;
static struct SV_payload *sv;

static int compute_SV_drop;
static int current_SV_cnt;
static int total_SV_drop;
static int iteration_nb;

static void print_help(const char* program_name)
{
        printf(HELP_MSG_FMT, program_name);
}

static int parse_args(int argc, char *argv[])
{
        int opt;
        int long_index = 0;
        // default values
        opts.device = NULL;
        opts.stream = NULL;
        opts.SV_filename = "/dev/stdout";
        opts.first_SV_cnt = 0;
        opts.max_SV_cnt = 0;
        opts.log_only_SV_cnt_0 = 0;

        while ((opt = getopt_long(argc, argv, "htld:s:n:f:c:m:", long_options,
                                  &long_index)) != -1) {
                switch (opt) {
                case 'h':
                        print_help(argv[0]);
                        return 1;
                case 'd':
                        opts.device = optarg;
                        break;
                case 't':
                        opts.enable_hardware_ts = 1;
                        break;
                case 's':
                        opts.stream = optarg;
                        break;
                case 'f':
                        opts.SV_filename = optarg;
                        break;
                case 'c':
                        opts.first_SV_cnt = atoi(optarg);
                        break;
                case 'm':
                        opts.max_SV_cnt = atoi(optarg);
                        break;
                case 'l':
                        opts.log_only_SV_cnt_0 = 1;
                        break;
                case '?':
                        fprintf(stderr, "Invalid option: -%c\n", optopt);
                        print_help(argv[0]);
                        return 1;
                }
        }

        iteration_nb = 0;
        current_SV_cnt = opts.first_SV_cnt - 1;

        if (opts.first_SV_cnt != 0 || opts.max_SV_cnt != 0 ) {
            compute_SV_drop = 1;
        }

        if(opts.device != NULL) {
                return 0;
        } else {
                fprintf(stderr, "No device provided\n");
                return 1;
        }
}

static void stop_capture_loop()
{
        if (compute_SV_drop) printf("SV drop: %d\n", total_SV_drop);
        if(monitor) {
                stop_monitor(monitor);
        }
}

static int get_ts(struct timeval* tv) {
    int ret = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        perror("clock_gettime");
        ret = -1;
    }
    TIMESPEC_TO_TIMEVAL(tv, &ts);
    return ret;
}

static int is_vlan(const uint8_t *packet)
{
        const struct ethhdr *eth_header = (const struct ethhdr *)packet;
        if (ntohs(eth_header->h_proto) == 0x8100) { // check if vlan Tagging EtherType
                return 1;
        } else {
                return 0;
        }
}

static void gather_records(const struct pcap_pkthdr *header,
                           const uint8_t *packet)
{
        if(is_vlan(packet)) {
                parse_SV_payload(packet
                        + sizeof(struct ethhdr) // skip Ethernet header
                        + 4*sizeof(uint8_t), // skip vlan PCP/DEI
                        sv);
        } else {
                parse_SV_payload(packet
                        + sizeof(struct ethhdr),
                        sv);
        }

        if (compute_SV_drop) {
            int gap = (sv->seqASDU[0].smpCnt - current_SV_cnt + opts.max_SV_cnt) % opts.max_SV_cnt;
            if (gap > 1) total_SV_drop += gap - 1;
        }

        if (sv->seqASDU[0].smpCnt < current_SV_cnt) iteration_nb++;
        current_SV_cnt = sv->seqASDU[0].smpCnt;

        struct timeval timestamp;

        if(opts.enable_hardware_ts) {
                timestamp = header->ts;
        } else {
                get_ts(&timestamp);
        }

        if ((opts.log_only_SV_cnt_0 && sv->seqASDU[0].smpCnt == 0)
            || (!opts.log_only_SV_cnt_0)) {
                if (opts.stream == NULL
                    || (opts.stream != NULL
                        && !strcmp(sv->seqASDU[0].svID, opts.stream))) {
                        fprintf(SV_timestamp_file, "%d:%s:%d:%ld\n",
                        iteration_nb,
                        sv->seqASDU[0].svID,
                        sv->seqASDU[0].smpCnt,
                        (timestamp.tv_sec * 1000 * 1000) + (timestamp.tv_usec));
                }
        }
}

int main(int argc, char *argv[]) {

        struct sched_param sp = { .sched_priority = 1};
        int ret;

        ret = sched_setscheduler(0, SCHED_FIFO, &sp);
        if (ret == -1) {
                perror("sched_setscheduler");
                return 1;
        }

        ret = parse_args(argc, argv);
        if(ret) return ret;


        monitor = init_monitor(opts.device, opts.enable_hardware_ts);
        if(!monitor) {
                ret = 1;
                goto exit;
        }

        sv = create_SV();

        set_sv_handler(monitor, gather_records);

        SV_timestamp_file = fopen(opts.SV_filename, "w");
        if(!SV_timestamp_file) {
                ret = 2;
                goto cleanup_SV_file;
        }

        signal(SIGSTOP, stop_capture_loop);
        signal(SIGTERM, stop_capture_loop);
        signal(SIGINT, stop_capture_loop);
        signal(SIGPIPE, stop_capture_loop);

        ret = run_monitor(monitor);

cleanup_SV_file:
        if (opts.SV_filename) fclose(SV_timestamp_file);

cleanup_monitor:
        free_monitor(monitor);

exit:
        free_SV(sv);
        return ret;
}
