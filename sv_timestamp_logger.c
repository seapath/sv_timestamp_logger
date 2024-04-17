/**
 * \file sv_timestamp_logger.c
 * \brief Tool to timstamp received SV pcaps
 *
 * \copyright Copyright (C) 2024 Savoir-faire Linux, Inc
 * \license SPDX-License-Identifier: Apache-2.0
 */

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
        { 0, 0, 0, 0 }
};

static const char * const HELP_MSG_FMT =
        "Usage: %s <-d|--device <device>> [s|--stream <name>] [-t|--hardware_timestamping] [-f| --filename] <--first_SV_cnt <cnt>> <--max_SV_cnt <cnt>>\n"
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
;

/*  Global Variables */
static struct sv_timestamp_logger_opts opts;
static struct sv_monitor * volatile monitor; // volatile because may be used
                                             // from a signal handler
static FILE * SV_timestamp_file;
static struct SV_payload *sv;

static int compute_SV_drop;


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

        while ((opt = getopt_long(argc, argv, "htd:s:n:f:c:m:", long_options,
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
                case '?':
                        fprintf(stderr, "Invalid option: -%c\n", optopt);
                        print_help(argv[0]);
                        return 1;
                }
        }

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

static void gather_records(const struct pcap_pkthdr *header,
                           const uint8_t *packet)
{
        parse_SV_payload(packet + sizeof(struct ethhdr) + 4*sizeof(uint8_t), sv);

        struct timeval timestamp;

        if(opts.enable_hardware_ts) {
                timestamp = header->ts;
        } else {
                get_ts(&timestamp);
        }

        if(opts.stream == NULL){ // if no stream has been selected
                fprintf(SV_timestamp_file, "%s:%d:%ld\n",
                        sv->seqASDU[0].svID,
                        sv->seqASDU[0].smpCnt,
                        (timestamp.tv_sec * 1000 * 1000)
                        + (timestamp.tv_usec));

        } else if(!strcmp(sv->seqASDU[0].svID, opts.stream)){
                fprintf(SV_timestamp_file, "%s:%d:%ld\n",
                        sv->seqASDU[0].svID,
                        sv->seqASDU[0].smpCnt,
                        (timestamp.tv_sec * 1000 * 1000)
                        + (timestamp.tv_usec));
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
