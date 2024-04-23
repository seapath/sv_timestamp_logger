/**
 * \file sv_timestamp_logger.h
 * \brief Tool to timstamp received SV pcaps
 *
 * \copyright Copyright (C) 2024 Savoir-faire Linux, Inc
 * \license SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <netinet/in.h>

struct sv_timestamp_logger_opts {
    char * device;
    int enable_hardware_ts;
    char *stream;
    char * SV_filename;
    int first_SV_cnt;
    int max_SV_cnt;
    char log_only_SV_cnt_0;
};
