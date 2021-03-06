/*
 * Copyright (C) 2018-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: bios.h
 *      Header for BIOS event log.
 */

/**
 * \addtogroup bios-event-log-api
 *  @{
 */

#ifndef _EVENT_LOG_BIOS_H
#define _EVENT_LOG_BIOS_H

#include "event_log.h"

#define MAX_EVENT_SIZE 200000
#define EVENT_HEADER_SIZE 32
#define MAX_EVENT_DATA_SIZE (MAX_EVENT_SIZE - EVENT_HEADER_SIZE)

struct bios_template_entry {
	struct {
		uint32_t pcr;
		uint32_t type;
		uint8_t digest[SHA_DIGEST_LENGTH];
		uint32_t len;
	} __attribute__((packed)) header;
	unsigned char data[0];
};

struct bios_log_entry {
	struct bios_template_entry *entry;
};

#endif /*_EVENT_LOG_BIOS_H*/
/** @}*/
