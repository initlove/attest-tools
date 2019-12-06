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

/* kernel types */
typedef u_int8_t u8;
typedef u_int16_t u16;
typedef u_int32_t u32;
typedef u_int64_t u64;
#ifndef bool
typedef int bool;
#endif

#define __packed __attribute__((packed));

#define TPM_DIGEST_SIZE 20	/* Max TPM v1.2 PCR size */
#define TPM_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE

struct tpm_digest {
	u16 alg_id;
	u8 digest[TPM_MAX_DIGEST_SIZE];
} __packed;

struct tpm_digest_ptr {
	u16 alg_id;
	u32 digest_size;
	u8 *digest_ptr;
};

enum bios_platform_class {
	BIOS_CLIENT = 0x00,
	BIOS_SERVER = 0x01,
};

struct tcpa_event {
	u32 pcr_index;
	u32 event_type;
	u8 pcr_value[20];	/* SHA1 */
	u32 event_size;
	u8 event_data[0];
};

enum tcpa_event_types {
	PREBOOT = 0,
	POST_CODE,
	UNUSED,
	NO_ACTION,
	SEPARATOR,
	ACTION,
	EVENT_TAG,
	SCRTM_CONTENTS,
	SCRTM_VERSION,
	CPU_MICROCODE,
	PLATFORM_CONFIG_FLAGS,
	TABLE_OF_DEVICES,
	COMPACT_HASH,
	IPL,
	IPL_PARTITION_DATA,
	NONHOST_CODE,
	NONHOST_CONFIG,
	NONHOST_INFO,
};

struct tcpa_pc_event {
	u32 event_id;
	u32 event_size;
	u8 event_data[0];
};

enum tcpa_pc_event_ids {
	SMBIOS = 1,
	BIS_CERT,
	POST_BIOS_ROM,
	ESCD,
	CMOS,
	NVRAM,
	OPTION_ROM_EXEC,
	OPTION_ROM_CONFIG,
	OPTION_ROM_MICROCODE = 10,
	S_CRTM_VERSION,
	S_CRTM_CONTENTS,
	POST_CONTENTS,
	HOST_TABLE_OF_DEVICES,
};

/* http://www.trustedcomputinggroup.org/tcg-efi-protocol-specification/ */

struct tcg_efi_specid_event_algs {
	u16 alg_id;
	u16 digest_size;
} __packed;

struct tcg_efi_specid_event_head {
	u8 signature[16];
	u32 platform_class;
	u8 spec_version_minor;
	u8 spec_version_major;
	u8 spec_errata;
	u8 uintnsize;
	u32 num_algs;
	struct tcg_efi_specid_event_algs digest_sizes[];
} __packed;

struct tcg_pcr_event {
	u32 pcr_idx;
	u32 event_type;
	u8 digest[20];
	u32 event_size;
	u8 event[0];
} __packed;

struct tcg_event_field {
	u32 event_size;
	u8 event[0];
} __packed;

struct tcg_pcr_event2_head {
	u32 pcr_idx;
	u32 event_type;
	u32 count;
	struct tpm_digest digests[];
} __packed;

struct bios_log_entry {
	void *entry;
};

#endif /*_EVENT_LOG_BIOS_H*/
/** @}*/
