#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <linux/mount.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <blkid/blkid.h>
#include <libmount/libmount.h>
#include <zconf.h>
#include <zlib.h>

#include "list/list.h"
#include "log/log.h"
#include "param_list/param_list.h"
#include "platform.h"
#include "process/process.h"
#include "system/system.h"
#include "talloc/talloc.h"
#include "types/types.h"

const char *ALLOWED_FILESYSTEMS[] = {"ext2", "ext3", "ext4", "xfs", "vfat", NULL};
const char MAGIC_CFBBLK_HEADER_MAGIC[] = {'P', 'E', 'T', 'B', 'C', 'F', 'G', '\0'};
const char MAGIC_CFBBLK_BLOCK_MAGIC[] = {'B', 'L', 'K', '\0'};

const char SIGNATURE_FILE[] = "/boot/petiboot.txt";
// Some firmwares are quirky enough to not be able to handle long filenames in VFAT ...
const char CONFIG_BLOCK_PATH[] = "/boot/pbconfig.bin";
const char CONFIG_BLOCK_PATH_SAVE_TMP[] = "/boot/pbconfig.tmp";
const char CONFIG_BLOCK_PATH_TMP[] = "/tmp/pbconfig.bin";
const char ENV_CONFIG_PARTITION_UUID[] = "PETITBOOT_CONFIG_PARTITION_UUID";

#define CFGBLOCK_ATTR __attribute__ ((packed))

enum blk_type {
	BLK_UNUSED,
	BLK_KEY,
	BLK_VALUE,
	BLK_CONTINUE,
	BLKTYPES_END,
};

// 64 bytes
struct CFGBLOCK_ATTR config_block_blk {
	char		magic[4];
	uint32_t	length;
	uint32_t	blk_type;
	char		content[52];
};

// 64 bytes
struct CFGBLOCK_ATTR config_block_header {
	char		magic[8];
	uint32_t	num_blocks;
	uint32_t	crc32;
	char		padding[48];
};

struct CFGBLOCK_ATTR config_block {
	struct config_block_header	header;
	struct config_block_blk		blocks[];
};

struct search_part {
	struct list_item list;
	char *name;
	char *fstype;
};

#define BLK_SIZE (sizeof (struct config_block_blk))
#define HDR_SIZE (sizeof (struct config_block_header))
#define BLK_CONTENT_SIZE sizeof(((struct config_block_blk *)0)->content)
// Maximum file size is limited to 1MiB.
#define MAX_BLOCKS ((1 << 20) / BLK_SIZE)
#define MAX_STR_LENGTH (1 << 12)

_Static_assert((BLK_SIZE & (BLK_SIZE - 1)) == 0, "Block size must be a power of 2");
_Static_assert(BLK_SIZE == HDR_SIZE, "Header should be the same size as the blocks");

struct platform_generic {
	// Absolute path to the config block file.
	char *config_path;
	// Mount point of the filesystem.
	// Note that it is not mounted after probing for the config block.
	char *mount_point;
	// Which partition it resides on.
	char *partition;
	// Filesystem type.
	char *fstype;
	// If it is using a temporary instance.
	bool using_temp;
	struct param_list *params;
};

int load_config(struct platform *, struct config *);
int save_config(struct platform *, struct config *);
int config_save_block(const char *, const struct platform *);
int config_check_block(const char *, const struct config_block *);
int config_load_block(const char *, struct config_block **, bool);
int config_block_to_params(const struct config_block *, struct param_list **);
int search_for_config_block(struct platform_generic **);
uint32_t config_block_checksum(const struct config_block *);

static inline uint32_t div_ceil(uint32_t in, uint32_t to) {
	if (to == 0) return 1;
	if (to == 1) return in;
	return (in / to) + ((in % to) != 0);
}

static inline uint32_t roundup_by (uint32_t in, uint32_t to) {
	return to * div_ceil(in, to);
}

static inline uint32_t clamp(uint32_t in, uint32_t min, uint32_t max) {
	if (min > max)
		return clamp(in, max, min);
	if (in < min)
		return min;
	if (in > max)
		return max;
	return in;
}

static inline const struct platform_generic *to_platform_generic_const(const struct platform *p)
{
	return (const struct platform_generic *)(p->platform_data);
}

static inline struct platform_generic *to_platform_generic(struct platform *p)
{
	return (struct platform_generic *)(p->platform_data);
}

static inline int file_exists (const char *path) {
	struct stat st;
	int ret = stat (path, &st);
	if (ret == 0) return true;
	if (errno == ENOENT) return false;
	return -1;
}

static void params_update_all(struct param_list *pl,
	const struct config *config)
{
	char *tmp = NULL;
	const char *val;

	val = config->autoboot_enabled ? "true" : "false";
	param_list_set_non_empty(pl, "auto-boot?", val, true);

	val = tmp = talloc_asprintf(pl, "%d",config->autoboot_timeout_sec);
	param_list_set_non_empty(pl, "petitboot,timeout", val, true);
	if (tmp)
		talloc_free(tmp);

	val = config->lang ?: "";
	param_list_set_non_empty(pl, "petitboot,language", val, true);

	val = config->allow_writes ? "true" : "false";
	param_list_set_non_empty(pl, "petitboot,write?", val, true);

	if (!config->manual_console) {
		val = config->boot_console ?: "";
		param_list_set_non_empty(pl, "petitboot,console", val, true);
	}

	val = config->http_proxy ?: "";
	param_list_set_non_empty(pl, "petitboot,http_proxy", val, true);
	val = config->https_proxy ?: "";
	param_list_set_non_empty(pl, "petitboot,https_proxy", val, true);
	params_update_network_values(pl, "petitboot,network", config);
	params_update_bootdev_values(pl, "petitboot,bootdevs", config);
}

static int mount_helper (const char *source, const char *mountpoint, const char *fstype, unsigned long flags, bool quirk) {
	struct libmnt_context *mnt = mnt_new_context();
	bool remount = (flags & MS_REMOUNT) == MS_REMOUNT;

	int ret = 0;
	unsigned long actual_flags = flags;
	// Quirk: In order to mount read-write, mount it first then remount rw.
	if (quirk) {
		ret = mount_helper(source, mountpoint, fstype, 0, false);
		if (ret != 0) {
			pb_log("Failed to mount %s for the quirk\n", source);
			goto cleanup;
		}
		remount = true;
	}
	mnt_context_set_optsmode(mnt, MNT_OMODE_IGNORE | MNT_OMODE_NOTAB);
	if (!remount) {
		ret = mnt_context_set_source(mnt, source);
		if (ret != 0) {
			pb_log("Unable to set source: %s\n", strerror(errno));
			goto cleanup;
		}
	}

	ret = mnt_context_set_target(mnt, mountpoint);
	if (ret != 0) {
		pb_log("Unable to set target: %s\n", strerror(errno));
		goto cleanup;
	}
	if (!remount) {
		ret = mnt_context_set_fstype(mnt, fstype);
		if (ret != 0) {
			pb_log("Unable to set fstype: %s\n", strerror(errno));
			goto cleanup;
		}
	}

	mnt_context_set_mflags(mnt, actual_flags);
	mnt_context_set_options(mnt, quirk ? "rw,remount" : "rw");
	ret = mnt_context_mount(mnt);
	if (ret != 0) {
		ret = -1;
		goto cleanup;
	}
cleanup:
	if (quirk && ret != 0) {
		umount(mountpoint);
	}
	if (mnt != NULL) {
		mnt_free_context(mnt);
	}
	return ret;
}

static int save_default_config_to (const char *path) {
	if (!path || strlen (path) == 0) {
		return -1;
	}
	void *ctx = talloc_new(NULL);
	struct platform default_platform;
	struct platform_generic default_platform_generic;
	struct config *default_config = NULL;
	int ret = 0;

	if (file_exists(path) && unlink(path) != 0) {
		return -1;
	}

	// Populate config and params list with defaults.
	default_config = talloc_zero(ctx, struct config);
	config_set_defaults(default_config);
	default_platform_generic.params = talloc_zero(ctx, struct param_list);
	param_list_init(default_platform_generic.params, common_known_params());
	params_update_all(default_platform_generic.params, default_config);

	default_platform.platform_data = &default_platform_generic;
	// FIXME: talloc doesn't work when allocating some odd sized buffers ...
	default_platform_generic.config_path = talloc_zero_size(ctx, roundup_by(strlen (path), 16));
	default_platform_generic.using_temp = true;
	default_platform_generic.mount_point = NULL;
	default_platform_generic.fstype = NULL;
	default_platform_generic.partition = NULL;

	strcpy(default_platform_generic.config_path, path);
	ret = save_config(&default_platform, default_config);
	talloc_free(ctx);
	return ret;
}

static int save_temporary_config(struct platform_generic **p) {
	pb_log("A temporary file with the default configuration will be used.\n");
	// Save defaults.
	if (save_default_config_to(CONFIG_BLOCK_PATH_TMP) == 0) {
		if ((*p)->config_path) talloc_free ((*p)->config_path);
		if ((*p)->partition) talloc_free ((*p)->partition);
		if ((*p)->fstype) talloc_free ((*p)->fstype);
		if ((*p)->mount_point) talloc_free ((*p)->mount_point);
		(*p)->partition = NULL;
		(*p)->config_path = talloc_zero_size (NULL, roundup_by (strlen (CONFIG_BLOCK_PATH_TMP), 16));
		(*p)->mount_point = NULL;
		(*p)->fstype = NULL;
		(*p)->using_temp = true;
		strcpy ((*p)->config_path, CONFIG_BLOCK_PATH_TMP);
		return 0;
	} else {
		return -1;
	}
}

static int find_possible_partitions(struct list **list_parts) {
	blkid_cache cache = NULL;
	blkid_dev dev = NULL;
	blkid_dev_iterate iter_dev = NULL;
	blkid_tag_iterate iter_tag = NULL;
	const char *cur_name = NULL;
	const char *tag_type = NULL, *tag_value = NULL;
	struct search_part *cur_item;
	void *ctx = talloc_new(NULL);
	bool has_results = false;

	pb_log("Searching for possible partitions\n");
	blkid_get_cache(&cache, NULL);
	blkid_probe_all(cache);
	if (!cache) {
		talloc_free(ctx);
		return -1;
	}
	iter_dev = blkid_dev_iterate_begin(cache);
	while ((blkid_dev_next(iter_dev, &dev)) == 0) {
		cur_name = blkid_dev_devname(dev);
		if (strstr(cur_name, "/dev/md") != NULL) {
			continue;
		}
		iter_tag = blkid_tag_iterate_begin(dev);
		while (blkid_tag_next(iter_tag, &tag_type, &tag_value) == 0) {
			if (!tag_type || !tag_value) {
				pb_log("Failed to get device information for %s\n", cur_name);
				break;
			}
			if (memcmp(tag_type, "TYPE", sizeof ("TYPE")) == 0) {
				for (const char **cur_fs = ALLOWED_FILESYSTEMS; *cur_fs != NULL; cur_fs++) {
					if (strcmp(tag_value, *cur_fs) == 0) {
						pb_log("Adding %s (%s) into the search list\n", cur_name, tag_value);
						cur_item = talloc_zero(*list_parts, struct search_part);
						cur_item->name = talloc_zero_size(*list_parts, roundup_by(strlen (cur_name) + 1, 16));
						cur_item->fstype = talloc_zero_size(*list_parts, roundup_by(strlen (cur_name) + 1, 16));
						strcpy(cur_item->name, cur_name);
						strcpy(cur_item->fstype, tag_value);
						list_add_tail(*list_parts, &cur_item->list);
						has_results = true;
						goto next_dev;
					}
				}
			}
		}
	next_dev:
		blkid_tag_iterate_end(iter_tag);
	}
	blkid_dev_iterate_end(iter_dev);
	blkid_put_cache(cache);
	talloc_free (ctx);
	if (has_results) {
		return 0;
	} else {
		return -1;
	}
}

static int find_partition_by_uuid(void * ctx, const char *input, char **out, char **out_fstype) {
	size_t fstype_len = 32;
	struct stat st;
	char *full_path = NULL;
	const char *cur_fstype = NULL;
	blkid_probe pr = NULL;
	int ret = 0;
	if (!input || !out || *out != NULL) {
		return -1;
	}
	*out = NULL;
	// FAT filesystem UUID: XXXX-XXXX.
	if (!(strlen(input) == 9 || strlen(input) == 36)) {
		return -1;
	}
	if (strspn(input, "0123456789abcdefABCDEF-") != strlen (input)) {
		return -1;
	}

	full_path = talloc_asprintf(ctx, "/dev/disk/by-uuid/%s", input);
	if (fstatat(AT_FDCWD, full_path, &st, AT_SYMLINK_NOFOLLOW) != 0) {
		pb_log("Specified partition UUID '%s' is invalid: %s.\n", input, strerror(errno));
		if (errno == ENOENT)
			ret = -1;
		else
			ret = -1;
		goto cleanup;
	}
	if (!S_ISLNK(st.st_mode)) {
		pb_log("Path %s is not a symlink.\n", full_path);
		ret = -1;
		goto cleanup;
	}
	if (stat(full_path, &st) != 0) {
		pb_log("Target of symlink '%s' is invalid: %s.\n", full_path, strerror(errno));
		ret = -1;
		goto cleanup;
	}

	pr = blkid_new_probe_from_filename(full_path);
	blkid_probe_enable_partitions(pr, false);
	blkid_probe_enable_superblocks(pr, true);
	blkid_do_safeprobe(pr);
	int ret2 = blkid_probe_lookup_value(pr, "TYPE", &cur_fstype, &fstype_len);
	if (cur_fstype == NULL || ret2 != 0) {
		pb_log("Partition %s contains invalid filesystem.\n", full_path);
		ret = -1;
		goto cleanup;
	}
	for (const char **fstype = ALLOWED_FILESYSTEMS; *fstype != NULL; fstype++) {
		if (strcmp(cur_fstype, *fstype) == 0) {
			*out_fstype = talloc_zero_size(ctx, 32);
			strcpy (*out_fstype, cur_fstype);
			break;
		}
	}
	if (*out_fstype == NULL) {
		pb_log("Partition %s contains an unsupported filesystem %s\n", full_path, cur_fstype);
	}

cleanup:
	if (pr != NULL) {
		blkid_free_probe(pr);
	}
	if (ret == 0) {
		*out = full_path;

	} else {
		talloc_free (full_path);
		full_path = NULL;
	}
	return ret;
}

static int read_to_buf(char **buf, const char *path, unsigned long len) {
	FILE *handle = fopen(path, "r");

	if (!handle || len == 0) {
		return -1;
	}

	fread(*buf, len, 1, handle);
	if (ferror(handle) || strlen(*buf) == 0) {
		fclose (handle);
		return -1;
	}
	fclose (handle);
	(*buf)[len - 1] = '\0';
	return 0;
}

#ifdef __mips__
static int get_sysinfo_lefi(struct system_info **info) {
	bool success = true;
	char buf[4096] = {0}, *p = buf;
	char *token1 = NULL, *token2 = NULL;
	char *saveptr1 = NULL, *saveptr2 = NULL;
	(*info)->type = NULL;
	(*info)->identifier = talloc_zero_size(*info, 16);
	// It doesn't report system serial number.
	strcpy((*info)->identifier, "N/A");

	if (read_to_buf(&p, "/sys/firmware/lefi/boardinfo", 4096) != 0) {
		success = false;
		goto out;
	}

	// Check the first line
	token1 = strtok_r(buf, "\n", &saveptr1);
	if (token1 == NULL) {
		success = false;
		goto out;
	}

	if (strncmp(token1, "Board Info", strlen ("Board Info")) != 0) {
		success = false;
		goto out;
	}

	// Find "Board Name" line
	for (; token1 != NULL;) {
		token1 = strtok_r(NULL, "\n", &saveptr1);
		if (token1 == NULL) {
			success = false;
			goto out;
		}
		token2 = strtok_r(token1, "\t", &saveptr2);
		if (strcmp(token2, "Board Name") == 0) {
			break;
		}
	}

	if (token1 == NULL || token2 == NULL) {
		success = false;
		goto out;
	}

	for (; token2 != NULL;) {
		token2 = strtok_r(NULL, ":", &saveptr2);
		if (token2 && strchr(token2, '\t') == NULL) {
			break;
		}
	}

	if (token2 == NULL || strlen(token2) == 0) {
		success = false;
		goto out;
	}

	if (*token2 == ' ' || *token2 == '\t') {
		do {
			if (*token2 == '\0' || token2 >= buf + 4095) break;
			token2++;
		} while (*token2 == ' ' || *token2 == '\t');
	}
out:
	if (success || token2 == NULL) {
		(*info)->type = talloc_zero_size(*info, roundup_by(strlen (token2), 16));
		strcpy((*info)->type, token2);
	} else {
		(*info)->type = talloc_zero_size(*info, 32);
		strcpy((*info)->type, "Generic Loongson Platform");
	}
	return 0;
}
#endif

static char *stdout_cleaner(struct process_stdout *out)
{
	char *p;
	const char *const end = out->buf + out->len;

	for (p = out->buf; *p && p < end; p++) {
		if (*p == '\n' || *p == '\r') {
			*p = 0;
		} else if (!isprint(*p)) {
			*p = '.';
		} else if (*p == '\t') {
			*p = ' ';
		}
	}
	return out->buf;
}

static int get_sysinfo_dmi(struct system_info **info) {
	struct process_stdout *out1, *out2;

	/* Use dmidecode to get sysinfo type and identifier. */

	process_get_stdout(NULL, &out1, pb_system_apps.dmidecode,
		"--string=system-manufacturer",
		NULL);
	process_get_stdout(NULL, &out2, pb_system_apps.dmidecode,
		"--string=system-product-name",
		NULL);

	if (out1 || out2) {
		pb_log("System Vendor: %s\n", out1->buf);
		pb_log("System Product Name: %s\n", out2->buf);
		(*info)->type = talloc_asprintf(*info, "%s %s",
			out1 ? stdout_cleaner(out1) : "Generic Manufacturer",
			out2 ? stdout_cleaner(out2) : "Generic Device");
	}
	talloc_free(out1);
	talloc_free(out2);

	process_get_stdout(NULL, &out1, pb_system_apps.dmidecode,
		"--string=system-uuid",
		NULL);

	if (out1)
		(*info)->identifier = talloc_asprintf(*info, "%s",
			stdout_cleaner(out1));
	talloc_free(out1);
	return 0;
}

static int get_sysinfo_of(struct system_info **info) {
	char buf[4096] = {0}, *p = buf;
	bool success = true;
	(*info)->type = NULL;
	(*info)->identifier = NULL;

	if (read_to_buf(&p, "/sys/firmware/devicetree/base/model", 4096) != 0) {
		success = false;
		goto out;
	}

	(*info)->type = talloc_zero_size(*info, roundup_by(strlen(buf), 16));
	strcpy((*info)->type, buf);

	if (read_to_buf(&p, "/sys/firmware/devicetree/base/serial-number", 4096) != 0) {
		(*info)->identifier = talloc_zero_size(*info, 16);
		strcpy((*info)->identifier, "N/A");
	} else {
		(*info)->identifier = talloc_zero_size(*info, roundup_by(strlen(buf), 16));
		strcpy((*info)->identifier, buf);
	}
out:
	if (!success) {
		(*info)->type = talloc_zero_size(*info, 32);
		strcpy((*info)->type, "Generic DT based device");
		(*info)->identifier = talloc_zero_size(*info, 16);
		strcpy((*info)->type, "N/A");
	}
	return 0;
}

static int get_sysinfo(struct platform *p __attribute ((unused)), struct system_info *sysinfo) {
#ifdef __mips__
	if (file_exists("/sys/firmware/lefi/boardinfo")) {
		return get_sysinfo_lefi(&sysinfo);
	}
#endif
	if (file_exists("/sys/firmware/devicetree/base/model")) {
		return get_sysinfo_of(&sysinfo);
	}
	return get_sysinfo_dmi(&sysinfo);
}

static void get_active_consoles(struct config *config)
{
	config->n_consoles = 0;
	config->consoles = talloc_array(config, char *, 2);
	if (!config->consoles)
		return;

	config->consoles[0] = talloc_asprintf(config,
					"/dev/tty1 [VGA]");
	config->consoles[1] = talloc_asprintf(config,
					"/dev/ttyS0 [Serial]");
	config->n_consoles = 2;
}

int search_for_config_block(struct platform_generic **pl) {
	int ret = 0;
	char mnt_path_template[] = "/tmp/pbmntXXXXXX";
	char cur_check_path[PATH_MAX];
	struct list *list_parts;
	struct search_part part_from_env;
	struct search_part *item;
	struct search_part *tmp;
	char *devname_from_env = NULL;
	char *full_devname_from_env = NULL;
	char *fstype_dev_from_env = NULL;
	char *mnt_path = NULL;

	char **dest_partition = &(*pl)->partition;
	char **path = &(*pl)->config_path;
	char **mountpoint = &(*pl)->mount_point;
	char **fstype = &(*pl)->fstype;
	bool *using_temp = &(*pl)->using_temp;

	void *ctx = talloc_new (NULL);
	bool has_designated_dev = false;
	bool found = false;
	bool list_empty = true;

	if (*path) talloc_free (*path);
	if (*dest_partition) talloc_free (*dest_partition);
	if (*mountpoint) talloc_free (*mountpoint);
	if (*fstype) talloc_free (*fstype);
	*path = NULL;
	*dest_partition = NULL;
	*mountpoint = NULL;
	*fstype = NULL;
	*using_temp = true;

	list_parts = talloc_zero (ctx, struct list);
	list_init (list_parts);

	devname_from_env = getenv (ENV_CONFIG_PARTITION_UUID);

	if (devname_from_env == NULL || find_partition_by_uuid(ctx, devname_from_env, &full_devname_from_env, &fstype_dev_from_env) != 0) {
		ret = find_possible_partitions (&list_parts);
		if (ret != 0) {
			return -1;
		} else {
			list_empty = false;
		}
	} else {
		pb_log("Specified partition %s is valid.\n", full_devname_from_env);
		part_from_env.name = full_devname_from_env;
		part_from_env.fstype = fstype_dev_from_env;
		list_add_tail(list_parts, &part_from_env.list);
		list_empty = false;
		has_designated_dev = true;
	}
	if (list_empty) {
		*using_temp = true;
		return -1;
	}
	pb_log("Search list:\n");
	list_for_each_entry_safe(list_parts, item, tmp, list) {
		pb_log("- %s (%s)\n", item->name, item->fstype);
	}
	mnt_path = mkdtemp(mnt_path_template);
	if (mnt_path == NULL) {
		pb_log("Failed to mkdir temporary mount point: %s\n", strerror (errno));
		talloc_free (ctx);
		return -1;
	}
	pb_log("Mount point: %s\n", mnt_path);
	list_for_each_entry_safe(list_parts, item, tmp, list) {
		pb_log("Checking for %s\n", item->name);
		if (mount_helper(item->name, mnt_path, item->fstype, 0, false) != 0) {
			pb_log("Failed to mount partition %s (%s): %s\n", item->name, item->fstype, strerror (errno));
			continue;
		}
		snprintf(cur_check_path, PATH_MAX, "%s/%s", mnt_path, SIGNATURE_FILE);
		if (file_exists(cur_check_path) != true) {
			if (has_designated_dev &&
				strcmp(item->name, full_devname_from_env) == 0) {
				// Create the signature file.
				pb_log("Signature file isn't found in the specified partition, creating.\n");
				char *bootdir = talloc_asprintf(NULL, "%s/boot", mnt_path);
				pb_mkdir_recursive(bootdir);
				talloc_free(bootdir);
				char *sigfile = talloc_asprintf(NULL, "%s/%s", mnt_path, SIGNATURE_FILE);
				FILE *f = fopen(sigfile, "w+");
				if (f == NULL) {
					pb_log("Failed to create the signature file at %s: %s\n", item->name, strerror(errno));
					talloc_free (sigfile);
					goto next;
				}
				fclose(f);
				talloc_free (sigfile);
			} else {
				goto next;
			}
		}
		// Signature file exists. Check if the param block file exists.
		snprintf(cur_check_path, PATH_MAX, "%s/%s", mnt_path, CONFIG_BLOCK_PATH);
		if (file_exists(cur_check_path) != true) {
			// Signature file exists, but the block file itself isn't.
			// Probably it is the first boot. Initialize.
			pb_log("Parameter block file isn't found in the specified partition, creating one with default configuration.\n");
			if (save_default_config_to(cur_check_path) != 0) {
				pb_log("Failed to save default configuration at %s: %s\n", cur_check_path, strerror (errno));
				goto next;
			}
		}

		// We have both the signature and the param block.
		*dest_partition = talloc_zero_size (*pl, roundup_by(strlen (item->name) + 1, 16));
		*path = talloc_zero_size (*pl, roundup_by(strlen (CONFIG_BLOCK_PATH) + 1, 16));
		*mountpoint = talloc_zero_size (*pl, roundup_by(strlen (mnt_path) + 1, 16));
		*fstype = talloc_zero_size (*pl, roundup_by(strlen (item->fstype), 16));

		strcpy (*dest_partition, item->name);
		strcpy (*path, CONFIG_BLOCK_PATH);
		strcpy (*mountpoint, mnt_path);
		strcpy (*fstype, item->fstype);

		*using_temp = false;
		found = true;
next:
		if (umount(mnt_path) != 0) {
			pb_log("Failed to unmount %s: %s\n", item->name, strerror (errno));
		}
		if (found) {
			break;
		}
	}
	if (!found) {
		pb_log("Couldn't find any partitions that can be used as the configuration partition.\n");
		talloc_free(ctx);
		return -1;
	}
	talloc_free(ctx);
	return 0;
}

int config_block_to_params(const struct config_block *cfg, struct param_list **list) {
	char *cur_key = NULL, *cur_value = NULL, *cur_str = NULL;
	uint32_t cur_len = 0;
	uint32_t cur_type = BLK_UNUSED;
	void *ctx = talloc_new(NULL);
	int ret = -1;

	const struct config_block_blk *cursor = cfg->blocks;

	if (list == NULL || *list == NULL) {
		return -1;
	}
	if (cfg == NULL) {
		return -1;
	}

	for (uint32_t i = 0; i < cfg->header.num_blocks;) {
		cur_len = le32toh(cursor->length);
		cur_type = le32toh(cursor->blk_type);
		if (cur_type == BLK_UNUSED) {
			if (cur_key != NULL) {
				pb_log("Expecting a value block after a key block, found terminator\n");
				ret = -1;
				break;
			}
			pb_log("Read %d blocks.\n", i);
			ret = 0;
			break;
		}
		if (cur_type != BLK_KEY && cur_type != BLK_VALUE) {
			// Then the checks failed their job ...
			// Continuation blocks should never appear at this point.
			pb_log("Invalid block encountered at block %d\n", i);
			goto cleanup;
		}
		if (cur_len >= MAX_STR_LENGTH) {
			pb_log("Content starting at block %d is too long\n", i);
			goto cleanup;
		}
		pb_log ("Reading block %d, type %d, length %d\n", i, cur_type, cur_len);
		cur_str = talloc_zero_size (ctx, roundup_by(cur_len + 1, BLK_CONTENT_SIZE));
		if (cur_str == NULL) {
			goto cleanup;
		}
		if (cur_type == BLK_KEY) {
			if (cur_key != NULL) {
				pb_log("Expecting a key block after a value at block %d\n", i);
				goto cleanup;
			}
			cur_key = cur_str;
		}
		if (cur_type == BLK_VALUE) {
			if (cur_value != NULL) {
				pb_log("Expecting a value block after a key at block %d\n", i);
				goto cleanup;
			}
			cur_value = cur_str;
		}
		for (uint32_t copied = 0; copied < cur_len; copied += BLK_CONTENT_SIZE) {
			pb_log ("Reading block %d, type %d, length remaining %d\n", i, le32toh(cursor->blk_type), le32toh(cursor->length));
			if (copied > 0 && le32toh(cursor->blk_type) != BLK_CONTINUE) {
				pb_log("Expecting more data at block %d\n", i);
				goto cleanup;
			}
			if (le32toh(cursor->length) != cur_len - copied) {
				pb_log("Invalid block encountered at block %d\n", i);
				goto cleanup;
			}
			uint32_t copy_len = clamp (cur_len - copied, 0, BLK_CONTENT_SIZE);
			memcpy (cur_str + copied, cursor->content, copy_len);
			cursor += 1;
			i += 1;
		}
		// Since we always allocate one more byte, we can force that byte to zero.
		cur_str[cur_len] = '\0';
		if (cur_key && cur_value) {
			pb_log ("Read key '%s' = '%s'\n", cur_key, cur_value);
			// It uses talloc_strdup().
			param_list_set (*list, cur_key, cur_value, false);
			talloc_free (cur_key);
			talloc_free (cur_value);
			cur_key = NULL;
			cur_value = NULL;
		}
		cur_str = NULL;
	}

cleanup:
	talloc_free (ctx);
	return ret;
}

uint32_t config_block_checksum(const struct config_block *blk) {
	struct config_block_header hdr;
	uint32_t crc = crc32(0, NULL, 0);
	const struct config_block_blk *cursor = blk->blocks;

	memcpy(&hdr, &blk->header, sizeof (struct config_block_header));
	hdr.crc32 = 0;
	crc = crc32(crc, (void *)&hdr, sizeof (struct config_block_header));

	for (uint32_t i = 0; i < hdr.num_blocks; i++) {
		crc = crc32(crc, (void *)&cursor[i], sizeof (struct config_block_blk));
	}

	return crc;
}

int config_check_block (const char *path, const struct config_block *config) {
	const struct config_block_header *header = &config->header;
	if (le32toh(header->crc32) != config_block_checksum(config)) {
		pb_log("Checksum failed for %s\n", path);
		return -1;
	}
	bool last_unterminated = false;
	bool check_err = false;
	bool current_is_key = true;
	unsigned int check_index = 0;

	if (config->header.num_blocks == 0) {
		return -1;
	}

	for (; check_index < header->num_blocks; check_index++) {
		const struct config_block_blk *cur = &config->blocks[check_index];
		int cur_type = le32toh(cur->blk_type);
		if (cur_type >= BLKTYPES_END) {
			pb_log("Invalid block type at block %d\n", check_index);
			check_err = true;
			goto out;
		}
		if (cur_type == BLK_UNUSED) {
			break;
		}
		if (last_unterminated && cur_type != BLK_CONTINUE) {
			pb_log("Block %d should be a continuation block for a %s block\n", check_index,
				current_is_key ? "key" : "value");
			check_err = true;
			goto out;
		}
		if (current_is_key && cur_type != (last_unterminated ? BLK_CONTINUE : BLK_KEY)) {
			pb_log("Block %d should be a key block\n", check_index);
			check_err = true;
			goto out;
		}
		if (!current_is_key && cur_type != (last_unterminated ? BLK_CONTINUE : BLK_VALUE)) {
			pb_log("Block %d should be a value block\n", check_index);
			check_err = true;
			goto out;
		}
		if (memcmp(cur->magic, MAGIC_CFBBLK_BLOCK_MAGIC, sizeof (MAGIC_CFBBLK_BLOCK_MAGIC)) != 0) {
			check_err = true;
			goto out;
		}
		if (cur->content[(sizeof (cur->content) - 1)] != '\0') {
			last_unterminated = true;
		} else {
			last_unterminated = false;
		}
		current_is_key = !current_is_key;
	}
out:
	if (check_err) {
		pb_log("Inavlid block encountered at block %u\n", check_index);
	}
	return check_err? -1 : 0;
}

int config_save_block(const char *path, const struct platform *p) {
	int ret = 0;
	if (p == NULL || path == NULL) {
		return -1;
	}
	char save_path[PATH_MAX] = {0};
	struct config_block *cfg_block = NULL;
	struct config_block_blk *blks = NULL;
	struct config_block_blk *cursor = NULL;
	struct param *param = NULL;
	FILE *tgt = NULL;
	const struct platform_generic *pl = NULL;
	pl = to_platform_generic_const (p);
	uint32_t num_blocks = 0;
	uint32_t crc32 = 0;
	bool needs_update = false;
	struct config_block_header *header = NULL;

	param_list_for_each (pl->params, param) {
		if (param->modified) {
			needs_update = true;
		}
		num_blocks += div_ceil (strlen (param->name) + 1, BLK_CONTENT_SIZE);
		num_blocks += div_ceil (strlen (param->value) + 1, BLK_CONTENT_SIZE);
	};

	if (!needs_update) {
		pb_log("No need to write as the config hasn't been changed.\n");
		return 0;
	}

	// Align the whole file to 1KiB:
	// Add one for a BLK_UNUSED (terminator), then align,
	// Then subtract one for the header.
	num_blocks = (16 * div_ceil(num_blocks + 1, 16)) - 1;
	if (num_blocks + 1 > MAX_BLOCKS) {
		pb_log("Parameter list is too long\n");
		ret = -1;
		goto cleanup;
	}

	cfg_block = talloc_zero_size(NULL, HDR_SIZE + (BLK_SIZE * num_blocks));
	if (cfg_block == NULL) {
		pb_log ("ERROR: Failed to allocate a config block\n");
		ret = -1;
		goto cleanup;
	}

	header = &cfg_block->header;
	memcpy (header->magic, MAGIC_CFBBLK_HEADER_MAGIC, sizeof (MAGIC_CFBBLK_HEADER_MAGIC));
	header->num_blocks = num_blocks;

	blks = cfg_block->blocks;
	cursor = blks;
	for (uint32_t i = 0; i < num_blocks; i++) {
		memcpy(blks[i].magic, MAGIC_CFBBLK_BLOCK_MAGIC, sizeof (MAGIC_CFBBLK_BLOCK_MAGIC));
		blks[i].blk_type = htole32(BLK_UNUSED);
	}

	param_list_for_each (pl->params, param) {
		bool save_is_key = true;
		do {
			char *s = save_is_key ? param->name : param->value;
			enum blk_type cur_type = save_is_key ? BLK_KEY : BLK_VALUE;
			// Includes the null terminator.
			uint32_t content_len = strlen (s) + 1;
			uint32_t cur_copy_len = 0;

			for (uint32_t i = 0; i < content_len; i += BLK_CONTENT_SIZE) {
				cursor->blk_type = htole32(i > 0 ? BLK_CONTINUE : cur_type);
				// Full length for the first block; otherwise the remaining length
				cursor->length = htole32(content_len - i);

				cur_copy_len = clamp (content_len - i, 0, BLK_CONTENT_SIZE);
				memcpy (cursor->content, s + i, cur_copy_len);
				// Advance one block
				cursor++;
			}
			save_is_key = !save_is_key;
		} while (!save_is_key);
	}
	crc32 = config_block_checksum(cfg_block);
	pb_log("CRC32: 0x%08x\n", crc32);
	cfg_block->header.crc32 = htole32(crc32);

	if (!pl->using_temp) {
		snprintf(save_path, PATH_MAX, "%s/%s", pl->mount_point, CONFIG_BLOCK_PATH_SAVE_TMP);
	} else {
		strcpy (save_path, path);
	}
	tgt = fopen(save_path, "wb+");
	if (tgt == NULL) {
		pb_log("Failed to create config block file '%s': %s\n", path, strerror (errno));
		ret = -1;
		goto cleanup;
	}
	if (fwrite(header, HDR_SIZE, 1, tgt) != 1) {
		pb_log("fwrite() error while writing the header into the config block file\n");
		ret = -1;
		goto cleanup;
	}
	if (fwrite(blks, BLK_SIZE, num_blocks, tgt) != num_blocks) {
		pb_log("fwrite() error while writing the blocks into the config block file\n");
		ret = -1;
		goto cleanup;
	}
	if (fflush(tgt) == EOF) {
		pb_log("Failed to commit the block: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	};

	if (!pl->using_temp) {
		if (rename(save_path, path) != 0) {
			pb_log("Failed to rename the new config file.\n");
			ret = -1;
		}
	}
cleanup:
	if (tgt != NULL) {
		fclose(tgt);
	}
	if (cfg_block != NULL) {
		talloc_free(cfg_block);
	}
	return ret;
}

int config_load_block(const char *path, struct config_block **config, bool after_error) {
	int ret = 0;
	FILE *tgt = NULL;
	struct config_block_header header;
	struct stat tgt_info;
	unsigned int actual_num_blocks;
	memset(&header, 0, sizeof (header));
	if (config == NULL) {
		ret = -1;
		return ret;
	}
	if (*config != NULL) {
		// Since its size is variable, we can not guarantee the
		// size of the buffer is correct.
		// Refuse to continue if the target is non-null.
		ret = -1;
		return ret;
	}
	tgt = fopen(path, "rb");
	if (tgt == NULL) {
		pb_log("Failed to open the config block file: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	if (stat(path, &tgt_info) != 0) {
		pb_log("Unable to retrieve information of the config block file: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	actual_num_blocks = (tgt_info.st_size / BLK_SIZE) - 1;
	if (fread(&header, sizeof (header), 1, tgt) != 1) {
		pb_log("fread() error while trying to read the header\n");
		ret = -1;
		goto cleanup;
	}
	if (memcmp(header.magic, MAGIC_CFBBLK_HEADER_MAGIC, 8) != 0) {
		pb_log("Invalid header found in config block file\n");
		ret = -1;
		goto cleanup;
	}
	if (actual_num_blocks != le32toh(header.num_blocks)) {
		pb_log("Encountered inconsistent header when reading: %d blocks vs expected %d\n", actual_num_blocks, le32toh(header.num_blocks));
		ret = -1;
		goto cleanup;
	}
	if (actual_num_blocks + 1 > MAX_BLOCKS) {
		pb_log("File too large\n");
		ret = -1;
		goto cleanup;
	}

	*config = talloc_zero_size(NULL, BLK_SIZE * (actual_num_blocks + 1));
	if (*config == NULL) {
		pb_log("Failed to allocate memory for the config block\n");
		ret = -1;
		goto cleanup;
	}

	memcpy(&(*config)->header, &header, HDR_SIZE);
	if (fread((*config)->blocks, BLK_SIZE, actual_num_blocks, tgt) != actual_num_blocks) {
		pb_log("Error encountered when reading config block: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}

	ret = config_check_block(path, *config);
	if (ret != 0 && !after_error) {
		// Check failed - save a copy with default settings
		pb_log("Integrity check failed - restoring defaults\n");
		talloc_free (*config);
		*config = NULL;
		if (save_default_config_to(path) == 0) {
			ret = config_load_block(path, config, true);
		}
		goto cleanup;
	} else if (ret != 0) {
		// Nothing else we can do ...
		pb_log("Integrity failed after saving defaults.\n");
	}

cleanup:
	if (tgt) {
		fclose(tgt);
	}
	if (*config != NULL && ret != 0) {
		talloc_free(*config);
		*config = NULL;
	}
	return ret;
}

static bool probe(struct platform *p, void *ctx) {
	struct platform_generic *platform = talloc_zero_size(ctx, sizeof (struct platform_generic));

	if (platform == NULL) {
		return false;
	}

	p->platform_data = platform;

	int ret = search_for_config_block(&platform);
	if (ret) {
		// Initialize the temporary instance
		pb_debug("Unable to find a suitable partition to store the block file.\n");
		platform->using_temp = true;
		goto verdict;
	}
	if (!platform->using_temp) {
		pb_log("Using file %s from %s\n", platform->config_path, platform->partition);
		if (pb_mkdir_recursive(platform->mount_point) != 0) {
			pb_log("Failed to create the mount point\n");
			platform->using_temp = true;
			goto verdict;
		};
	}

verdict:
	platform->params = talloc_zero(platform, struct param_list);
	param_list_init(platform->params, common_known_params());
	if (platform->using_temp) {
		pb_debug("A temporary config file will be used.\n");
		return save_temporary_config(&platform) == 0 ? true : false;
	}
	return true;
}

int load_config(struct platform *p, struct config *config) {
	struct platform_generic *platform = to_platform_generic(p);
	struct param_list *pl = platform->params;
	struct config_block *cfg = NULL;
	char load_path[PATH_MAX] = {0};
	struct param *param;
	bool load_failed = false;

	if (platform->using_temp) {
		strcpy (load_path, platform->config_path);
	} else {
		if (mount_helper(platform->partition, platform->mount_point, platform->fstype, 0, false) != 0) {
			pb_log("Failed to mount %s: %s\n", platform->partition, strerror (errno));
			// We can still use a temporary file
			load_failed = true;
			goto out;
		}
		snprintf(load_path, PATH_MAX - 1, "%s/%s", platform->mount_point, platform->config_path);
	}

	if (config_load_block(load_path, &cfg, false) != 0) {
		pb_log("Failed to load %s on %s\n.\n", platform->config_path, platform->partition);
		load_failed = true;
		goto out;
	};

	if (config_block_to_params(cfg, &pl) == 0) {
		param_list_for_each(pl, param) {
			pb_log ("Param '%s' = '%s'\n", param->name, param->value);
		}
		config_populate_all(config, pl);
		get_active_consoles(config);
	} else {
		// Ignore the error, use a temporary file this time.
		// Next boot will use the initialized defaults.
		save_default_config_to(load_path);
		load_failed = true;
	}
out:
	if (cfg) {
		talloc_free(cfg);
	}
	if (!platform->using_temp) {
		if (umount(platform->mount_point) != 0) {
			pb_log("Failed to umount %s: %s\n", platform->mount_point, strerror (errno));
		}
		if (load_failed) {
			if (save_temporary_config(&platform) != 0) {
				return -1;
			}
			return load_config(p, config);
		}
	}
	return load_failed ? -1 : 0;
}

int save_config(struct platform *p, struct config *config) {
	struct platform_generic *platform = to_platform_generic(p);
	struct param_list *pl = platform->params;
	struct config *defaults;
	char save_path[PATH_MAX] = {0};

	defaults = talloc_zero(NULL, struct config);
	config_set_defaults(defaults);

	if (config == NULL) {
		pb_log("Saving default configuration ...\n");
		params_update_all(pl, defaults);
	} else {
		pb_log("Saving updated configuration ...\n");
		params_update_all(pl, config);
	}
	talloc_free(defaults);

	if (platform->using_temp) {
		strcpy (save_path, platform->config_path);
	} else {
		if (mount_helper(platform->partition, platform->mount_point, platform->fstype, 0, true) != 0) {
			pb_log("Failed to mount %s read-write: %s\n", platform->partition, strerror (errno));
			return -1;
		}
		snprintf(save_path, PATH_MAX - 1, "%s/%s", platform->mount_point, platform->config_path);
	}

	pb_log("Saving to file %s\n", save_path);
	int ret = config_save_block(save_path, p);

	if (!platform->using_temp) {
		if (umount(platform->mount_point) != 0) {
			pb_log("Failed to umount %s: %s\n", platform->mount_point, strerror (errno));
		}
	}

	return ret;
}

struct platform platform_generic = {
	.name		= "generic",
	.probe		= probe,
	.get_sysinfo	= get_sysinfo,
	.load_config	= load_config,
	.save_config	= save_config,
};

register_platform (platform_generic);
