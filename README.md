Petitboot with file backed parameter storage
============================================

[Original README](./README.original.md)

This Petitboot fork enables devices without proper NVRAM support to use a file as the configuration storage.

It uses a block based format to store the configuration data (everything in the "System Configuration" menu), thus it is not human-readable.

Usage
=====

> [!NOTE]
> It is recommended to build this Petitboot environment with Buildroot.

1. Enable `BR2_PACKAGE_UTIL_LINUX_LIBMOUNT`, `BR2_PACKAGE_UTIL_LINUX_LIBBLKID` and `BR2_PACKAGE_ZLIB`.
2. Apply [the diff](https://github.com/open-power/petitboot/compare/master...Cyanoxygen:petitboot:cyan/master.patch) ([View the diff in GitHub UI here](https://github.com/open-power/petitboot/compare/master...Cyanoxygen:petitboot:cyan/master)).
   - You can download the patch into `packages/petitboot/` with a `.patch` extension.
3. Add `PETITBOOT_AUTORECONF = YES` at the beginning section of `packages/petitboot/petitboot.mk`, since the patch modifies `configure.ac`.
4. Enable the petitboot package.
5. Run `make petitboot-dirclean && make` to build.
6. To specify a filesystem for the config block file, either:
   - Create an empty file `/boot/petitboot.txt` in the filesystem to signify that this filesystem is available to Petitboot.
   - Add `PETITBOOT_CONFIG_BLOCK_PARTITION_UUID=UUID_HERE` to the kernel command line arguments. It supports FAT volume IDs in `ABCD-ABCD` format and GUIDs as seen in other filesystems.
7. Boot the built initramfs image, it will initialize a config block file with default settings at `/boot/pbconfig.bin`.
8. Try changing a setting and saving.

Notes
=====

This fork is intended for MIPS Loongson devices with a PMON firmware, or an early "Loongson EFI (LEFI)" firmware. Petitboot being able to parse GRUB configuration file makes it feasible.
