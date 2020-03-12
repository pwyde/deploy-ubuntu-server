# Deploy Ubuntu Server

## About
A collection of scripts and configuration files used to quickly deploy a minimal [Ubuntu Server](https://ubuntu.com/server) installation.

## Disclaimer
Scripts are written for [Bash](https://www.gnu.org/software/bash/) and must be executed in this shell. They are designed for and tested on **Ubuntu 18.04 LTS** only!

Please note that these scripts are not designed to accommodate all types of hardware, installation and configuration options. Installation script is made to suite a specific use case and contain configuration options that are specific for the destination server, i.e. locale. System hardening that is performed by configuration script is not official common best practices and are subject to debate and changes in the future.

## install-ubuntu-zfs-root.sh
This script deploys a minimal Ubuntu Server installation with [ZFS](https://zfsonlinux.org/) on root with [LUKS](https://gitlab.com/cryptsetup/cryptsetup/) encryption.

Script is designed to install the following resulting configured system:
- [UEFI](https://wiki.archlinux.org/index.php/Unified_Extensible_Firmware_Interface) booting.
- Boot partition (`/boot`) is a ZFS pool (`bpool`) on a two drive ZFS mirror.
- Root partition (`/`) is a ZFS pool (`rpool`) on a two drive ZFS mirror encrypted with LUKS.

### Disk & Partition Scheme
Script is designed to be used on a [UEFI](https://wiki.archlinux.org/index.php/Unified_Extensible_Firmware_Interface) system only. No legacy BIOS support, hence no Master Boot Record (MBR) will be created. It will automatically partition the disks with the following scheme.

```
+---------------------------------------------------------------------------+
| /dev/disk/by-id/ata|nvme|scsi-Manufacturer_Model_Number                   |
+-------------------+-------------------------------------------------------+
| ESP partition:    | ZFS mirror (bpool) | Linux filesystem partition:      |
+-------------------+-------------------------------------------------------+
| 550 MB            | 2 GB               | Remaining disk space             |
|                   |                    |                                  |
| Not encrypted     | Not encrypted      | Encrypted                        |
+-------------------+-------------------------------------------------------+
```

### Disk & dm-crypt/LUKS Encrypted ZFS Pool Configuration
The EFI System Partition ([ESP](https://wiki.archlinux.org/index.php/EFI_system_partition)) is mounted to `/boot/efi`. The boot (`/boot`) partition is a ZFS mirror pool (`bpool`). The root (`/`) partition is also a ZFS mirror pool (`rpool`) encrypted with dm-crypt/LUKS (`crypt-root1/2`).

```
ZFS mirror:
  ata|nvme|scsi-Manufacturer_Model_Number-part1
   └─ ESP (/boot/efi)
  ata|nvme|scsi-Manufacturer_Model_Number-part2
   └─ ZFS pool (bpool -> /boot)
  ata|nvme|scsi-Manufacturer_Model_Number-part3
   └─ crypt-root (/)
       └─ ZFS pool (rpool)
```

### ZFS Dataset Configuration
The following [ZFS datasets](https://wiki.archlinux.org/index.php/ZFS#Creating_datasets) will be automatically created during installation.

| **Name**                |  **Mountpoint**    |
| ---                     | ---                |
| `rpool`                 | `/`                |
| `rpool/ROOT`            | none               |
| `rpool/ROOT/ubuntu`     | `/boot`            |
| `rpool`                 | `/`                |
| `rpool/ROOT`            | none               |
| `rpool/ROOT/ubuntu`     | `/`                |
| `rpool/home`            | `/home`            |
| `rpool/home/root`       | `/root`            |
| `rpool/srv`             | `/srv`             |
| `rpool/var`             | `/var`             |
| `rpool/var/cache`       | `/var/cache`       |
| `rpool/var/lib`         | `/var/lib`         |
| `rpool/var/lib/docker`  | `/var/lib/docker`  |
| `rpool/var/lib/nfs`     | `/var/lib/nfs`     |
| `rpool/var/log`         | `/var/log`         |
| `rpool/var/snap`        | `/var/snap`        |
| `rpool/var/spool`       | `/var/spool`       |
| `rpool/var/tmp`         | `/var/tmp`         |
| `rpool/var/www`         | `/var/www`         |

### Preperation
Prior to script execution, boot into **Ubuntu Desktop Live CD** environment.

Set a password for the buil-in user.
```
$ passwd
```

Install **SSH server** and **Git** in the live CD environment.
```
$ sudo apt update
$ sudo apt install --yes openssh-server git
```

Obtain **IPv4 address** assigned by DHCP.
```
$ ip addr show
```

Connect to the host system using SSH.
```
$ ssh ubuntu@<ipv4>
```

Become **root**.
```
$ sudo -i
# cd ~
```

Download Git repository.
```
# git clone https://github.com/pwyde/deploy-ubuntu-server.git
# cd deploy-ubuntu-server
```

Execute install script.
```
# bash install-ubuntu-zfs-root.sh --install
```

## configure-ubuntu-server.sh
Script performs post-deployment configuration on a newly installed Ubuntu server. Used for installing utilities/tools and basic system hardening.

Script performs the following configuration changes:
- Update package database and upgrade system.
- Install common packages.
- Create regular user account.
- Set default editor.
- Configure SSH.
  - SSH daemon and client hardening.
  - Creates dedicated SSH user group and adds specified user to group.
- Configure system networking.
- Configure welcome message/banner.
- Disable log compression. Assumes ZFS root partition, hence compression is already performed by the filesystem.
- Configure file and inode limits.
- Configure journal size limit.
- Disable core dumps.
- Set a timeout session for sudo sessions.
- TCP/IP stack hardening.
- Restrict access to kernel logs.
- Disable Speck kernel module.
- Disable the root password.

### Options
| **Option**          | **Description**                                                                 |
| ---                 | ---                                                                             |
| `-a`,`--apply`      | Apply system configuration and hardening included in script.                    |
| `-n`,`--net-config` | Specify a specific Netplan configuration file that will be applied on the host. |
| `-h`,`--help`       | Display help message including available options.                               |

## Credits
Script is based from and inspired by the following sources:
- [ZFS root on Ubuntu with LUKS encryption and USB boot](https://www.coolgeeks101.com/howto/infrastructure/zfs-root-ubuntu-luks-encryption-usb-boot/)
- [Ubuntu 18.04 Root on ZFS](https://github.com/zfsonlinux/zfs/wiki/Ubuntu-18.04-Root-on-ZFS)
- [vrivellino/install-ubuntu.sh](https://gist.github.com/vrivellino/7dcf150da4cc1d07008315643bfdbfb5)
