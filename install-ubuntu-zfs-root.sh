#!/usr/bin/env bash

# Install script for Ubuntu Server with ZFS on root, LUKS encryption
# and USB boot.
# Copyright (C) 2019 Patrik Wyde <patrik@wyde.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Print commands and their arguments as they are executed.
#set -x
# Exit immediately if a command exits with a non-zero exit status.
set -e

# Configure script variables.
git_repo="deploy-ubuntu-server"
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
install="false"
post_install="false"
## Disk drive IDs (symlinks in /dev/disk/by-id).
# Disks for ZFS boot/root pool (bpool/rpool).
disk1=""
disk2=""
# Directories for temporary storage of LUKS keyfiles.
temp_key_dir="/dev/shm/luks-keys"
# Destination directory for LUKS keyfiles and headers.
luks_dir="/etc/luks"
# Configure hostname on destination server/system.
hostname=""
## Colorize output.
# shellcheck disable=SC2034
red="\033[91m"
# shellcheck disable=SC2034
green="\033[92m"
# shellcheck disable=SC2034
blue="\033[94m"
# shellcheck disable=SC2034
yellow="\033[93m"
# shellcheck disable=SC2034
cyan="\033[96m"
# shellcheck disable=SC2034
magenta="\033[95m"
# shellcheck disable=SC2034
white="\033[1m"
# shellcheck disable=SC2034
no_color="\033[0m"

print_help() {
echo -e "
${white}Description:${no_color}
  Script deploys a minimal Ubuntu Server installation with ZFS on root and LUKS
  encryption.

  Please note that this installation script is system specific and subject to
  change depending on hardware configuration of the destination server.

  Script is designed to install the following resulting configuration/system.
    - Boot partition (/boot) is a ZFS pool (bpool) on a two drive ZFS mirror.
    - Root partition (/) is a ZFS pool (rpool) on a two drive ZFS mirror
      encrypted with LUKS.

  Script is designed to be used on a UEFI system only. No legacy BIOS support,
  hence no Master Boot Record (MBR) will be created. It will automatically
  partition the disks with the following scheme.

  +---------------------------------------------------------------------------+
  | /dev/disk/by-id/ata|nvme-Manufacturer_Model_Number                        |
  +-------------------+-------------------------------------------------------+
  | ESP partition:    | ZFS mirror (bpool) | Linux filesystem partition:      |
  +-------------------+-------------------------------------------------------+
  | 550 MB            | 2 GB               | Remaining disk space             |
  |                   |                    |                                  |
  | Not encrypted     | Not encrypted      | Encrypted                        |
  +-------------------+-------------------------------------------------------+

  The EFI System Partition (ESP) is mounted to /boot/efi. The boot (/boot)
  partition is a ZFS mirror pool (bpool). The root (/) partition is also a ZFS
  mirror pool (rpool) encrypted with dm-crypt/LUKS (crypt-root1/2).

  ZFS mirror:
    ata|nvme|scsi-Manufacturer_Model_Number-part1
     └─ ESP (/boot/efi)
    ata|nvme|scsi-Manufacturer_Model_Number-part2
     └─ ZFS pool (bpool -> /boot)
    ata|nvme|scsi-Manufacturer_Model_Number-part3
     └─ crypt-root (/)
         └─ ZFS pool (rpool)

  The following ZFS datasets will be automatically created during installation.

  Name:                  Mountpoint:
  bpool                  /
  bpool/BOOT             none
  bpool/BOOT/ubuntu      /boot
  rpool                  /
  rpool/ROOT             none
  rpool/ROOT/ubuntu      /
  rpool/home             /home
  rpool/home/root        /root
  rpool/srv              /srv
  rpool/var              /var
  rpool/var/cache        /var/cache
  rpool/var/lib          /var/lib
  rpool/var/lib/docker   /var/lib/docker
  rpool/var/lib/nfs      /var/lib/nfs
  rpool/var/log          /var/log
  rpool/var/snap         /var/snap
  rpool/var/spool        /var/spool
  rpool/var/tmp          /var/tmp
  rpool/var/www          /var/www

${white}Caveats:${no_color}
  Script is written for Bash and must be executed in this shell. It is designed
  for and tested on Ubuntu Server 18.04 LTS. It also containes configuration
  variables that are specific for the destination system, such as locale, time-
  zone and more...
          This MUST be changed prior to script execution!

  ${white}With the information stated above,${no_color} ${yellow}YOU HAVE BEEN WARNED!${no_color}

${white}Preperation:${no_color}
  Prior to script execution, boot into Ubuntu Desktop Live CD environment.

  Set a password for the buil-in user.
  $ passwd

  Install SSH server and Git in the live CD environment.
  $ sudo apt install --yes openssh-server git

  Obtain IPv4 address assigned by DHCP.
  $ ip addr show

  Connect to the host system using SSH.
  $ ssh ubuntu@<ipv4>

  Become root.
  $ sudo -i
  # cd ~

  Download Git repository.
  # git clone https://gitlab.com/pwyde/$git_repo.git
  # cd $git_repo

  Execute install script.
  # bash $0 --install

${white}Options:${no_color}
  ${cyan}-i${no_color}, ${cyan}--install${no_color}       Performs installation and configuration on destination
                      server.

  ${cyan}-p${no_color}, ${cyan}--post-install${no_color}  Performs post-installation configuration. This option
                      is only used when performing configuration in the chroot
                      environment. Should NOT be used when executing script.

${white}Reference:${no_color}
  Script was written with information taken from the following sources:
    - https://www.coolgeeks101.com/howto/infrastructure/zfs-root-ubuntu-luks-encryption-usb-boot/
    - https://github.com/zfsonlinux/zfs/wiki/Ubuntu-18.04-Root-on-ZFS
  Script is a re-implementation from the following install script:
    - https://gist.github.com/vrivellino/7dcf150da4cc1d07008315643bfdbfb5
" >&2
}

# Print help if no argument is specified.
if [ "${#}" -le 0 ]; then
    print_help
    exit 1
fi

# Loop as long as there is at least one more argument.
while [ "${#}" -gt 0 ]; do
    arg="${1}"
    case "${arg}" in
        # This is an arg value type option. Will catch both '-i' or
        # '--install' value.
        -i|--install) install="true" ;;
        # This arg value is only used when performing configuration
        # in the chroot environment.
        -p|--post-install) post_install="true" ;;
        # This is an arg value type option. Will catch both '-h' or
        # '--help' value.
        -h|--help) print_help; exit ;;
        *) echo "Invalid option '${arg}'." >&2; print_help; exit 1 ;;
    esac
    # Shift after checking all the cases to get the next option.
    shift
done

print_msg() {
    echo -e "$green=>$no_color$white" "$@" "$no_color" >&1
}

print_error() {
    echo -e "$red=> ERROR:$no_color$white" "$@" "$no_color" >&1
}

test_run_as_root() {
    # Verify that script is executed as the 'root' user.
    if [[ "${EUID}" -ne 0 ]]; then
        print_error "Script must be executed as the 'root' user!"
        exit 1
    fi
}

setup_variables() {
    echo -e "${white}""Select disks to partition:""${no_color}"
    echo
    for disk in /dev/disk/by-id/*; do
        disk="${disk##*/}"
        echo -e "${yellow}""${disk}""${no_color}"
    done
    echo
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")System disk #1 (bpool/rpool): $(echo -e "${no_color}")" disk1
    if ! [[ -e /dev/disk/by-id/"${disk1}" ]]; then
        echo "Invalid or non-existing disk: $disk1"
        exit 1
    fi
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")System disk #2 (bpool/rpool): $(echo -e "${no_color}")" disk2
    if ! [[ -e /dev/disk/by-id/"${disk2}" ]]; then
        echo "Invalid or non-existing disk: $disk2"
        exit 1
    fi
    echo
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Enter hostname: $(echo -e "${no_color}")" hostname
    echo
    if [[ -z "${hostname}" ]]; then
        echo "Invalid hostname!"
        exit 1
    fi
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Enter domain name (use '.local' if no specific): $(echo -e "${no_color}")" domain_name
    echo
    # Remove leading dot (.) in domain name string if it exists.
    domain_name="${domain_name##.}"
    if [[ -z "${domain_name}" ]]; then
        print_error "Invalid domain name!"
        exit 1
    fi
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Enter NTP server (leave blank for none): $(echo -e "${no_color}")" ntp_server
    echo
    # Dump disk variables to file that will be sourced in chroot environment.
    cat > "${script_dir}"/.variables <<EOF
## Disk drive IDs (symlinks in /dev/disk/by-id).
# Disks for ZFS boot/root pool (bpool/rpool).
disk1="$disk1"
disk2="$disk2"
# Hostname.
hostname="$hostname"
# Domain name.
domain_name="$domain_name"
# NTP server.
ntp_server="$ntp_server"
EOF
}

prep_install_environment() {
    print_msg "Adding universe repository..."
    apt-add-repository universe
    apt update
    print_msg "Installing package dependencies..."
    apt install --yes debootstrap gdisk zfs-initramfs
}

partition() {
    echo
    echo -e "${red}""WARNING: Selected disks will be re-partitioned!""${no_color}"
    echo
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Press enter to continue or Ctrl + C to abort...$(echo -e "${no_color}")"
    echo
    # Clear all partitions and tables.
    print_msg "Deleting disk partitions..."
    for disk in $disk1 $disk2; do
        sgdisk --clear /dev/disk/by-id/"${disk}"
        sgdisk --zap-all /dev/disk/by-id/"${disk}"
    done
    print_msg "Creatinig new partitions..."
    for disk in $disk1 $disk2; do
        # Partition root disk; EFI system partition (part1).
        sgdisk --new=1:1M:+550M --typecode=1:EF00 /dev/disk/by-id/"${disk}"
        # Partition root disk; boot partition (part2) that will contain the ZFS boot
        # pool (bpool).
        sgdisk --new=2:0:+2G --typecode=2:BF01 /dev/disk/by-id/"${disk}"
        # Partition root disk; use remaining space for encrypted block device (part3)
        # that will contain the ZFS root pool (rpool).
        sgdisk --new=3:0:0 --typecode=3:8300 /dev/disk/by-id/"${disk}"
    done
    }

setup_encryption() {
    print_msg "Creating encrypted block devices..."
    mkdir -p "${temp_key_dir}"
    chmod 0700 "${temp_key_dir}"
    # Create keyfiles for LUKS container that will contain the ZFS root pool (rpool).
    for disk in $disk1 $disk2; do
        if ! [[ -f "${temp_key_dir}"/"${disk}"-keyfile ]]; then
            dd if=/dev/urandom of="${temp_key_dir}"/"${disk}"-keyfile bs=512 count=4
        fi
        chmod 0600 "${temp_key_dir}"/"${disk}"*
        cryptsetup luksFormat -c aes-xts-plain64 -h sha512 -s 512 --use-urandom --type luks2 /dev/disk/by-id/"${disk}"-part3
    done
    for disk in $disk1 $disk2; do
        print_msg "Finalize encrypted block device for '${disk}'..."
        cryptsetup luksAddKey /dev/disk/by-id/"${disk}"-part3 "${temp_key_dir}"/"${disk}"-keyfile
    done
}

luks_open() {
    # Open all LUKS containers.
    cryptsetup status crypt-root1 || cryptsetup luksOpen --key-file "${temp_key_dir}"/"${disk1}"-keyfile /dev/disk/by-id/"${disk1}"-part3 crypt-root1
    cryptsetup status crypt-root2 || cryptsetup luksOpen --key-file "${temp_key_dir}"/"${disk2}"-keyfile /dev/disk/by-id/"${disk2}"-part3 crypt-root2
}

initialize_zfs() {
    if zpool status bpool > /dev/null 2>&1; then
        zpool destroy bpool
    fi
    ## Create zpool for /boot (bpool).
    # Create ZFS mirror for the boot pool.
    zpool create -o ashift=12 -d \
        -o feature@async_destroy=enabled \
        -o feature@bookmarks=enabled \
        -o feature@embedded_data=enabled \
        -o feature@empty_bpobj=enabled \
        -o feature@enabled_txg=enabled \
        -o feature@extensible_dataset=enabled \
        -o feature@filesystem_limits=enabled \
        -o feature@hole_birth=enabled \
        -o feature@large_blocks=enabled \
        -o feature@lz4_compress=enabled \
        -o feature@spacemap_histogram=enabled \
        -o feature@userobj_accounting=enabled \
        -O acltype=posixacl -O canmount=off -O compression=lz4 -O devices=off \
        -O normalization=formD -O relatime=on -O xattr=sa \
        -O mountpoint=/ -R /mnt -f \
        bpool mirror "${disk1}"-part2 "${disk2}"-part2
    if zpool status rpool > /dev/null 2>&1; then
        zpool destroy rpool
    fi
    ## Create zpool for / (rpool).
    # Create ZFS mirror for the root pool.
    zpool create -o ashift=12 \
        -O acltype=posixacl -O canmount=off -O compression=lz4 \
        -O dnodesize=auto -O normalization=formD -O relatime=on -O xattr=sa \
        -O mountpoint=/ -R /mnt \
        rpool mirror /dev/mapper/crypt-root1 /dev/mapper/crypt-root2
    # Create filesystem dataset to act as containers.
    zfs create -o canmount=off -o mountpoint=none bpool/BOOT
    zfs create -o canmount=off -o mountpoint=none rpool/ROOT
    # Create filesystem datasets for the root and boot filesystems.
    zfs create -o canmount=noauto -o mountpoint=/ rpool/ROOT/ubuntu
    zfs mount rpool/ROOT/ubuntu
    zfs create -o canmount=noauto -o mountpoint=/boot bpool/BOOT/ubuntu
    zfs mount bpool/BOOT/ubuntu
    # Create remaining datasets.
    zfs create                                 rpool/home
    zfs create -o mountpoint=/root             rpool/home/root
    zfs create -o canmount=off                 rpool/var
    zfs create -o canmount=off                 rpool/var/lib
    zfs create                                 rpool/var/log
    zfs create                                 rpool/var/spool
    # Exclude /var/cashe and /var/tmp from snapshots.
    zfs create -o com.sun:auto-snapshot=false  rpool/var/cache
    zfs create -o com.sun:auto-snapshot=false  rpool/var/tmp
    # If services will share data using the /srv directory.
    zfs create                                 rpool/srv
    # If the system will use Snap packages.
    zfs create                                 rpool/var/snap
    # If a web server will be hosted on the system.
    zfs create                                 rpool/var/www
    # Exclude Docker from snapshots which manages its own datasets and snapshots.
    zfs create -o com.sun:auto-snapshot=false  rpool/var/lib/docker
    # Exclude NFS from snapshots (locking).
    zfs create -o com.sun:auto-snapshot=false  rpool/var/lib/nfs
    print_msg "Created ZFS data structure..."
}

setup_initial_system() {
    print_msg "Setup initial system..."
    chmod 1777 /mnt/var/tmp
    # Install minimal system.
    debootstrap bionic /mnt
    zfs set devices=off rpool
    # Configure hostname and domain name.
    echo "$hostname.$domain_name" > /mnt/etc/hostname
    cat > /mnt/etc/hosts <<EOF
127.0.0.1   $hostname.$domain_name    $hostname

#::1        localhost ip6-localhost ip6-loopback
#ff02::1    ip6-allnodes
#ff02::2    ip6-allrouters
EOF
    print_msg "Configured hostname..."
    # Configure networking and use DHCP.
    eth_dev=$(ip link | grep -v '^ ' | awk '{ print $2 }' | cut -f 1 -d : | grep -v '^lo$' | head -n 1)
    if [[ -n "${eth_dev}" ]]; then
    cat > /mnt/etc/netplan/"${eth_dev}".yaml <<EOF
network:
  version: 2
  ethernets:
    NAME:
      dhcp4: true
EOF
    fi
    sed -i "s/NAME/$eth_dev/" /mnt/etc/netplan/"${eth_dev}".yaml
    print_msg "Configured networking and use of DHCP..."
    # Configure the package sources.
    cat > /mnt/etc/apt/sources.list << EOF
deb http://archive.ubuntu.com/ubuntu bionic main universe
deb-src http://archive.ubuntu.com/ubuntu bionic main universe

deb http://security.ubuntu.com/ubuntu bionic-security main universe
deb-src http://security.ubuntu.com/ubuntu bionic-security main universe

deb http://archive.ubuntu.com/ubuntu bionic-updates main universe
deb-src http://archive.ubuntu.com/ubuntu bionic-updates main universe
EOF
    print_msg "Configure the package sources..."
    # Bind the virtual filesystems from the LiveCD environment to the new system.
    mount --rbind /dev  /mnt/dev
    mount --rbind /proc /mnt/proc
    mount --rbind /sys  /mnt/sys
    print_msg "Completed setup of initial system..."
}

copy_luks_keys() {
    mkdir -p /mnt"${luks_dir}"
    chmod 0700 /mnt"${luks_dir}"
    cp "${temp_key_dir}"/* /mnt"${luks_dir}"
    chmod 0400 /mnt"${luks_dir}"/*
    print_msg "Moved LUKS keys..."
}

dest_system_basic_config() {
    test -e "/root/$git_repo/$(basename "${0}")"
    print_msg "Configure locale and timezone..."
    # Configure locale.
    locale-gen en_GB.UTF-8 en_US.UTF-8 sv_SE.UTF-8
    cp --force "${script_dir}"/etc/default/locale /etc/default/locale
    # Configure keyboard.
    dpkg-reconfigure keyboard-configuration
    # Configure timezone.
    dpkg-reconfigure tzdata
    if [[ -n "${ntp_server}" ]]; then
        # Configure NTP server.
        sed -i "s/#NTP=/NTP=$ntp_server/" /etc/systemd/timesyncd.conf
    fi
    ln -s /proc/self/mounts /etc/mtab
    # Install ZFS and utilities in the chroot environment for the destination system.
    print_msg "Installing base packages including ZFS..."
    apt update
    apt install --yes --no-install-recommends linux-image-generic
    apt install --yes zfs-initramfs cryptsetup openssh-server nano vim git
    print_msg "Installed base packages, ZFS and more..."
}

dest_system_crypttab() {
    test -e "/root/$git_repo/$(basename "${0}")"
    sed -i "/^crypt-\(root\|data\)[0-9] /d" /etc/crypttab
    ## Configure crypttab.
    # shellcheck disable=SC2129
    echo "crypt-root1 /dev/disk/by-id/$disk1-part3 none luks,discard,initramfs" >> /etc/crypttab
    echo "crypt-root2 /dev/disk/by-id/$disk2-part3 none luks,discard,initramfs" >> /etc/crypttab
    print_msg "Configured crypttab..."
}

dest_system_install_grub() {
    test -e "/root/$git_repo/$(basename "${0}")"
    # Install GRUB for UEFI booting.
    apt install dosfstools
    mkdosfs -F 32 -n EFI /dev/disk/by-id/"${disk1}"-part1
    test -d /boot/efi || mkdir /boot/efi
    mount /dev/disk/by-id/"${disk1}"-part1 /boot/efi
    apt install --yes grub-efi-amd64
    print_msg "Installed GRUB with UEFI booting..."
}

dest_system_setup_boot() {
    test -e "/root/$git_repo/$(basename "${0}")"
    update-initramfs -u -k all
    chmod 0600 /boot/initrd*
    # Configure GRUB.
    sed -i "s/^GRUB_TIMEOUT_STYLE=hidden/#GRUB_TIMEOUT_STYLE=hidden/" /etc/default/grub
    sed -i "s/^GRUB_TIMEOUT=0/GRUB_TIMEOUT=5/" /etc/default/grub
    # System specific configuration:
    #   - Disable IPv6.
    #   - Fix kernel warning message on Supermicro server motherboard.
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable_ipv6=1 pcie_aspm=off"/' /etc/default/grub
    sed -i 's/^GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="root=ZFS=rpool\/ROOT\/ubuntu"/' /etc/default/grub
    sed -i "s/^#GRUB_TERMINAL=console/GRUB_TERMINAL=console/" /etc/default/grub
    # Configure GRUB for LUKS encrypted boot partition (/boot).
    cat >> /etc/default/grub <<EOF

# Disable os-prober, it might add menu entries for each guest
GRUB_DISABLE_OS_PROBER=true
EOF
    update-grub
    # Install GRUB for UEFI booting.
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Ubuntu --recheck --no-floppy
    ls /boot/grub/*/zfs.mod
    # Add autostart of GRUB in UEFI shell.
    cat >> /boot/efi/startup.nsh <<EOF
cls
fs0:\EFI\Ubuntu\grubx64.efi
EOF
    print_msg "Configured GRUB with UEFI booting..."
}

dest_system_zfs_legacy_mount() {
    test -e "/root/$git_repo/$(basename "${0}")"
    # Enable tmpfs (RAM filesystem).
    cp /usr/share/systemd/tmp.mount /etc/systemd/system/
    systemctl enable tmp.mount
    # Configure filesystem mount ordering (fstab).
    echo "# <file system>                               <mount point>   <type>  <options>                                                   <dump>  <pass>" > /etc/fstab
    # Get PARTUUID for the EFI partition.
    uefiboot_uuid=$(blkid -s PARTUUID -o value /dev/disk/by-id/"${disk1}"-part1)
    echo "PARTUUID=$uefiboot_uuid /boot/efi       vfat    nofail,x-systemd.device-timeout=10                            0       1" >> /etc/fstab
    # Ensure EFI partition is not mounted as it is a child to the /boot mountpoint.
    umount /boot/efi
    zfs set mountpoint=legacy bpool/BOOT/ubuntu
    echo "bpool/BOOT/ubuntu                             /boot           zfs     nodev,relatime,x-systemd.requires=zfs-import-bpool.service    0       0" >> /etc/fstab
    zfs set mountpoint=legacy rpool/var/log
    echo "rpool/var/log                                 /var/log        zfs     nodev,relatime                                                0       0" >> /etc/fstab
    zfs set mountpoint=legacy rpool/var/spool
    echo "rpool/var/spool                               /var/spool      zfs     nodev,relatime                                                0       0" >> /etc/fstab
    zfs set mountpoint=legacy rpool/var/tmp
    echo "rpool/var/tmp                                 /var/tmp        zfs     nodev,relatime                                                0       0" >> /etc/fstab
    print_msg "Configured filesystem mounting..."
}

dest_system_setup_zpools() {
    test -e "/root/$git_repo/$(basename "${0}")"
    # This ensures that bpool is always imported.
    cp --force "${script_dir}"/etc/systemd/system/zfs-import-bpool.service /etc/systemd/system/zfs-import-bpool.service
    systemctl enable zfs-import-bpool.service
    print_msg "Configured importing of ZFS boot pool (bpool)..."
}

dest_system_enable_scrubbing() {
    test -e "/root/$git_repo/$(basename "${0}")"
    # Enable scrubbing using systemd service and timer units.
    cp --force "${script_dir}"/etc/systemd/system/zfs-scrub@.timer /etc/systemd/system/zfs-scrub@.timer
    cp --force "${script_dir}"/etc/systemd/system/zfs-scrub@.service /etc/systemd/system/zfs-scrub@.service
    systemctl enable zfs-scrub@rpool.timer
    print_msg "Enabled ZFS scrubbing..."
}

dest_system_final_config_before_reboot() {
    test -e "/root/$git_repo/$(basename "${0}")"
    # Create system groups.
    getent group lpadmin > /dev/null || addgroup --system lpadmin
    getent group sambashare > /dev/null || addgroup --system sambashare
    set +x
    # Set root password.
    root_pw=$(getent shadow root | cut -f 2 -d :)
    if [[ "${root_pw}" == '*' ]] || [[ -z "${root_pw}" ]]; then
        echo
        echo -e "${white}""Set root password for system.""${no_color}"
        passwd
        echo
    fi
    # Create snapshots.
    for snap in rpool/ROOT/ubuntu@install bpool/BOOT/ubuntu@install; do
        if zfs list -t snap | grep -q $snap; then
            zfs destroy $snap
        fi
        zfs snapshot $snap
    done
}

if [[ "${install}" == true && "${post_install}" == false ]]; then
    test_run_as_root
    echo
    echo -e "${cyan}""Performing pre-installation configuration...""${no_color}"
    echo
    #set -x
    setup_variables
    prep_install_environment
    partition
    setup_encryption
    luks_open
    initialize_zfs
    echo
    echo -e "${cyan}""Performing minimal installation...""${no_color}"
    echo
    setup_initial_system
    copy_luks_keys
    # Copy script to destination system and execute via chroot.
    cp -r "${script_dir}" /mnt/root
    chroot /mnt /bin/bash --login "/root/$git_repo/$(basename "$0")" --post-install
    set +x
    echo
    echo -e "${green}""System installation completed!""${no_color}"
    echo
    echo -e "${yellow}""System is ready to reboot!""${no_color}"
    echo
    echo -e "${white}""The following commands will be executed.""${no_color}"
    echo -e "${white}""# mount | grep -v zfs | tac | awk '/\\/mnt/ {print \$3}' | xargs -i{} umount -lf {}""${no_color}"
    echo -e "${white}""# zpool export bpool""${no_color}"
    echo -e "${white}""# zpool export rpool""${no_color}"
    echo -e "${white}""# reboot --force""${no_color}"
    echo
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Press enter to continue or Ctrl + C to abort...$(echo -e "${no_color}")"
    mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -i{} umount -lf {}
    zpool export bpool
    zpool export rpool
    reboot --force
elif [[ "${install}" == false && "${post_install}" == true ]]; then
    echo
    echo -e "${cyan}""Performing post-install configuration...""${no_color}"
    echo
    #set -x
    # Source disk variables that were dumped to file during '--install'.
    # shellcheck source=/dev/null
    source /root/"${git_repo}"/.variables
    dest_system_basic_config
    dest_system_crypttab
    dest_system_install_grub
    dest_system_setup_boot
    dest_system_zfs_legacy_mount
    dest_system_setup_zpools
    dest_system_enable_scrubbing
    dest_system_final_config_before_reboot
    set +x
else
    echo "Missing or invalid options, see help below."
    print_help
    exit 1
fi
