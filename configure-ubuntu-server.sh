#!/usr/bin/env bash

# Configuration script for Ubuntu Server.
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

# Exit immediately if a command exits with a non-zero exit status.
set -e

# Configure script variables.
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
apply="false"
net_config=""
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
  Script performs post-deployment configuration on a newly installed Ubuntu
  server. Used for installing utilities/tools and basic system hardening.

  Script performs the following configuration changes:
    - Update package database and upgrade system.
    - Install common packages.
    - Set default editor.
    - Configure SSH.
      - SSH daemon and client hardening.
      - Creates dedicated SSH user group and adds specified user to group.
    - Configure system networking.
    - Configure welcome message/banner.
    - Disable log compression. Assumes ZFS root partition, hence comp-
      ression is already performed by the filesystem.
    - Configure file and inode limits.
    - Configure journal size limit.
    - Disable core dumps.
    - Set a timeout for sudo sessions.
    - TCP/IP stack hardening.
    - Restrict access to kernel logs.
    - Disable Speck kernel module.
    - Disable the root password.

${white}Caveats:${no_color}
  Script is written for Bash and must be executed in this shell. It is designed
  for and tested on Ubuntu Server 18.04 LTS. It contains configuration variables
  and other configuratioin files that are specific for the destination system,
  i.e. SSH daemon/client and ZFS as root filesystem.

  System hardening performed by this script is not official common best
  practices and are subject to debate and changes in the future.

  ${white}With the information stated above,${no_color} ${yellow}YOU HAVE BEEN WARNED!${no_color}

${white}Examples:${no_color}
  ${0} --apply --net-config /pat/to/config_file/netplan.yaml

${white}Options:${no_color}
  ${cyan}-a${no_color}, ${cyan}--apply${no_color}       Apply system configuration and hardening included in script.

  ${cyan}-n${no_color}, ${cyan}--net-config${no_color}  Specify a specific Netplan configuration file that will be
                    applied on the host.
" >&1
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
        # This is an arg value type option. Will catch both '-a' or
        # '--apply' value.
        -a|--apply) apply="true" ;;
        # This is an arg value type option. Will catch both '-n' or
        # '--net-config' value.
        -n|--net-config) shift; netplan_file="${1}" net_config="true" ;;
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
    echo -e "$red=> ERROR:$no_color$white" "$@" "$no_color" >&2
}

test_run_as_root() {
    # Verify that script is executed as the 'root' user.
    if [[ "${EUID}" -ne 0 ]]; then
        print_error "Script must be executed as the 'root' user!"
        exit 1
    fi
}

setup_variables() {
    if [[ "${net_config}" == true ]]; then
        if ! [[ -f "${netplan_file}" ]]; then
            print_error "Specified network configuration file does not exist!"
            exit 1
        fi
    fi
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Enter system IPv4 address: $(echo -e "${no_color}")" ipv4
    echo
    if [[ -z "${ipv4}" ]]; then
        print_error "Invalid system IPv4 address!"
        exit 1
    fi
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Enter username to create: $(echo -e "${no_color}")" username
    echo
    if [[ -z "${username}" ]]; then
        print_error "Invalid username!"
        exit 1
    fi
    # Dump disk variables to file that will be sourced in chroot environment.
    cat >> "${script_dir}"/.variables <<EOF
# Regular user.
username="$username"
EOF
}

update_system() {
    print_msg "Updating system..."
    apt update
    apt upgrade --yes
    # Install common Ubuntu server packages.
    apt install --yes ubuntu-server
    print_msg "System update completed..."
}

install_common_pkgs() {
    # Instal common applications, tools and utilities.
    print_msg "Installing common packages..."
    apt install --yes bash-completion vim htop apt-transport-https man-db
    print_msg "Installation of common packages completed..."
}

config_regular_user() {
    print_msg "Creating regular user..."
    # Create regular user.
    zfs create rpool/home/"${username}"
    adduser "${username}"
    cp -a /etc/skel/.[!.]* /home/"${username}"/
    chown -R "$username":"$username" /home/"${username}"
    chmod 0700 /home/"${username}"
    usermod -a -G adm,cdrom,dip,lpadmin,plugdev,sambashare,sudo "${username}"
    print_msg "Created regular user '${username}'..."
}

config_editor() {
    print_msg "Configure default editor..."
    # Configre default editor.
    update-alternatives --config editor
    print_msg "Default editor configured..."
}

config_ssh() {
    print_msg "Configuring OpenSSH..."
    # Create group for SSH access.
    groupadd sshusers
    # Add user to SSH group.
    usermod -aG sshusers "${username}"
    # Enable diffie-hellman-group-exchange-sha256 key exchange protocol.
    awk '$5 > 2000' /etc/ssh/moduli > "${HOME}/moduli"
    wc -l "${HOME}/moduli"
    mv "${HOME}/moduli" /etc/ssh/moduli
    # Generate new SSH keys.
    rm /etc/ssh/ssh_host_*key*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null
    # Copy SSH daemon configuration file.
    cp --force "${script_dir}"/etc/ssh/sshd_config /etc/ssh/sshd_config
    # Copy SSH client configuration file.
    cp --force "${script_dir}"/etc/ssh/ssh_config /etc/ssh/ssh_config
    print_msg "Configured OpenSSH..."
}

config_networking() {
    sed -i "s/127.0.0.1/$ipv4/" /etc/hosts
    # If specified, apply custom Netplan configuration file.
    if [[ "${net_config}" == true ]]; then
        # Rename existing Netplan configuration file(s) and add '.bak' suffix.
        for file in /etc/netplan/*.yaml; do
            mv "${file}" "${file}".bak
        done
        cp "${netplan_file}" /etc/netplan/
    fi
    print_msg "Configured host networking..."
}

config_welcome_msg() {
    cat > /etc/issue <<EOF
Ubuntu LTS on \n

EOF
    print_msg "Configured welcome message/banner..."
}

config_swappiness() {
    # Improve performance of swap on ZFS on Linux (ZoL).
    cp --force "${script_dir}"/etc/sysctl.d/50-vm.conf /etc/sysctl.d/50-vm.conf
    print_msg "Configured swappiness..."
}

config_log_compression() {
    # Disable log compression, /var/log is already compressed by ZFS.
    for file in /etc/logrotate.d/*; do
        if grep -Eq "(^|[^#y])compress" "${file}"; then
            sed -i -r 's/(^|[^#y])(compress)/\1#\2/' "${file}"
        fi
    done
    print_msg "Disabled log compression..."
}

config_file_inode_limits() {
    # Configure inode limits.
    cp --force "${script_dir}"/etc/sysctl.d/30-fs.conf /etc/sysctl.d/30-fs.conf
    # Configure file limits.
    cat >> /etc/security/limits.conf <<EOF

# Start of custom configuration.

# Increase file limits.
*               soft    nofile          100000
*               hard    nofile          100000
EOF
    print_msg "Configured file and inode limits..."
}

config_journal_size() {
    # Configure journal size limit.
    mkdir -p /etc/systemd/journald.conf.d
    cp --force "${script_dir}"/etc/systemd/journald.conf.d/00-journal-size.conf /etc/systemd/journald.conf.d/00-journal-size.conf
    systemctl daemon-reload
    print_msg "Configured journal size limit..."
}

config_core_dumps() {
    ## Disable core dumps.
    # Using systemd
    mkdir -p /etc/systemd/coredump.conf.d
    cp --force "${script_dir}"/etc/systemd/coredump.conf.d/00-core-dumps.conf /etc/systemd/coredump.conf.d/00-core-dumps.conf
    systemctl daemon-reload
    # Using ulimit
    cat >> /etc/security/limits.conf <<EOF

# Disable core dumps.
*               hard    core            0
EOF
    # Using sysctl.
    cp --force "${script_dir}"/etc/sysctl.d/50-coredump.conf /etc/sysctl.d/50-coredump.conf
    print_msg "Disabled core dumps..."
}

secure_sudo_timeout() {
    # Set a timeout for sudo sessions.
    sed -i "s/env_reset/env_reset,timestamp_timeout=15/" /etc/sudoers
    print_msg "Configured sudo session timeout..."
}

secure_tcpip_stack() {
    # TCP/IP stack hardening.
    cp --force "${script_dir}"/etc/sysctl.d/40-ipv4.conf /etc/sysctl.d/40-ipv4.conf
    cp --force "${script_dir}"/etc/sysctl.d/41-net.conf /etc/sysctl.d/41-net.conf
    cp --force "${script_dir}"/etc/sysctl.d/40-ipv6.conf /etc/sysctl.d/40-ipv6.conf
    print_msg "Performed TCP/IP stack hardening..."
}

secure_kernel_log_access() {
    # Restrict access to kernel logs.
    cp --force "${script_dir}"/etc/sysctl.d/50-dmesg-restrict.conf /etc/sysctl.d/50-dmesg-restrict.conf
    print_msg "Restricted access to kernel logs..."
}

secure_speck_module() {
    # Disable Speck kernel module.
    cat >> /etc/modprobe.d/blacklist.conf <<EOF

# Disable the Speck kernel module (cipher developed by the NSA).
install speck /bin/false
EOF
    print_msg "Disabled Speck kernel module..."
}

secure_root_login() {
    # Disable the root password.
    usermod -p '*' root
    print_msg "Disabled root password..."
}

if [[ "${apply}" == true ]]; then
    test_run_as_root
    echo
    echo -e "${cyan}""Performing basic system configuration...""${no_color}"
    echo
    setup_variables
    update_system
    install_common_pkgs
    config_regular_user
    config_editor
    config_ssh
    config_networking
    echo
    echo -e "${cyan}""Performing system optimization configuration...""${no_color}"
    echo
    config_swappiness
    config_log_compression
    config_file_inode_limits
    config_journal_size
    config_core_dumps
    echo
    echo -e "${cyan}""Performing security configuration...""${no_color}"
    echo
    secure_sudo_timeout
    secure_tcpip_stack
    secure_kernel_log_access
    secure_speck_module
    secure_root_login
    echo
    echo -e "${yellow}""System is ready to reboot!""${no_color}"
    echo
    # shellcheck disable=SC2162
    read -p "$(echo -e "${white}")Press enter to continue or Ctrl + C to abort...$(echo -e "${no_color}")"
    reboot --force
else
    print_error "Missing or invalid options, see help below."
    print_help
    exit 1
fi
