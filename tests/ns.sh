#!/bin/bash
#
# Copyright (C) 2018 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Input:
#  ADDRESS=10.200.2.1
#  CLI_ADDRESS=10.200.1.1
#  VPNNET=192.168.1.0/24
#  VPNADDR=192.168.1.1
#
# Provides:
#  ${NSCMD1} - to run on NS1
#  ${NSCMD2} - to run on NS2
#
# Cleanup is automatic via a trap
#  Requires: finish() to be defined


PATH=${PATH}:/usr/sbin
IP=$(which ip)

if test "$(id -u)" != "0";then
	echo "This test must be run as root"
	exit 77
fi

ip netns list >/dev/null 2>&1
if test $? != 0;then
	echo "This test requires ip netns command"
	exit 77
fi

if test "$(uname -s)" != Linux;then
	echo "This test must be run on Linux"
	exit 77
fi

function nsfinish {
  set +e
  test -n "${ETHNAME1}" && ${IP} link delete ${ETHNAME1} >/dev/null 2>&1
  test -n "${ETHNAME2}" && ${IP} link delete ${ETHNAME2} >/dev/null 2>&1
  test -n "${NSNAME1}" && ${IP} netns delete ${NSNAME1} >/dev/null 2>&1
  test -n "${NSNAME2}" && ${IP} netns delete ${NSNAME2} >/dev/null 2>&1

  finish
}
trap nsfinish EXIT

echo " * Setting up namespaces..."
set -e
NSNAME1="ocserv-c-tmp-$$"
NSNAME2="ocserv-s-tmp-$$"
ETHNAME1="oceth-c$$"
ETHNAME2="oceth-s$$"
${IP} netns add ${NSNAME1}
${IP} netns add ${NSNAME2}

${IP} link add ${ETHNAME1} type veth peer name ${ETHNAME2}
${IP} link set ${ETHNAME1} netns ${NSNAME1}
${IP} link set ${ETHNAME2} netns ${NSNAME2}

${IP} netns exec ${NSNAME1} ip link set ${ETHNAME1} up
${IP} netns exec ${NSNAME2} ip link set ${ETHNAME2} up
${IP} netns exec ${NSNAME2} ip link set lo up

${IP} netns exec ${NSNAME1} ip addr add ${CLI_ADDRESS} dev ${ETHNAME1}
${IP} netns exec ${NSNAME2} ip addr add ${ADDRESS} dev ${ETHNAME2}

${IP} netns exec ${NSNAME1} ip route add default via ${CLI_ADDRESS} dev ${ETHNAME1}
${IP} netns exec ${NSNAME2} ip route add default via ${ADDRESS} dev ${ETHNAME2}

${IP} netns exec ${NSNAME2} ip addr
${IP} netns exec ${NSNAME2} ip route
${IP} netns exec ${NSNAME1} ip route

${IP} netns exec ${NSNAME1} ping -c 1 ${ADDRESS} >/dev/null
${IP} netns exec ${NSNAME2} ping -c 1 ${ADDRESS} >/dev/null
${IP} netns exec ${NSNAME2} ping -c 1 ${CLI_ADDRESS} >/dev/null
set +e

CMDNS1="${IP} netns exec ${NSNAME1}"
CMDNS2="${IP} netns exec ${NSNAME2}"
