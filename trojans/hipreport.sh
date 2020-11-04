#!/bin/sh

# openconnect will call this script with the follow command-line
# arguments, which are needed to populate the contents of the
# HIP report:
#
#   --cookie: a URL-encoded string, as output by openconnect
#             --authenticate --protocol=gp, which includes parameters
#             from the /ssl-vpn/login.esp response
#
#   --client-ip{,v6}: IPv4/6 addresses allocated by the GlobalProtect
#                     VPN for this client (included in
#                     /ssl-vpn/getconfig.esp response)
#
#   --md5: The md5 digest to encode into this HIP report. I'm not sure
#          exactly what this is the md5 digest *of*, but all that
#          really matters is that the value in the HIP report
#          submission should match the value in the HIP report check.
#
#   --client-os: The platform name in GlobalProtect's format (known
#                values are 'Linux', 'Mac' or 'Windows' ). Defaults to
#                'Windows'.
#
# This hipreport.sh does not work as-is on Android. The large here-doc
# (cat <<EOF) does not appear to work with Android's /system/bin/sh,
# likely due to an insufficient read buffer size.
# Try hipreport-android.sh instead.

# Read command line arguments into variables
COOKIE=
IP=
IPv6=
MD5=
CLIENTOS=Windows


while [ "$1" ]; do
    if [ "$1" = "--cookie" ];      then shift; COOKIE="$1"; fi
    if [ "$1" = "--client-ip" ];   then shift; IP="$1"; fi
    if [ "$1" = "--client-ipv6" ]; then shift; IPV6="$1"; fi
    if [ "$1" = "--md5" ];         then shift; MD5="$1"; fi
    if [ "$1" = "--client-os" ];   then shift; CLIENTOS="$1"; fi
    shift
done

if [ -z "$COOKIE" -o -z "$MD5" -o -z "$IP$IPV6" ]; then
    echo "Parameters --cookie, --md5, and --client-ip and/or --client-ipv6 are required" >&2
    exit 1;
fi

# Extract username and domain and computer from cookie
USER=$(echo "$COOKIE" | sed -rn 's/(.+&|^)user=([^&]+)(&.+|$)/\2/p')
DOMAIN=$(echo "$COOKIE" | sed -rn 's/(.+&|^)domain=([^&]+)(&.+|$)/\2/p')
COMPUTER=$(echo "$COOKIE" | sed -rn 's/(.+&|^)computer=([^&]+)(&.+|$)/\2/p')

# This value may need to be extracted from the official HIP report, if a made-up value is not accepted.
HOSTID="deadbeef-dead-beef-dead-beefdeadbeef"
case $CLIENTOS in
	Linux)
		CLIENT_VERSION="5.1.5-8"
		OS="Linux Fedora 32"
		OS_VENDOR="Linux"
		NETWORK_INTERFACE_NAME="virbr0"
		NETWORK_INTERFACE_DESCRIPTION="virbr0"
		# Not currently used for Linux
		ENCDRIVE='/'
		;;

	*)
		CLIENT_VERSION="5.1.5-8"
		OS="Microsoft Windows 10 Pro , 64-bit"
		OS_VENDOR="Microsoft"
		NETWORK_INTERFACE_NAME="{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}"
		NETWORK_INTERFACE_DESCRIPTION="PANGP Virtual Ethernet Adapter #2"
		# Many VPNs seem to require trailing backslash, others don't accept it
		ENCDRIVE='C:\\'
		;;
esac

# Timestamp in the format expected by GlobalProtect server
NOW=$(date +'%m/%d/%Y %H:%M:%S')
DAY=$(date +'%d')
MONTH=$(date +'%m')
YEAR=$(date +'%Y')

cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<hip-report name="hip-report">
	<md5-sum>$MD5</md5-sum>
	<user-name>$USER</user-name>
	<domain>$DOMAIN</domain>
	<host-name>$COMPUTER</host-name>
	<host-id>$HOSTID</host-id>
	<ip-address>$IP</ip-address>
	<ipv6-address>$IPV6</ipv6-address>
	<generate-time>$NOW</generate-time>
	<hip-report-version>4</hip-report-version>
	<categories>
		<entry name="host-info">
			<client-version>$CLIENT_VERSION</client-version>
			<os>$OS</os>
			<os-vendor>$OS_VENDOR</os-vendor>
			<domain>$DOMAIN.internal</domain>
			<host-name>$COMPUTER</host-name>
			<host-id>$HOSTID</host-id>
			<network-interface>
				<entry name="$NETWORK_INTERFACE_NAME">
					<description>$NETWORK_INTERFACE_DESCRIPTION</description>
					<mac-address>01-02-03-00-00-01</mac-address>
					<ip-address>
						<entry name="$IP"/>
					</ip-address>
					<ipv6-address>
						<entry name="$IPV6"/>
					</ipv6-address>
				</entry>
			</network-interface>
		</entry>
EOF

case $CLIENTOS in
	Linux)
	;;
	*) cat <<EOF
		<entry name="antivirus">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="McAfee VirusScan Enterprise" version="8.8.0.1804" defver="8682.0" prodType="1" engver="5900.7806" osType="1" vendor="McAfee, Inc." dateday="$DAY" dateyear="$YEAR" datemon="$MONTH">
						</Prod>
						<real-time-protection>yes</real-time-protection>
						<last-full-scan-time>$NOW</last-full-scan-time>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="Windows Defender" version="4.11.15063.332" defver="1.245.683.0" prodType="1" engver="1.1.13804.0" osType="1" vendor="Microsoft Corp." dateday="$DAY" dateyear="$YEAR" datemon="$MONTH">
						</Prod>
						<real-time-protection>no</real-time-protection>
						<last-full-scan-time>n/a</last-full-scan-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
esac

case $CLIENTOS in
	Linux) cat <<EOF
		<entry name="anti-malware">
			<list/>
		</entry>
EOF
	;;
	*) cat <<EOF
		<entry name="anti-spyware">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="McAfee VirusScan Enterprise" version="8.8.0.1804" defver="8682.0" prodType="2" engver="5900.7806" osType="1" vendor="McAfee, Inc." dateday="$DAY" dateyear="$YEAR" datemon="$MONTH">
						</Prod>
						<real-time-protection>yes</real-time-protection>
						<last-full-scan-time>$NOW</last-full-scan-time>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="Windows Defender" version="4.11.15063.332" defver="1.245.683.0" prodType="2" engver="1.1.13804.0" osType="1" vendor="Microsoft Corp." dateday="$DAY" dateyear="$YEAR" datemon="$MONTH">
						</Prod>
						<real-time-protection>no</real-time-protection>
						<last-full-scan-time>n/a</last-full-scan-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
esac

case $CLIENTOS in
	Linux) cat <<EOF
		<entry name="disk-backup">
			<list/>
		</entry>
EOF
	;;
	*) cat <<EOF
		<entry name="disk-backup">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Windows Backup and Restore" version="10.0.15063.0" vendor="Microsoft Corp.">
						</Prod>
						<last-backup-time>n/a</last-backup-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
esac

case $CLIENTOS in
	Linux) cat <<EOF
		<entry name="disk-encryption">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="cryptsetup" version="2.3.3" vendor="GitLab Inc.">
						</Prod>
						<drives>
							<entry>
								<drive-name>/</drive-name>
								<enc-state>encrypted</enc-state>
							</entry>
						</drives>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
	*) cat <<EOF
		<entry name="disk-encryption">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Windows Drive Encryption" version="10.0.15063.0" vendor="Microsoft Corp.">
						</Prod>
						<drives>
							<entry>
								<drive-name>$ENCDRIVE</drive-name>
								<enc-state>full</enc-state>
							</entry>
						</drives>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
esac

case $CLIENTOS in
	Linux) cat <<EOF
		<entry name="firewall">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="IPTables" version="1.8.4" vendor="IPTables">
						</Prod>
						<is-enabled>no</is-enabled>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="nftables" version="0.9.3" vendor="The Netfilter Project">
						</Prod>
						<is-enabled>n/a</is-enabled>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
	*) cat <<EOF
		<entry name="firewall">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Microsoft Windows Firewall" version="10.0" vendor="Microsoft Corp.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
		</entry>
EOF
	;;
esac

case $CLIENTOS in
	Linux) cat <<EOF
		<entry name="patch-management">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Dandified Yum" version="4.2.23" vendor="Red Hat, Inc.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
			<missing-patches/>
		</entry>
EOF
	;;
	*) cat <<EOF
		<entry name="patch-management">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="McAfee ePolicy Orchestrator Agent" version="5.0.5.658" vendor="McAfee, Inc.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="Microsoft Windows Update Agent" version="10.0.15063.0" vendor="Microsoft Corp.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
			<missing-patches/>
		</entry>
EOF
	;;
esac

cat <<EOF
		<entry name="data-loss-prevention">
			<list/>
		</entry>
	</categories>
</hip-report>
EOF
