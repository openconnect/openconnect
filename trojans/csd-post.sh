#!/bin/bash
# Cisco Anyconnect CSD wrapper for OpenConnect
#
# Instead of actually downloading and spawning the hostscan trojan,
# this script posts results directly. Ideally we would work out how to
# interpret the DES-encrypted (yay Cisco!) tables.dat and basically
# reimplement the necessary parts hostscan itself. But prepackaged
# answers, tuned to match what the VPN server currently wants to see,
# will work for most people. Of course it's perfectly possible to make
# this tell the truth and not just give prepackaged answers, and most
# people should do that rather than deliberately circumventing their
# server's security policy with lies. This script exists as an example
# to work from.

if ! xmlstarlet --version > /dev/null 2>&1; then
    echo "************************************************************************" >&2
    echo "WARNING: xmlstarlet not found in path; CSD token extraction may not work" >&2
    echo "************************************************************************" >&2
    unset XMLSTARLET
else
    XMLSTARLET=true
fi

# cURL 7.39 (https://bugzilla.redhat.com/show_bug.cgi?id=1195771)
# is required to support pin-based certificate validation. Must set this
# to false if using an older version of cURL.

INSECURE=false
if [[ "$INSECURE" == "true" ]]; then
    echo "*********************************************************************" >&2
    echo "WARNING: running insecurely; will not validate CSD server certificate" >&2
    echo "*********************************************************************" >&2
fi


export RESPONSE=$(mktemp /tmp/csdresponseXXXXXXX)
export RESULT=$(mktemp /tmp/csdresultXXXXXXX)
trap 'rm $RESPONSE $RESULT' EXIT


cat >> $RESPONSE <<EOF
endpoint.os.version="$(uname -s)";
endpoint.os.servicepack="$(uname -r)";
endpoint.os.architecture="$(uname -m)";
endpoint.policy.location="Default";
endpoint.device.protection="none";
endpoint.device.protection_version="3.1.03103";
endpoint.device.hostname="$(hostname)";
endpoint.device.port["9217"]="true";
endpoint.device.port["139"]="true";
endpoint.device.port["53"]="true";
endpoint.device.port["22"]="true";
endpoint.device.port["631"]="true";
endpoint.device.port["445"]="true";
endpoint.device.port["9216"]="true";
endpoint.device.tcp4port["9217"]="true";
endpoint.device.tcp4port["139"]="true";
endpoint.device.tcp4port["53"]="true";
endpoint.device.tcp4port["22"]="true";
endpoint.device.tcp4port["631"]="true";
endpoint.device.tcp4port["445"]="true";
endpoint.device.tcp4port["9216"]="true";
endpoint.device.tcp6port["139"]="true";
endpoint.device.tcp6port["53"]="true";
endpoint.device.tcp6port["22"]="true";
endpoint.device.tcp6port["631"]="true";
endpoint.device.tcp6port["445"]="true";
endpoint.device.MAC["FFFF.FFFF.FFFF"]="true";
endpoint.device.protection_extension="3.6.4900.2";
endpoint.fw["IPTablesFW"]={};
endpoint.fw["IPTablesFW"].exists="true";
endpoint.fw["IPTablesFW"].description="IPTables (Linux)";
endpoint.fw["IPTablesFW"].version="1.6.1";
endpoint.fw["IPTablesFW"].enabled="ok";
EOF

shift

TICKET=
STUB=0

while [ "$1" ]; do
    if [ "$1" == "-ticket" ];   then shift; TICKET=${1//\"/}; fi
    if [ "$1" == "-stub" ];     then shift; STUB=${1//\"/}; fi
    shift
done

if [[ "$INSECURE" == "true" ]]; then
    # Don't validate server certificate at all
    PINNEDPUBKEY="-k"
else
    # Validate certificate using pin-sha256 value in CSD_SHA256, or fallback to
    # cURL's default certificate validation if not set.
    PINNEDPUBKEY="${CSD_SHA256:+"-k --pinnedpubkey sha256//$CSD_SHA256"}"
fi

URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/token.xml?ticket=$TICKET&stub=$STUB"
if [ -n "$XMLSTARLET" ]; then
    TOKEN=$(curl $PINNEDPUBKEY -s "$URL"  | xmlstarlet sel -t -v /hostscan/token)
else
    TOKEN=$(curl $PINNEDPUBKEY -s "$URL" | sed -n '/<token>/s^.*<token>\(.*\)</token>^\1^p' )
fi

if [ -n "$XMLSTARLET" ]; then
    URL="https://$CSD_HOSTNAME/CACHE/sdesktop/data.xml"

    curl $PINNEDPUBKEY -s "$URL" | xmlstarlet sel -t -v '/data/hostscan/field/@value' | while read -r ENTRY; do
	# XX: How are ' and , characters escaped in this?
	TYPE="$(sed "s/^'\(.*\)','\(.*\)','\(.*\)'$/\1/" <<< "$ENTRY")"
	NAME="$(sed "s/^'\(.*\)','\(.*\)','\(.*\)'$/\2/" <<< "$ENTRY")"
	VALUE="$(sed "s/^'\(.*\)','\(.*\)','\(.*\)'$/\3/" <<< "$ENTRY")"

	if [ "$TYPE" != "$ENTRY" ]; then
	    case "$TYPE" in
		File)
		    BASENAME="$(basename "$VALUE")"
		    cat >> $RESPONSE <<EOF
endpoint.file["$NAME"]={};
endpoint.file["$NAME"].path="$VALUE";
endpoint.file["$NAME"].name="$BASENAME";
EOF
		    TS=$(stat -c %Y "$VALUE" 2>/dev/null)
		    if [ "$TS" = "" ]; then
		    cat >> $RESPONSE <<EOF
endpoint.file["$NAME"].exists="false";
EOF
		    else
			LASTMOD=$(( $(date +%s) - $TS ))
		    cat >> $RESPONSE <<EOF
endpoint.file["$NAME"].exists="true";
endpoint.file["$NAME"].lastmodified="$LASTMOD";
endpoint.file["$NAME"].timestamp="$TS";
EOF
			CRC32=$(crc32 "$VALUE")
			if [ "$CRC32" != "" ]; then
		    cat >> $RESPONSE <<EOF
endpoint.file["$NAME"].crc32="0x$CRC32";
EOF
			fi
		    fi
		    ;;

		Process)
		    if pidof "$VALUE" &> /dev/null; then
			EXISTS=true
		    else
			EXISTS=false
		    fi
		    cat >> $RESPONSE <<EOF
endpoint.process["$NAME"]={};
endpoint.process["$NAME"].name="$VALUE";
endpoint.process["$NAME"].exists="$EXISTS";
EOF
		    ## XX: Add '.path' if it's running?
		    ;;

		Registry)
		    # We silently ignore registry entry requests
		    ;;

		*)
		    echo "Unhandled hostscan element of type '$TYPE': '$NAME'/'$VALUE'"
		    ;;
	    esac
	else
	    echo "Unhandled hostscan field '$ENTRY'"
	fi
    done
fi

COOKIE_HEADER="Cookie: sdesktop=$TOKEN"
CONTENT_HEADER="Content-Type: text/xml"
URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/scan.xml?reusebrowser=1"
curl $PINNEDPUBKEY -s -H "$CONTENT_HEADER" -H "$COOKIE_HEADER" -H 'Expect: ' --data-binary @$RESPONSE "$URL" > $RESULT

cat $RESULT || :

exit 0
