#!/bin/sh
## FlexQoS
version=1.0
release=12/31/2020
# shellcheck disable=SC2039
# Forked from FreshJR_QOS v8.8, written by FreshJR07 https://github.com/FreshJR07/FreshJR_QOS
#
# Script Changes Unidentified traffic destination away from "Defaults" into "Others"
# Script Changes HTTPS traffic destination away from "Net Control" into "Web Surfing"
# Script Changes Guaranteed Bandwidth per QOS category into logical percentages of upload and download.
#Script includes misc hardcoded rules
#   (Wifi Calling)  -  UDP traffic on remote ports 500 & 4500 moved into VOIP
#   (Facetime)      -  UDP traffic on local  ports 16384 - 16415 moved into VOIP
#   (Usenet)        -  TCP traffic on remote ports 119 & 563 moved into Downloads
#   (Gaming)        -  Gaming TCP traffic from remote ports 80 & 443 moved into Game Downloads.
#   (Snapchat)      -  Moved into Others
#   (Speedtest.net) -  Moved into Downloads
#   (Google Play)   -  Moved into Downloads
#   (Apple AppStore)-  Moved into Downloads
#   (Advertisement) -  Moved into Downloads
#   (VPN Fix)       -  Router VPN Client upload traffic moved into Downloads instead of whitelisted
#   (VPN Fix)       -  Router VPN Client download traffic moved into Downloads instead of showing up in Uploads
#   (Gaming Manual) -  Unidentified traffic for specified devices, not originating from ports 80/443, moved into "Gaming"
#
#  Gaming traffic originating from ports 80 & 443 is primarily downloads & patches (some lobby/login protocols mixed within)
#  Manually configurable rule will take untracked traffic, not originating from 80/443, for specified devices and place it into Gaming
#  Use of this gaming rule REQUIRES devices to have a continuous static ip assignment && this range needs to be defined in the script
##License
##  FlexQoS is free to use under the GNU General Public License, version 3 (GPL-3.0).
##  https://opensource.org/licenses/GPL-3.0

# initialize Merlin Addon API helper functions
. /usr/sbin/helper.sh

# Global variables
GIT_REPO="https://raw.githubusercontent.com/dave14305/FlexQoS"
GIT_BRANCH="dev"
GIT_URL="${GIT_REPO}/${GIT_BRANCH}"
ADDON_DIR="/jffs/addons/flexqos"
WEBUIPATH="${ADDON_DIR}/flexqos.asp"
SCRIPTPATH="${ADDON_DIR}/flexqos.sh"
ipv6_enabled="$(nvram get ipv6_service)"

#marks for iptable rules
Net_mark_down="0x80090001"
VOIP_mark_down="0x80060001"		# Marks for iptables variant of download rules
Gaming_mark_down="0x80080001"		# Note these marks are same as filter match/mask combo but have a 1 at the end.  That trailing 1 prevents them from being caught by unidentified mask
Others_mark_down="0x800a0001"
Web_mark_down="0x80180001"
Streaming_mark_down="0x80040001"
Downloads_mark_down="0x80030001"
Default_mark_down="0x803f0001"

Net_mark_up="0x40090001"
VOIP_mark_up="0x40060001"		# Marks for iptables variant of upload rules
Gaming_mark_up="0x40080001"		# Note these marks are same as filter match/mask combo but have a 1 at the end.  That trailing 1 prevents them from being caught by unidentified mask
Others_mark_up="0x400a0001"
Web_mark_up="0x40180001"
Streaming_mark_up="0x40040001"
Downloads_mark_up="0x40030001"
Default_mark_up="0x403f0001"

iptables_static_rules() {
	echo "Applying - Iptable Down Rules"
	##DOWNLOAD (INCOMING TRAFFIC) CUSTOM RULES START HERE  -- legacy method
	iptables -D POSTROUTING -t mangle -o br0 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-xmark 0x80000000/0xC0000000 > /dev/null 2>&1		#VPN Fix - (Fixes download traffic showing up in upload section when router is acting as a VPN Client)
	iptables -A POSTROUTING -t mangle -o br0 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-xmark 0x80000000/0xC0000000
	if [ "$ipv6_enabled" != "disabled" ]; then
		ip6tables -D POSTROUTING -t mangle -o br0 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-xmark 0x80000000/0xC0000000 > /dev/null 2>&1		#VPN Fix - (Fixes download traffic showing up in upload section when router is acting as a VPN Client)
		ip6tables -A POSTROUTING -t mangle -o br0 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-xmark 0x80000000/0xC0000000
	fi
	##DOWNLOAD (INCOMING TRAFFIC) CUSTOM RULES END HERE  -- legacy method
	echo "Applying - Iptable Up   Rules ($wan)"
	iptables -D OUTPUT -t mangle -o "$wan" -p udp -m multiport ! --dports 53,123 -j MARK --set-mark ${Downloads_mark_up} > /dev/null 2>&1		#VPN Fix - (Fixes upload traffic not detected when the router is acting as a VPN Client)
	iptables -A OUTPUT -t mangle -o "$wan" -p udp -m multiport ! --dports 53,123 -j MARK --set-mark ${Downloads_mark_up}

	iptables -D OUTPUT -t mangle -o "$wan" -p tcp -m multiport ! --dports 53,123,853 -j MARK --set-mark ${Downloads_mark_up} > /dev/null 2>&1		#VPN Fix - (Fixes upload traffic not detected when the router is acting as a VPN Client)
	iptables -A OUTPUT -t mangle -o "$wan" -p tcp -m multiport ! --dports 53,123,853 -j MARK --set-mark ${Downloads_mark_up}

	if [ "$ipv6_enabled" != "disabled" ]; then
		ip6tables -D OUTPUT -t mangle -o "$wan" -p udp -m multiport ! --dports 53,123 -j MARK --set-mark ${Downloads_mark_up} > /dev/null 2>&1		#VPN Fix - (Fixes upload traffic not detected when the router is acting as a VPN Client)
		ip6tables -A OUTPUT -t mangle -o "$wan" -p udp -m multiport ! --dports 53,123 -j MARK --set-mark ${Downloads_mark_up}

		ip6tables -D OUTPUT -t mangle -o "$wan" -p tcp -m multiport ! --dports 53,123,853 -j MARK --set-mark ${Downloads_mark_up} > /dev/null 2>&1		#VPN Fix - (Fixes upload traffic not detected when the router is acting as a VPN Client)
		ip6tables -A OUTPUT -t mangle -o "$wan" -p tcp -m multiport ! --dports 53,123,853 -j MARK --set-mark ${Downloads_mark_up}
	fi
}

tc_redirection_static_rules() {
	echo "Applying  TC Down Rules"
	##DOWNLOAD APP_DB TRAFFIC REDIRECTION RULES START HERE  -- legacy method

	##DOWNLOAD APP_DB TRAFFIC REDIRECTION RULES END HERE  -- legacy method
	${tc} filter add dev br0 protocol all prio 10 u32 match mark 0x803f0001 0xc03fffff flowid "${Defaults}"		#Used for iptables Default_mark_down functionality
	echo "Applying  TC Up   Rules"
	##UPLOAD APP_DB TRAFFIC REDIRECTION RULES START HERE  -- legacy method

	##UPLOAD APP_DB TRAFFIC REDIRECTION RULES END HERE  -- legacy method
	${tc} filter add dev eth0 protocol all prio 10 u32 match mark 0x403f0001 0xc03fffff flowid "${Defaults}"		#Used for iptables Default_mark_up functionality
} # tc_redirection_static_rules

custom_rates() {
	echo "Modifying TC Class Rates"
	${tc} class change dev br0 parent 1:1 classid 1:10 htb "${PARMS}"prio 0 rate "${DownRate0}"Kbit ceil "${DownCeil0}"Kbit burst "${DownBurst0}" cburst "${DownCburst0}"
	${tc} class change dev br0 parent 1:1 classid 1:11 htb "${PARMS}"prio 1 rate "${DownRate1}"Kbit ceil "${DownCeil1}"Kbit burst "${DownBurst1}" cburst "${DownCburst1}"
	${tc} class change dev br0 parent 1:1 classid 1:12 htb "${PARMS}"prio 2 rate "${DownRate2}"Kbit ceil "${DownCeil2}"Kbit burst "${DownBurst2}" cburst "${DownCburst2}"
	${tc} class change dev br0 parent 1:1 classid 1:13 htb "${PARMS}"prio 3 rate "${DownRate3}"Kbit ceil "${DownCeil3}"Kbit burst "${DownBurst3}" cburst "${DownCburst3}"
	${tc} class change dev br0 parent 1:1 classid 1:14 htb "${PARMS}"prio 4 rate "${DownRate4}"Kbit ceil "${DownCeil4}"Kbit burst "${DownBurst4}" cburst "${DownCburst4}"
	${tc} class change dev br0 parent 1:1 classid 1:15 htb "${PARMS}"prio 5 rate "${DownRate5}"Kbit ceil "${DownCeil5}"Kbit burst "${DownBurst5}" cburst "${DownCburst5}"
	${tc} class change dev br0 parent 1:1 classid 1:16 htb "${PARMS}"prio 6 rate "${DownRate6}"Kbit ceil "${DownCeil6}"Kbit burst "${DownBurst6}" cburst "${DownCburst6}"
	${tc} class change dev br0 parent 1:1 classid 1:17 htb "${PARMS}"prio 7 rate "${DownRate7}"Kbit ceil "${DownCeil7}"Kbit burst "${DownBurst7}" cburst "${DownCburst7}"

	${tc} class change dev eth0 parent 1:1 classid 1:10 htb "${PARMS}"prio 0 rate "${UpRate0}"Kbit ceil "${UpCeil0}"Kbit burst "${UpBurst0}" cburst "${UpCburst0}"
	${tc} class change dev eth0 parent 1:1 classid 1:11 htb "${PARMS}"prio 1 rate "${UpRate1}"Kbit ceil "${UpCeil1}"Kbit burst "${UpBurst1}" cburst "${UpCburst1}"
	${tc} class change dev eth0 parent 1:1 classid 1:12 htb "${PARMS}"prio 2 rate "${UpRate2}"Kbit ceil "${UpCeil2}"Kbit burst "${UpBurst2}" cburst "${UpCburst2}"
	${tc} class change dev eth0 parent 1:1 classid 1:13 htb "${PARMS}"prio 3 rate "${UpRate3}"Kbit ceil "${UpCeil3}"Kbit burst "${UpBurst3}" cburst "${UpCburst3}"
	${tc} class change dev eth0 parent 1:1 classid 1:14 htb "${PARMS}"prio 4 rate "${UpRate4}"Kbit ceil "${UpCeil4}"Kbit burst "${UpBurst4}" cburst "${UpCburst4}"
	${tc} class change dev eth0 parent 1:1 classid 1:15 htb "${PARMS}"prio 5 rate "${UpRate5}"Kbit ceil "${UpCeil5}"Kbit burst "${UpBurst5}" cburst "${UpCburst5}"
	${tc} class change dev eth0 parent 1:1 classid 1:16 htb "${PARMS}"prio 6 rate "${UpRate6}"Kbit ceil "${UpCeil6}"Kbit burst "${UpBurst6}" cburst "${UpCburst6}"
	${tc} class change dev eth0 parent 1:1 classid 1:17 htb "${PARMS}"prio 7 rate "${UpRate7}"Kbit ceil "${UpCeil7}"Kbit burst "${UpBurst7}" cburst "${UpCburst7}"
} # custom_rates

####################  DO NOT MODIFY BELOW  #####################

set_tc_variables(){

	if [ -e "/usr/sbin/realtc" ]; then
		tc="realtc"
	else
		tc="tc"
	fi

	#read order of QOS categories
	flowid=0
	while read -r line;		# reads users order of QOS categories
	do
		if [ "${line:0:1}" = '[' ]; then
			flowid="${line:1:1}"
		fi
		#logger -s "${line}    ${flowid}"
		case ${line} in
		'0')
			VOIP="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp1}"
			eval "Cat${flowid}UpBandPercent=${urp1}"
			eval "Cat${flowid}DownCeilPercent=${dcp1}"
			eval "Cat${flowid}UpCeilPercent=${ucp1}"
			;;
		'1')
			Downloads="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp7}"
			eval "Cat${flowid}UpBandPercent=${urp7}"
			eval "Cat${flowid}DownCeilPercent=${dcp7}"
			eval "Cat${flowid}UpCeilPercent=${ucp7}"
			;;
		'4')
		if [ -z "$Streaming" ]; then		# only process 4 if streaming not done (only process it once)
			Streaming="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp5}"
			eval "Cat${flowid}UpBandPercent=${urp5}"
			eval "Cat${flowid}DownCeilPercent=${dcp5}"
			eval "Cat${flowid}UpCeilPercent=${ucp5}"
		else
			Defaults="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp6}"
			eval "Cat${flowid}UpBandPercent=${urp6}"
			eval "Cat${flowid}DownCeilPercent=${dcp6}"
			eval "Cat${flowid}UpCeilPercent=${ucp6}"
		fi
			;;
		'7')
			Others="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp3}"
			eval "Cat${flowid}UpBandPercent=${urp3}"
			eval "Cat${flowid}DownCeilPercent=${dcp3}"
			eval "Cat${flowid}UpCeilPercent=${ucp3}"
			;;
		'8')
			Gaming="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp2}"
			eval "Cat${flowid}UpBandPercent=${urp2}"
			eval "Cat${flowid}DownCeilPercent=${dcp2}"
			eval "Cat${flowid}UpCeilPercent=${ucp2}"
			;;
		'9')
			Net="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp0}"
			eval "Cat${flowid}UpBandPercent=${urp0}"
			eval "Cat${flowid}DownCeilPercent=${dcp0}"
			eval "Cat${flowid}UpCeilPercent=${ucp0}"
			;;
		'24')
			Web="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp4}"
			eval "Cat${flowid}UpBandPercent=${urp4}"
			eval "Cat${flowid}DownCeilPercent=${dcp4}"
			eval "Cat${flowid}UpCeilPercent=${ucp4}"
			;;
		'na')
			Defaults="1:1${flowid}"
			eval "Cat${flowid}DownBandPercent=${drp6}"
			eval "Cat${flowid}UpBandPercent=${urp6}"
			eval "Cat${flowid}DownCeilPercent=${dcp6}"
			eval "Cat${flowid}UpCeilPercent=${ucp6}"
			;;
		esac

	done <<EOF
$(sed -E '/^ceil_/d;s/rule=//g;/\{/q' /tmp/bwdpi/qosd.conf | head -n -1)
EOF

	#calculate up/down rates
	DownCeil="$(printf "%.0f" $(nvram get qos_ibw))"
	UpCeil="$(printf "%.0f" $(nvram get qos_obw))"

	i=0
	while [ $i -lt 8 ]
	do
		eval "DownRate$i=$((DownCeil\*Cat${i}DownBandPercent/100))"
		eval "UpRate$i=$((UpCeil\*Cat${i}UpBandPercent/100))"
		eval "DownCeil$i=$((DownCeil\*Cat${i}DownCeilPercent/100))"
		eval "UpCeil$i=$((UpCeil\*Cat${i}UpCeilPercent/100))"
		i="$((i+1))"
	done

	ClassesPresent=0
	#read existing burst/cburst per download class
	while read -r line;
	do
		ClassesPresent=$((ClassesPresent+1))
		if [ "$( echo "${line}" | sed -n -e 's/.*1:10 //p' )" != "" ]; then
			DownBurst0=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst0=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:11 //p' )" != "" ]; then
			DownBurst1=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst1=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:12 //p' )" != "" ]; then
			DownBurst2=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst2=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:13 //p' )" != "" ]; then
			DownBurst3=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst3=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:14 //p' )" != "" ]; then
			DownBurst4=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst4=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:15 //p' )" != "" ]; then
			DownBurst5=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst5=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:16 //p' )" != "" ]; then
			DownBurst6=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst6=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:17 //p' )" != "" ]; then
			DownBurst7=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			DownCburst7=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi
	done < $(tc class show dev br0 | /bin/grep "parent 1:1 ")

	#read existing burst/cburst per upload class
	while read -r line;
	do
		if [ "$( echo "${line}" | sed -n -e 's/.*1:10 //p' )" != "" ]; then
			UpBurst0=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst0=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:11 //p' )" != "" ]; then
			UpBurst1=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst1=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:12 //p' )" != "" ]; then
			UpBurst2=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst2=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:13 //p' )" != "" ]; then
			UpBurst3=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst3=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:14 //p' )" != "" ]; then
			UpBurst4=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst4=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:15 //p' )" != "" ]; then
			UpBurst5=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst5=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:16 //p' )" != "" ]; then
			UpBurst6=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst6=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi

		if [ "$( echo "${line}" | sed -n -e 's/.*1:17 //p' )" != "" ]; then
			UpBurst7=$( echo "${line}" | sed -n -e 's/.* burst \([a-zA-z0-9]*\).*/\1/p' )
			UpCburst7=$( echo "${line}" | sed -n -e 's/.*cburst \([a-zA-z0-9]*\).*/\1/p' )
		fi
	done < $(tc class show dev "$wan" | /bin/grep "parent 1:1 ")

	#read parameters for fakeTC
	PARMS=""
	OVERHEAD=$(nvram get qos_overhead)
	if [ -n "$OVERHEAD" ] && [ "$OVERHEAD" -gt "0" ]; then
		ATM=$(nvram get qos_atm)
		if [ "$ATM" = "1" ]; then
			PARMS="overhead $OVERHEAD linklayer atm "
		else
			PARMS="overhead $OVERHEAD linklayer ethernet "
		fi
	fi
}

## Main Menu -appdb function
appdb(){

	/bin/grep -m 25 -i "${1}" /tmp/bwdpi/bwdpi.app.db | while read -r line; do
		echo "$line" | cut -f 4 -d ","
		cat_decimal=$(echo "$line" | cut -f 1 -d "," )
		cat_hex=$( printf "%02x" "$cat_decimal" )
		case "$cat_decimal" in
		'9'|'18'|'19'|'20')
			echo " Originally:  Net Control"
			;;
		'0'|'5'|'6'|'15'|'17')
			echo " Originally:  VoIP"
			;;
		'8')
			echo " Originally:  Gaming"
			;;
		'7'|'10'|'11'|'21'|'23')
			echo " Originally:  Others"
			;;
		'13'|'24')
			echo " Originally:  Web"
			;;
		'4')
			echo " Originally:  Streaming"
			;;
		'1'|'3'|'14')
			echo " Originally:  Downloads"
			;;
		esac
		echo -n " Mark:        ${cat_hex}"
		echo "$line" | cut -f 2 -d "," | awk '{printf("%04x \n",$1)}'
		echo ""
	done
}

scriptinfo() {
	echo "FlexQoS v${version} released ${release}"
} # scriptinfo

## Main Menu -debug function
debug(){
	scriptinfo
	echo "Debug:"
	echo ""
	set_tc_variables
	current_undf_rule="$(tc filter show dev br0 | /bin/grep -v "/" | /bin/grep "000ffff" -B1)"
	if [ -n "$current_undf_rule" ]; then
		undf_flowid=$(echo "$current_undf_rule" | /bin/grep -o "flowid.*" | cut -d" " -f2 | head -1)
		undf_prio=$(echo "$current_undf_rule" | /bin/grep -o "pref.*" | cut -d" " -f2 | head -1)
	else
		undf_flowid=""
		undf_prio=2
	fi

	logger -t "FlexQoS" -s "Undf Prio: $undf_prio"
	logger -t "FlexQoS" -s "Undf FlowID: $undf_flowid"
	logger -t "FlexQoS" -s "Classes Present: $ClassesPresent"
	logger -t "FlexQoS" -s "Down Band: $DownCeil"
	logger -t "FlexQoS" -s "Up Band  : $UpCeil"
	logger -t "FlexQoS" -s "***********"
	logger -t "FlexQoS" -s "Net Control = $Net"
	logger -t "FlexQoS" -s "Work-From-Home = $VOIP"
	logger -t "FlexQoS" -s "Gaming = $Gaming"
	logger -t "FlexQoS" -s "Others = $Others"
	logger -t "FlexQoS" -s "Web Surfing = $Web"
	logger -t "FlexQoS" -s "Streaming = $Streaming"
	logger -t "FlexQoS" -s "Downloads = $Downloads"
	logger -t "FlexQoS" -s "Defaults = $Defaults"
	logger -t "FlexQoS" -s "***********"
	logger -t "FlexQoS" -s "Downrates -- $DownRate0, $DownRate1, $DownRate2, $DownRate3, $DownRate4, $DownRate5, $DownRate6, $DownRate7"
	logger -t "FlexQoS" -s "Downceils -- $DownCeil0, $DownCeil1, $DownCeil2, $DownCeil3, $DownCeil4, $DownCeil5, $DownCeil6, $DownCeil7"
	logger -t "FlexQoS" -s "Downbursts -- $DownBurst0, $DownBurst1, $DownBurst2, $DownBurst3, $DownBurst4, $DownBurst5, $DownBurst6, $DownBurst7"
	logger -t "FlexQoS" -s "DownCbursts -- $DownCburst0, $DownCburst1, $DownCburst2, $DownCburst3, $DownCburst4, $DownCburst5, $DownCburst6, $DownCburst7"
	logger -t "FlexQoS" -s "***********"
	logger -t "FlexQoS" -s "Uprates -- $UpRate0, $UpRate1, $UpRate2, $UpRate3, $UpRate4, $UpRate5, $UpRate6, $UpRate7"
	logger -t "FlexQoS" -s "Upceils -- $UpCeil0, $UpCeil1, $UpCeil2, $UpCeil3, $UpCeil4, $UpCeil5, $UpCeil6, $UpCeil7"
	logger -t "FlexQoS" -s "Upbursts -- $UpBurst0, $UpBurst1, $UpBurst2, $UpBurst3, $UpBurst4, $UpBurst5, $UpBurst6, $UpBurst7"
	logger -t "FlexQoS" -s "UpCbursts -- $UpCburst0, $UpCburst1, $UpCburst2, $UpCburst3, $UpCburst4, $UpCburst5, $UpCburst6, $UpCburst7"
	logger -t "FlexQoS" -s "***********"
	write_iptables_rules
	cat /tmp/flexqos_iprules | logger -t "FlexQoS" -s
	logger -t "FlexQoS" -s "***********"
	write_appdb_rules
	cat /tmp/flexqos_tcrules | logger -t "FlexQoS" -s
}

## helper function to parse csv nvram variables
read_nvram(){
	OLDIFS=$IFS
	IFS=";"

	if [ $(nvram get fb_comment | sed 's/>/;/g' | tr -cd ';' | wc -c) -eq 20 ] && [ -z "$(am_settings_get flexqos_iptables)" ]; then
		read \
			e1 e2 e3 e4 e5 e6 e7 \
			f1 f2 f3 f4 f5 f6 f7 \
			g1 g2 g3 g4 g5 g6 g7 \
		<<EOF
"$(nvram get fb_comment | sed 's/>/;/g' )"
EOF
	fi
	if [ $(nvram get fb_email_dbg | sed 's/>/;/g' | tr -cd ';' | wc -c) -eq 48 ]; then
		read \
			h1 h2 h3 h4 h5 h6 h7 \
			r1 d1 \
			r2 d2 \
			r3 d3 \
			r4 d4 \
			gameCIDR \
			ruleFLAG \
			drp0 drp1 drp2 drp3 drp4 drp5 drp6 drp7 \
			dcp0 dcp1 dcp2 dcp3 dcp4 dcp5 dcp6 dcp7 \
			urp0 urp1 urp2 urp3 urp4 urp5 urp6 urp7 \
			ucp0 ucp1 ucp2 ucp3 ucp4 ucp5 ucp6 ucp7 \
		<<EOF
"$(nvram get fb_email_dbg | sed 's/>/;/g' )"
EOF
	fi

	IFS=$OLDIFS

	if [ -z "$(am_settings_get flexqos_iptables)" ]; then
		if [ "$gameCIDR" ]; then
			tmp_iptables_rules="<${gameCIDR}>>both>>!80,443>000000>1"
		fi
		tmp_iptables_rules="${tmp_iptables_rules}<>>udp>>500,4500>>3<>>udp>16384:16415>>>3<>>tcp>>119,563>>5<>>tcp>>80,443>08****>7"
		tmp_iptables_rules="${tmp_iptables_rules}<${e1}>${e2}>${e3}>${e4}>${e5}>${e6}>${e7}<${f1}>${f2}>${f3}>${f4}>${f5}>${f6}>${f7}<${g1}>${g2}>${g3}>${g4}>${g5}>${g6}>${g7}<${h1}>${h2}>${h3}>${h4}>${h5}>${h6}>${h7}"
		tmp_iptables_rules=$(echo "$tmp_iptables_rules" | sed 's/<>>>>>>//g')
		am_settings_set flexqos_iptables "$tmp_iptables_rules"
	fi

	if [ -z "$(am_settings_get flexqos_appdb)" ]; then
		tmp_appdb_rules="<000000>6<00006B>6<0D0007>5<0D0086>5<0D00A0>5<12003F>4<13****>4<14****>4<1A****>5"
		tmp_appdb_rules="${tmp_appdb_rules}<${r1}>${d1}<${r2}>${d2}<${r3}>${d3}<${r4}>${d4}"
		tmp_appdb_rules=$(echo "$tmp_appdb_rules" | sed 's/<>//g')
		am_settings_set flexqos_appdb "$tmp_appdb_rules"
	fi

	if [ -z "$(am_settings_get flexqos_bandwidth)" ]; then
		am_settings_set flexqos_bandwidth "<${drp0}>${drp1}>${drp2}>${drp3}>${drp4}>${drp5}>${drp6}>${drp7}<${dcp0}>${dcp1}>${dcp2}>${dcp3}>${dcp4}>${dcp5}>${dcp6}>${dcp7}<${urp0}>${urp1}>${urp2}>${urp3}>${urp4}>${urp5}>${urp6}>${urp7}<${ucp0}>${ucp1}>${ucp2}>${ucp3}>${ucp4}>${ucp5}>${ucp6}>${ucp7}"
	fi

	{
		echo "nvram set fb_comment=\"$(nvram get fb_comment)\""
		echo "nvram set fb_email_dbg=\"$(nvram get fb_email_dbg)\""
		echo "nvram commit"
	} > "${ADDON_DIR}/restore_freshjr_nvram.sh"
	nvram set fb_comment=""
	nvram set fb_email_dbg=""
	nvram commit
}

## helper function for interactive menu mode
dst_2_name() {
	case "$1" in
		0) echo "Net Control" ;;
		1) echo "Gaming" ;;
		2) echo "Streaming" ;;
		3) echo "Work-From-Home" ;;
		4) echo "Web Surfing" ;;
		5) echo "Downloads" ;;
		6) echo "Others" ;;
		7) echo "Game Downloads" ;;
		*) echo "" ;;
	esac
}

## helper function for interactive menu mode
mark_2_name() {
	[ -z "$1" ] && return
	cat="${1:0:2}"
	id="${1:2:4}"
	cat="$(printf "%d" 0x${cat})"
	id="$(printf "%d" 0x${id})"
	/bin/grep "^${cat},${id}," /tmp/bwdpi/bwdpi.app.db | head -n1 |  cut -d',' -f4
}

## helper function - parse parameters into tc syntax
parse_tcrule() {
	##requires global variables previously set by set_tc_variables
	##----------input-----------
	##$1 = mark
	##$2 = dst

	cat="${1:0:2}"
	id="${1:2:4}"

	#filter field
	if [ "${#1}" -eq "6" ]; then
		if [ "${id}" = "****" ]; then
			DOWN_mark="0x80${1//\*/0} 0xc03f0000"
			UP_mark="0x40${1//\*/0} 0xc03f0000"
		elif [ "$1" = "000000" ]; then
			# unidentified traffic has special mask
			DOWN_mark="0x80${1} 0xc000ffff"
			UP_mark="0x40${1} 0xc000ffff"
		else
			DOWN_mark="0x80${1} 0xc03fffff"
			UP_mark="0x40${1} 0xc03fffff"
		fi
	else
		##return early if mark is less than 6 digits
		return
	fi

	#destination field
	case "$2" in
		0)	flowid=${Net};;
		1)	flowid=${Gaming};;
		2)  flowid=${Streaming};;
		3)  flowid=${VOIP};;
		4)  flowid=${Web};;
		5)  flowid=${Downloads};;
		6)  flowid=${Others};;
		7)  flowid=${Defaults};;
		##return early if destination missing
		*)  return ;;
	esac

	#prio field
	if [ "$1" = "000000" ]; then
		# special unidentified traffic rule
		prio="$undf_prio"
	else
		# normal traffic redirection rule
		prio="$(tc filter show dev br0 | /bin/grep -i ${cat}0000 -B1 | /bin/grep 3f0000 -B1 | head -1 | cut -d " " -f7)"
	fi
	currprio=$prio
	if [ -z "${prio}" ]; then
		prio="${undf_prio}"
	else
		prio="$((prio-1))"
	fi

	{
		if [ "${id}" = "****" ] || [ "$1" = "000000" ]; then
			# delete existing rule
			echo "${tc} filter del dev br0 parent 1: prio $currprio > /dev/null 2>&1"
			echo "${tc} filter del dev eth0 parent 1: prio $currprio > /dev/null 2>&1"
			# add new rule at same priority
			echo "${tc} filter add dev br0 protocol all prio $currprio u32 match mark $DOWN_mark flowid $flowid"
			echo "${tc} filter add dev eth0 protocol all prio $currprio u32 match mark $UP_mark flowid $flowid"
		else
			# add new rule for individual app one priority level higher (-1)
			echo "${tc} filter add dev br0 protocol all prio $prio u32 match mark $DOWN_mark flowid $flowid"
			echo "${tc} filter add dev eth0 protocol all prio $prio u32 match mark $UP_mark flowid $flowid"
		fi
	} >> /tmp/flexqos_tcrules
}

## helper function - parse parameters into iptable syntax
parse_iptablerule() {
	##----------input-----------
	#$1=local IP			accepted XXX.XXX.XXX.XXX or !XXX.XXX.XXX.XXX
	#$2=remote IP			accepted XXX.XXX.XXX.XXX or !XXX.XXX.XXX.XXX
	#$3=protocol  			accepted tcp or udp
	#$4=local port			accepted XXXXX or XXXXX:YYYYY or XXX,YYY,ZZZ or  !XXXXX or !XXXXX:YYYYY or !XXX,YYY,ZZZ
	#$5=remote port			accepted XXXXX or XXXXX:YYYYY or XXX,YYY,ZZZ or  !XXXXX or !XXXXX:YYYYY or !XXX,YYY,ZZZ
	#$6=mark				accepted XXYYYY   (setting YYYY to **** will filter entire "XX" parent category)
	#$7=qos destination		accepted 0-7

	#local IP
	if [ "${#1}" -ge "7" ]; then
		DOWN_Lip="${1//[^!]*/} -d ${1//!/}"
		UP_Lip="${1//[^!]*/} -s ${1//!/}"
	else
		DOWN_Lip=""
		UP_Lip=""
	fi

	#remote IP
	if [ "${#2}" -ge "7" ]; then
		DOWN_Rip="${2//[^!]*/} -s ${2//!/}"
		UP_Rip="${2//[^!]*/} -d ${2//!/}"
	else
		DOWN_Rip=""
		UP_Rip=""
	fi

	#protocol (required for port rules)
	if [ "${3}" = 'tcp' ] || [ "${3}" = 'udp' ]; then		#if tcp/udp
		PROTO="-p ${3}"
	else
		if [ "${#4}" -gt "1" ] || [ "${#5}" -gt "1" ]; then		#if both & port rules defined
			PROTO="-p both"		#"BOTH" gets replaced with tcp & udp during later prior to rule execution
		else		#if both & port rules not defined
			PROTO=""
		fi
	fi

	#local port
	if [ "${#4}" -gt "1" ]; then
		if [ "$( echo "${4}" | tr -cd ',' | wc -c )" -ge "1" ]; then
			#multiport XXX,YYY,ZZZ
			DOWN_Lport="-m multiport ${4//[^!]*/} --dports ${4//!/}"
			UP_Lport="-m multiport ${4//[^!]*/} --sports ${4//!/}"
		else
			#single port XXX or port range XXX:YYY
			DOWN_Lport="${4//[^!]*/} --dport ${4//!/}"
			UP_Lport="${4//[^!]*/} --sport ${4//!/}"
		fi
	else
		DOWN_Lport=""
		UP_Lport=""
	fi

	#remote port
	if [ "${#5}" -gt "1" ]; then
		if [ "$( echo "${5}" | tr -cd ',' | wc -c )" -ge "1" ]; then
			#multiport XXX,YYY,ZZZ
			DOWN_Rport="-m multiport ${5//[^!]*/} --sports ${5//!/}"
			UP_Rport="-m multiport ${5//[^!]*/} --dports ${5//!/}"
		else
			#single port XXX or port range XXX:YYY
			DOWN_Rport="${5//[^!]*/} --sport ${5//!/}"
			UP_Rport="${5//[^!]*/} --dport ${5//!/}"
		fi
	else
		DOWN_Rport=""
		UP_Rport=""
	fi

	#match mark
	if [ "${#6}" -eq "6" ]; then
		if [ "${6:2:4}" = "****" ]; then
			DOWN_mark="-m mark --mark 0x80${6//\*/0}/0xc03f0000"
			UP_mark="-m mark --mark 0x40${6//\*/0}/0xc03f0000"
		else
			DOWN_mark="-m mark --mark 0x80${6}/0xc03fffff"
			UP_mark="-m mark --mark 0x40${6}/0xc03fffff"
		fi
	else
		DOWN_mark=""
		UP_mark=""
	fi

	##if parameters are empty return early
	if [ -z "${DOWN_Lip}${DOWN_Rip}${DOWN_Lport}${DOWN_Rport}${DOWN_mark}" ]; then
		return
	fi

	#destination mark
	case "$7" in
		0)
			DOWN_dst="-j MARK --set-mark ${Net_mark_down}"
			UP_dst="-j MARK --set-mark ${Net_mark_up}"
			;;
		1)
			DOWN_dst="-j MARK --set-mark ${Gaming_mark_down}"
			UP_dst="-j MARK --set-mark ${Gaming_mark_up}"
			;;
		2)
			DOWN_dst="-j MARK --set-mark ${Streaming_mark_down}"
			UP_dst="-j MARK --set-mark ${Streaming_mark_up}"
			;;
		3)
			DOWN_dst="-j MARK --set-mark ${VOIP_mark_down}"
			UP_dst="-j MARK --set-mark ${VOIP_mark_up}"
			;;
		4)
			DOWN_dst="-j MARK --set-mark ${Web_mark_down}"
			UP_dst="-j MARK --set-mark ${Web_mark_up}"
			;;
		5)
			DOWN_dst="-j MARK --set-mark ${Downloads_mark_down}"
			UP_dst="-j MARK --set-mark ${Downloads_mark_up}"
			;;
		6)
			DOWN_dst="-j MARK --set-mark ${Others_mark_down}"
			UP_dst="-j MARK --set-mark ${Others_mark_up}"
			;;
		7)
			DOWN_dst="-j MARK --set-mark ${Default_mark_down}"
			UP_dst="-j MARK --set-mark ${Default_mark_up}"
			;;
		*)
			##if destinations is empty return early
			return
			;;
	esac

	{
		if [ "$PROTO" = "both" ]; then
			# download ipv4
			echo "iptables -D POSTROUTING -t mangle -o br0 ${DOWN_Lip} ${DOWN_Rip} ${PROTO//both/tcp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst} >/dev/null 2>&1" | sed 's/  */ /g'
			echo "iptables -A POSTROUTING -t mangle -o br0 ${DOWN_Lip} ${DOWN_Rip} ${PROTO//both/tcp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst}" | sed 's/  */ /g'
			echo "iptables -D POSTROUTING -t mangle -o br0 ${DOWN_Lip} ${DOWN_Rip} ${PROTO//both/udp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst} >/dev/null 2>&1" | sed 's/  */ /g'
			echo "iptables -A POSTROUTING -t mangle -o br0 ${DOWN_Lip} ${DOWN_Rip} ${PROTO//both/udp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst}" | sed 's/  */ /g'
			# upload ipv4
			echo "iptables -D POSTROUTING -t mangle -o ${wan} ${UP_Lip} ${UP_Rip} ${PROTO//both/tcp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst} >/dev/null 2>&1" | sed 's/  */ /g'
			echo "iptables -A POSTROUTING -t mangle -o ${wan} ${UP_Lip} ${UP_Rip} ${PROTO//both/tcp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst}" | sed 's/  */ /g'
			echo "iptables -D POSTROUTING -t mangle -o ${wan} ${UP_Lip} ${UP_Rip} ${PROTO//both/udp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst} >/dev/null 2>&1" | sed 's/  */ /g'
			echo "iptables -A POSTROUTING -t mangle -o ${wan} ${UP_Lip} ${UP_Rip} ${PROTO//both/udp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst}" | sed 's/  */ /g'
			if [ -z "$DOWN_Lip" ] && [ -z "$DOWN_Rip" ] && [ "$ipv6_enabled" != "disabled" ]; then
				# download ipv6
				echo "ip6tables -D POSTROUTING -t mangle -o br0 ${PROTO//both/tcp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst} >/dev/null 2>&1" | sed 's/  */ /g'
				echo "ip6tables -A POSTROUTING -t mangle -o br0 ${PROTO//both/tcp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst}" | sed 's/  */ /g'
				echo "ip6tables -D POSTROUTING -t mangle -o br0 ${PROTO//both/udp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst} >/dev/null 2>&1" | sed 's/  */ /g'
				echo "ip6tables -A POSTROUTING -t mangle -o br0 ${PROTO//both/udp} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst}" | sed 's/  */ /g'
				# upload ipv6
				echo "ip6tables -D POSTROUTING -t mangle -o ${wan} ${PROTO//both/tcp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst} >/dev/null 2>&1" | sed 's/  */ /g'
				echo "ip6tables -A POSTROUTING -t mangle -o ${wan} ${PROTO//both/tcp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst}" | sed 's/  */ /g'
				echo "ip6tables -D POSTROUTING -t mangle -o ${wan} ${PROTO//both/udp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst} >/dev/null 2>&1" | sed 's/  */ /g'
				echo "ip6tables -A POSTROUTING -t mangle -o ${wan} ${PROTO//both/udp} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst}" | sed 's/  */ /g'
			fi
		else
			# download ipv4
			echo "iptables -D POSTROUTING -t mangle -o br0 ${DOWN_Lip} ${DOWN_Rip} ${PROTO} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst} >/dev/null 2>&1" | sed 's/  */ /g'
			echo "iptables -A POSTROUTING -t mangle -o br0 ${DOWN_Lip} ${DOWN_Rip} ${PROTO} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst}" | sed 's/  */ /g'
			# upload ipv4
			echo "iptables -D POSTROUTING -t mangle -o ${wan} ${UP_Lip} ${UP_Rip} ${PROTO} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst} >/dev/null 2>&1" | sed 's/  */ /g'
			echo "iptables -A POSTROUTING -t mangle -o ${wan} ${UP_Lip} ${UP_Rip} ${PROTO} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst}" | sed 's/  */ /g'
			if [ -z "$DOWN_Lip" ] && [ -z "$DOWN_Rip" ] && [ "$ipv6_enabled" != "disabled" ]; then
				# download ipv6
				echo "ip6tables -D POSTROUTING -t mangle -o br0 ${PROTO} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst} >/dev/null 2>&1" | sed 's/  */ /g'
				echo "ip6tables -A POSTROUTING -t mangle -o br0 ${PROTO} ${DOWN_Lport} ${DOWN_Rport} ${DOWN_mark} ${DOWN_dst}" | sed 's/  */ /g'
				# upload ipv6
				echo "ip6tables -D POSTROUTING -t mangle -o ${wan} ${PROTO} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst} >/dev/null 2>&1" | sed 's/  */ /g'
				echo "ip6tables -A POSTROUTING -t mangle -o ${wan} ${PROTO} ${UP_Lport} ${UP_Rport} ${UP_mark} ${UP_dst}" | sed 's/  */ /g'
			fi
		fi
	} >> /tmp/flexqos_iprules
}

about() {
	# clear
	scriptinfo
	echo ""
	echo "License"
	echo "  FlexQoS is free to use under the GNU General Public License, version 3 (GPL-3.0)."
	echo "  https://opensource.org/licenses/GPL-3.0"
	echo ""
	echo "For discussion visit this thread:"
	echo "  https://www.snbforums.com/threads/release-freshjr-adaptive-qos-improvements-custom-rules-and-inner-workings.36836/"
	echo "  https://github.com/dave14305/FlexQoS (Source Code)"
	echo ""
	echo "About"
	echo '  Script Changes Unidentified traffic destination away from "Defaults" into "Others"'
	echo '  Script Changes HTTPS traffic destination away from "Net Control" into "Web Surfing"'
	echo '  Script Changes Guaranteed Bandwidth per QOS category into logical percentages of upload and download.'
	echo '  Script Repurposes "Learn-From-Home" to contain "Game Downloads"'
	echo ""
	echo '  Script includes misc default rules'
	echo '   (Wifi Calling)  -  UDP traffic on remote ports 500 & 4500 moved into VOIP'
	echo '   (Facetime)      -  UDP traffic on local  ports 16384 - 16415 moved into VOIP '
	echo '   (Usenet)        -  TCP traffic on remote ports 119 & 563 moved into Downloads '
	echo '   (Gaming)        -  Gaming TCP traffic from remote ports 80 & 443 moved into Game Downloads.'
	echo '   (Snapchat)      -  Moved into Others'
	echo '   (Speedtest.net) -  Moved into Downloads'
	echo '   (Google Play)   -  Moved into Downloads'
	echo '   (Apple AppStore)-  Moved into Downloads'
	echo '   (Advertisement) -  Moved into Downloads'
	echo '   (VPN Fix)       -  Router VPN Client upload traffic moved into Downloads instead of whitelisted'
	echo '   (VPN Fix)       -  Router VPN Client download traffic moved into Downloads instead of showing up in Uploads'
	echo '   (Gaming Manual) -  Unidentified traffic for specified devices, not originating from ports 80/443, moved into "Gaming"'
	echo ""
	echo 'Gaming Rule Note'
	echo '  Gaming traffic originating from ports 80 & 443 is primarily downloads & patches (some lobby/login protocols mixed within)'
	echo '  Manually configurable rule will take untracked traffic for specified devices, not originating from server ports 80/443, and place it into Gaming'
	echo '  Use of this gaming rule REQUIRES devices to have a continous static ip assignment && this range needs to be passed into the script'
}

# From Adamm00
check_connection() {
	livecheck="0"
	while [ "$livecheck" != "2" ]; do
		if ping -q -w3 -c1 raw.githubusercontent.com >/dev/null 2>&1; then
			break
		else
			livecheck="$((livecheck + 1))"
			if [ "$livecheck" != "2" ]; then
				sleep 3
			else
				return "1"
			fi
		fi
	done
} # check_connection

download_file() {
	if [ "$(curl -fsL --retry 3 --connect-timeout 3 "${GIT_URL}/${1}" | md5sum | awk '{print $1}')" != "$(md5sum "$2" 2>/dev/null | awk '{print $1}')" ]; then
		if curl -fsL --retry 3 --connect-timeout 3 "${GIT_URL}/${1}" -o "$2"; then
			logger -t "FlexQoS" "Updated $(echo "$1" | awk -F / '{print $NF}')"
		else
			logger -t "FlexQoS" "Updating $(echo "$1" | awk -F / '{print $NF}') failed"
		fi
	else
		logger -t "FlexQoS" "File $(echo $2 | awk -F / '{print $NF}') is already up-to-date"
	fi
} # download_file

update() {
	# clear
	scriptinfo
	echo "Checking for updates"
	echo ""
	url="${GIT_URL}/flexqos.sh"
	remotever=$(curl -fsN --retry 3 ${url} | /bin/grep "^version=" | sed -e s/version=//)

	if [ "$version" != "$remotever" ]; then
		echo " FlexQoS v${remotever} is now available!"
		echo ""
		echo -n " Would you like to update now? [1=Yes 2=No] : "
		read -r yn
		echo ""
		if ! [ "${yn}" = "1" ]; then
			echo " No Changes have been made"
			echo ""
			return 0
		fi
	else
		echo " You have the latest version installed"
		echo -n " Would you like to overwrite your existing installation anyway? [1=Yes 2=No] : "
		read -r yn
		echo ""
		if ! [ "${yn}" = "1"  ]; then
			echo " No Changes have been made"
			echo ""
			return 0
		fi
	fi

	echo "Installing: FlexQoS v${remotever}"
	echo ""
	echo "Curl Output:"
	curl "${GIT_URL}/flexqos.sh" -o ${SCRIPTPATH} --create-dirs && curl "${GIT_URL}/flexqos.asp" -o "${WEBUIPATH}" && sh ${SCRIPTPATH} -install
	exit
}

prompt_restart() {
	echo ""
	echo -n " Would you like to [Restart QoS] for modifications to take effect? [1=Yes 2=No] : "
	read -r yn
	if [ "${yn}" = "1" ]; then
		if /bin/grep -q -x "${SCRIPTPATH} -start \$1 & " /jffs/scripts/firewall-start ; then		#RMerlin install
			service "restart_qos;restart_firewall"
		fi
		echo ""
	else
		echo ""
		if /bin/grep -q -x "${SCRIPTPATH} -start \$1 & " /jffs/scripts/firewall-start ; then		#RMerlin install
			echo "  Remember: [ Restart QOS ] for modifications to take effect"
			echo ""
		fi
	fi
} # prompt_restart

menu() {
	# clear
	echo "FlexQoS v${version} released ${release}"
	echo "  (1) about        explain functionality"
	echo "  (2) update       check for updates "
	echo "  (3) debug        traffic control parameters"
	echo "  (u) uninstall    uninstall script"
	echo "  (e) exit"
	echo ""
	echo -n "Make a selection: "
	read -r input
	case $input in
		'1')
			about
			;;
		'2')
			update
			;;
		'3')
			debug
			;;
		'u'|'U')
			# clear
			echo "FlexQoS v${version} released ${release}"
			echo ""
			echo -n " Confirm you want to uninstall FlexQoS [1=Yes 2=No] : "
			read -r yn
			if [ "${yn}" = "1" ]; then
				echo ""
				sh ${SCRIPTPATH} -uninstall
				echo ""
				exit
			fi
			echo ""
			echo "FlexQoS has NOT been uninstalled"
			;;
		'e'|'E')
			return
			;;
	esac
	menu
}

remove_webui() {
	am_get_webui_page "$WEBUIPATH"

	if [ -n "$am_webui_page" ] && [ "$am_webui_page" != "none" ]; then
		if [ -f /tmp/menuTree.js ]; then
			umount /www/require/modules/menuTree.js 2>/dev/null
			sed -i "\~tabName: \"FlexQoS\"},~d" /tmp/menuTree.js
			if diff /tmp/menuTree.js /www/require/modules/menuTree.js; then
				rm /tmp/menuTree.js
			else
				# Still some modifications from another script so remount
				mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
			fi
			if [ -f /www/user/"$am_webui_page" ]; then
				rm /www/user/"$am_webui_page"
			fi
		fi
		for i in $(/bin/grep -l FlexQoS /www/user/user*.asp 2>/dev/null)
		do
			rm "$i"
		done
	fi
	rm -rf /www/user/flexqos		# remove js helper scripts
}

install_webui() {
	if [ -z "$1" ]; then
		download_file "${GIT_URL}/flexqos.asp" "$WEBUIPATH"
		mkdir -p "${ADDON_DIR}/table"
		download_file "${GIT_URL|/table.js" "${ADDON_DIR}/table/table.js"
		download_file "${GIT_URL|/tableValidator.js" "${ADDON_DIR}/table/tableValidator.js"
	fi
	am_get_webui_page "$WEBUIPATH"
	if [ "$am_webui_page" = "none" ]; then
		logger -t "FlexQoS" -s "No API slots to install web page"
	elif [ ! -f /www/user/"$am_webui_page" ]; then
		cp "$WEBUIPATH" /www/user/"$am_webui_page"
		if [ ! -f /tmp/menuTree.js ]; then
			cp /www/require/modules/menuTree.js /tmp/
			mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
		fi
		if ! /bin/grep -q "{url: \"$am_webui_page\", tabName: \"FlexQoS\"}," /tmp/menuTree.js; then
			umount /www/require/modules/menuTree.js 2>/dev/null
			sed -i "\~tabName: \"FlexQoS\"},~d" /tmp/menuTree.js
			sed -i "/url: \"QoS_Stats.asp\", tabName:/a {url: \"$am_webui_page\", tabName: \"FlexQoS\"}," /tmp/menuTree.js
			mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
		fi
	fi
	ln -sf "${ADDON_DIR}/table" /www/user/flexqos
}

Auto_ServiceEventEnd() {
	# Borrowed from Adamm00
	# https://github.com/Adamm00/IPSet_ASUS/blob/master/firewall.sh
	if [ ! -f "/jffs/scripts/service-event-end" ]; then
			echo "#!/bin/sh" > /jffs/scripts/service-event-end
			echo >> /jffs/scripts/service-event-end
	elif [ -f "/jffs/scripts/service-event-end" ] && ! head -1 /jffs/scripts/service-event-end | /bin/grep -qE "^#!/bin/sh"; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/service-event-end
	fi
	if [ ! -x "/jffs/scripts/service-event-end" ]; then
		chmod 755 /jffs/scripts/service-event-end
	fi
	if ! /bin/grep -vE "^#" /jffs/scripts/service-event-end | /bin/grep -qE "restart.*wrs.*sh ${SCRIPTPATH}"; then
		cmdline="if [ \"\$1\" = \"restart\" ] && [ \"\$2\" = \"wrs\" ]; then sh ${SCRIPTPATH} -check; fi # FlexQoS Addition"
		sed -i '\~\"wrs\".*# FlexQoS Addition~d' /jffs/scripts/service-event-end
		echo "$cmdline" >> /jffs/scripts/service-event-end
	fi
}

Auto_FirewallStart() {
	if [ -f /jffs/scripts/firewall-start ]; then		#check if firewall-start exists
		if ! /bin/grep -q "#!/bin/sh" /jffs/scripts/firewall-start ; then		#check if firewall-start header is correct
			#if header is incorrect, fix header
			echo "Detected improper header in firewall-start, fixing header"
			sed -i "1i #!/bin/sh" /jffs/scripts/firewall-start
			chmod 0755 /jffs/scripts/firewall-start
		fi

		if ! /bin/grep -q -x "${SCRIPTPATH} -start \$1 & " /jffs/scripts/firewall-start ; then		#check if FlexQoS is present as item in firewall start
			#if not, appened it to the last line (also delete any previously formated entry)
			echo "Placing FlexQoS entry into firewall-start"
			sed -i '/flexqos/d' /jffs/scripts/firewall-start
			echo "${SCRIPTPATH} -start \$1 & # FlexQoS Addition" >> /jffs/scripts/firewall-start
		fi
	else		#if firewall-start does not exist then set it up entirely
		echo "Firewall-start not detected, creating firewall-start"
		echo "Placing FlexQoS entry into firewall-start"
		echo "#!/bin/sh" > /jffs/scripts/firewall-start
		echo "${SCRIPTPATH} -start \$1 & # FlexQoS Addition" >> /jffs/scripts/firewall-start
		chmod 0755 /jffs/scripts/firewall-start
	fi
} # Auto_FirewallStart

Auto_Crontab() {
	cru a flexqos "30 3 * * * ${SCRIPTPATH} -check"
} # Auto_Crontab

setup_aliases() {
	# shortcuts to launching FlexQoS
	sed -i '/flexqos/d' /jffs/configs/profile.add 2>/dev/null
	if [ -d /opt/bin ]; then
		ln -sf "$SCRIPTPATH" /opt/bin/flexqos
	else
		alias flexqos="sh ${SCRIPTPATH} -menu"
		echo "alias flexqos=\"sh ${SCRIPTPATH} -menu\"" >> /jffs/configs/profile.add
	fi
} # setup_aliases

Uninstall_FreshJR() {
	echo "Removing old FreshJR_QOS files. Reinstall with amtm if necessary."
	# Remove profile aliases
	echo -n "Removing profile aliases..."
	sed -i '/FreshJR_QOS/d' /jffs/configs/profile.add 2>/dev/null && echo "Done." || echo "Failed!"
	# Remove cron
	echo -n "Removing cron job..."
	cru d FreshJR_QOS 2>/dev/null && echo "Done." || echo "Failed!"
	# Remove mount
	if mount | /bin/grep -q www_FreshJR_QoS_Stats.asp; then
		echo -n "Removing old webui mount..."
		umount /www/QoS_Stats.asp 2>/dev/null && echo "Done." || echo "Failed!"
	fi
	# Remove entries from scripts
	echo -n "Removing firewall-start entry..."
	sed -i '/FreshJR_QOS/d' /jffs/scripts/firewall-start 2>/dev/null && echo "Done." || echo "Failed!"
	# Remove script file
	if [ -f /jffs/scripts/FreshJR_QOS ]; then
		echo -n "Removing FreshJR_QOS script..."
		rm -f /jffs/scripts/FreshJR_QOS 2>/dev/null && echo "Done." || echo "Failed!"
	fi
	# Remove asp file
	if [ -f /jffs/scripts/www_FreshJR_QoS_Stats.asp ]; then
		echo -n "Removing FreshJR_QOS webpage..."
		rm -f /jffs/scripts/www_FreshJR_QoS_Stats.asp 2>/dev/null && echo "Done." || echo "Failed!"
	fi
	# leave NVRAM var for now, or convert to settings?
} # Uninstall_FreshJR

Firmware_Check() {
	local fwplatform="$(uname -o)"
	local fwver="$(nvram get buildno)"
	local fwmaj="$(echo "$fwver" | cut -d. -f1)"
	local fwmin="$(echo "$fwver" | cut -d. -f2)"
	if [ "$fwplatform" != "ASUSWRT-Merlin" ]; then
		echo "This version of FlexQoS requires ASUSWRT-Merlin. Stock firmware is no longer supported."
		exit 3
	fi
	if [ "$fwmaj" -ge "384" ] && [ "$fwmin" -ge "18" ]; then
		true
	else
		echo "FlexQoS requires ASUSWRT-Merlin 384.18 or higher. Installation aborted"
		exit 5
	fi
} # Firmware_Check

install() {
	# clear
	Firmware_Check
	Uninstall_FreshJR
	if ! [ -d "$ADDON_DIR" ]; then
		mkdir -p "$ADDON_DIR"
		chmod 755 "$ADDON_DIR"
	fi
	if ! [ -f "$SCRIPTPATH" ]; then
		download_file "flexqos.sh" "$SCRIPTPATH"
	fi
	if ! [ -x "$SCRIPTPATH" ]; then
		chmod 0755 "$SCRIPTPATH"
	fi
	install_webui
	Auto_FirewallStart
	Auto_ServiceEventEnd
	Auto_Crontab
	setup_aliases

	scriptinfo
	echo ""
	echo -n " Advanced configuration available via: "
	echo "http://$(nvram get lan_ipaddr_rt):$(nvram get http_lanport)/$am_webui_page"		# TODO add logic to detect https only
	[ "$(nvram get qos_enable)" = "1" ] && prompt_restart
} # install

uninstall() {
	sed -i '/FlexQoS/d' /jffs/scripts/firewall-start 2>/dev/null
	sed -i '\~\"wrs\".*# FlexQoS Addition~d' /jffs/scripts/service-event-end
	sed -i '/flexqos/d' /jffs/configs/profile.add 2>/dev/null
	cru d flexqos
	sed -i '/flexqos/d' /jffs/configs/profile.add
	rm -f /opt/bin/flexqos
	rm -f "$SCRIPTPATH"

	remove_webui
	rm -f "${WEBUIPATH}"

	sed -i '/^flexqos_/d' /jffs/addons/custom_settings.txt
	echo "FlexQoS has been uninstalled"
} # uninstall

get_config() {
	iptables_rules="$(am_settings_get flexqos_iptables)"
	appdb_rules="$(am_settings_get flexqos_appdb)"
	read \
		drp0 drp1 drp2 drp3 drp4 drp5 drp6 drp7 \
		dcp0 dcp1 dcp2 dcp3 dcp4 dcp5 dcp6 dcp7 \
		urp0 urp1 urp2 urp3 urp4 urp5 urp6 urp7 \
		ucp0 ucp1 ucp2 ucp3 ucp4 ucp5 ucp6 ucp7 \
<<EOF
$(am_settings_get flexqos_bandwidth | sed 's/^<//g;s/[<>]/ /g')
EOF
} # get_config

write_iptables_rules() {
	# loop through iptables rules and write an iptables command to a temporary script file
	OLDIFS="$IFS"
	IFS=">"
	if [ -f "/tmp/flexqos_iprules" ]; then
		rm -f "/tmp/flexqos_iprules"
	fi

	echo "$iptables_rules" | sed 's/</\n/g' | while read -r localip remoteip proto lport rport mark class
	do
		if [ -n "${localip}${remoteip}${proto}${lport}${rport}${mark}" ]; then
			parse_iptablerule "$localip" "$remoteip" "$proto" "$lport" "$rport" "$mark" "$class"
		fi
	done
	IFS="$OLDIFS"
	# [ -f "/tmp/flexqos_iprules" ] && . /tmp/flexqos_iprules
} # write_iptables_rules

write_appdb_rules() {
	# loop through appdb rules and write a tc command to a temporary script file
	OLDIFS="$IFS"
	IFS=">"
	if [ -f "/tmp/flexqos_tcrules" ]; then
		rm -f "/tmp/flexqos_tcrules"
	fi

	echo "$appdb_rules" | sed 's/</\n/g' | while read -r mark class
	do
		if [ -n "${mark}" ]; then
			parse_tcrule "$mark" "$class"
		fi
	done
	IFS="$OLDIFS"
} # write_appdb_rules

check_qos_tc() {
	dlclasscnt="$(tc class show dev br0 | /bin/grep -c "parent 1:1 ")"
	ulclasscnt="$(tc class show dev eth0 | /bin/grep -c "parent 1:1 ")"
	dlfiltercnt="$(tc filter show dev br0 | /bin/grep -cE "flowid 1:1[0-7] $")"
	ulfiltercnt="$(tc filter show dev eth0 | /bin/grep -cE "flowid 1:1[0-7] $")"
	#return ${dlclasscnt}+${ulclasscnt}+${dlfiltercnt}+${ulfiltercnt}
} # check_qos_tc

start() {
	if [ "$(nvram get qos_enable)" = "1" ] && [ "$(nvram get qos_type)" = "1" ]; then
		for pid in $(pidof flexqos); do
			if [ "$pid" != $$ ]; then
				if ! ps -w | /bin/grep -q "^\s*${pid}\s.*\(install\|menu\)"; then		#kill all previous instances of flexqos (-install, -menu instances are whitelisted)
					kill "$pid"
					logger -t "FlexQoS" -s "Delayed Start Canceled (${pid})"
				fi
			fi
		done

		install_webui mount
		generate_bwdpi_arrays
		get_config

		if [ -n "$1" ]; then
			##iptables rules will only be reapplied on firewall "start" due to receiving interface name

			write_iptables_rules
			exit
			iptables_static_rules 2>&1 | logger -t "FlexQoS"
			if [ -s "/tmp/flexqos_iprules" ]; then
				logger -t "FlexQoS" "Applying custom user rules"
				. /tmp/flexqos_iprules | logger -t "FlexQoS"
				logger -t "FlexQoS" "Finished applying custom user rules"
			fi

			sleepdelay=0
			while [ "$(tc class show dev br0 | /bin/grep -c "parent 1:1 ")" -lt 8 ] && [ "$(tc class show dev eth0 | /bin/grep -c "parent 1:1 ")" -lt 8 ];
			do
				[ "$sleepdelay" = "0" ] && logger -t "FlexQoS" -s "TC Modification Delayed Start"
				sleep 10s
				if [ "$sleepdelay" -gt 300 ]; then
					logger -t "FlexQoS" -s "TC Modification Delay reached maximum 300 seconds"
					break
				fi
				sleepdelay=$((sleepdelay+10))
			done
			logger -t "FlexQoS" -s "TC Modification Delay ended after $sleepdelay seconds"
		fi

		current_undf_rule="$(tc filter show dev br0 | /bin/grep "00ffff" -B1)"
		if [ -n "$current_undf_rule" ]; then
			undf_flowid=$(echo "$current_undf_rule" | /bin/grep -o "flowid.*" | cut -d" " -f2 | head -1)
			undf_prio=$(echo "$current_undf_rule" | /bin/grep -o "pref.*" | cut -d" " -f2 | head -1)
		else
			undf_flowid=""
			undf_prio=2
		fi
		#if TC modifcations have not been applied then run modification script
		#eg (if rule setting unidentified traffic to 1:17 exists) --> run modification script
		if [ "${undf_flowid}" = "1:17" ] || [ -z "${undf_flowid}" ]; then
			if [ -z "$1" ]; then
				# check action was called without a WAN interface passed
				logger -t "FlexQoS" -s "Scheduled Persistence Check -> Reapplying Changes"
			fi # check

			set_tc_variables 	#needs to be set before parse_tcrule
			write_appdb_rules
			tc_redirection_static_rules 2>&1 | logger -t "FlexQoS"		#forwards terminal output & errors to logger

			if [ "$ClassesPresent" -lt "8" ]; then
				logger -t "FlexQoS" -s "Adaptive QOS not fully done setting up prior to modification script"
				logger -t "FlexQoS" -s "(Skipping class modification, delay trigger time period needs increase)"
			else
				if [ "$DownCeil" -gt "500" ] && [ "$UpCeil" -gt "500" ]; then
					custom_rates 2>&1 | logger -t "FlexQoS"		#forwards terminal output & errors to logger
				fi
			fi # Classes less than 8
		else # 1:17
			if [ "$1" = "check" ]; then
				logger -t "FlexQoS" -s "Scheduled Persistence Check -> No modifications necessary"
			else
				logger -t "FlexQoS" -s "No modifications necessary"
			fi
		fi # 1:17
	fi # adaptive qos enabled
} # start

show_help() {
	# clear
	scriptinfo
	echo "released ${release}"
	echo ""
	echo "You have inputted an UNRECOGNIZED COMMAND"
	echo ""
	echo "  Available commands:"
	echo ""
	echo "  flexqos -about              explains functionality"
	echo "  flexqos -update             checks for updates "
	echo ""
	echo "  flexqos -install            install   script"
	echo "  flexqos -uninstall          uninstall script && delete from disk "
	echo ""
	echo "  flexqos -enable             enable    script "
	echo "  flexqos -disable            disable   script but do not delete from disk"
	echo ""
	echo "  flexqos -debug              print traffic control parameters"
	echo ""
	echo '  flexqos -menu               interactive main menu'
	echo ""
} # show_help

generate_bwdpi_arrays() {
	# generate if not exist, plus after wrs restart (signature update)
	if ! [ -f /www/user/ext/flexqos_arrays.js ] || [ /tmp/bwdpi.app.db -nt /www/user/ext/flexqos_arrays.js ]; then
	{
		awk -F, 'BEGIN { printf "var catdb_mark_array = [ \"000000\", "} { printf("\"%02X****\", ",$1) }' /tmp/bwdpi/bwdpi.cat.db
		awk -F, '{ printf("\"%02X%04X\", ",$1,$2) } END { printf "\"\" ]\;" }' /tmp/bwdpi/bwdpi.app.db
		awk -F, 'BEGIN { printf "var catdb_label_array = [ \"Untracked\", "} { printf("\"%s\", ",$2) }' /tmp/bwdpi/bwdpi.cat.db
		awk -F, '{ printf("\"%s\", ",$4) } END { printf "\"\" ]\;" }' /tmp/bwdpi/bwdpi.app.db
	} > /www/ext/flexqos_arrays.js
	fi
}

################################################################################
# Main program
################################################################################

arg1="$(echo "$1" | tr -d "-")"
if [ -z "$2" ]; then
	wan="$(nvram get wan0_ifname)"
else
	wan="$2"
fi

case "$arg1" in
	'start')
		# triggered from firewall-start with wan iface passed
		start "$wan"
		;;
	'check')
		# triggered from cron or service-event-end without wan iface
		start
		;;
	'install'|'enable')		# INSTALLS AND TURNS ON SCRIPT
		install
		;;
	'uninstall')		# UNINSTALLS SCRIPT AND DELETES FILES
		uninstall
		;;
	'disable')		# TURNS OFF SCRIPT BUT KEEP FILES
		sed -i '/flexqos/d' /jffs/scripts/firewall-start  2>/dev/null
		sed -i '/flexqos/d' /jffs/scripts/service-event-end  2>/dev/null
		cru d flexqos
		remove_webui
		;;
	'debug*')
		debug
		;;
	'about')
		about
		;;
	'update')
		update
		;;
	'menu')
		menu
		;;
	*)
		show_help
		;;
esac
