#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
# SC2004,SC2154,SC2181
# bash /volume1/homes/admin/scripts/bash/plex/syno.plexinfo.sh

SCRIPT_VERSION=2.1.1

# Function to get Script information
get_source_info() {
  srcScrpVer=${SCRIPT_VERSION}                                                                    # Source script version
  srcFullPth=$(readlink -f "${BASH_SOURCE[0]}")                                                   # Source script absolute path of script
  srcDirctry=$(dirname "$srcFullPth")                                                             # Source script directory containing script
  srcFileNam=${srcFullPth##*/}                                                                    # Source script script file name
}
get_source_info

# Function to stop redirect logging
stop_logging_redirect() {
  set +x                                                                                          # Disable xtrace output for debug file
  exec 1>&2 2>&1                                                                                  # Close and normalize the logging redirections
}

# Function to start redirect logging
start_logging_redirect() {
  exec > >(tee "$srcFullPth.log") 2>"$srcFullPth.debug"                                           # Redirect stdout to tee in order to duplicate the output to the terminal as well as a . log file
  set -x                                                                                          # Enable xtrace output for debug file
}
start_logging_redirect
trap 'stop_logging_redirect' EXIT

# Parse script arguments
SHOW_SECRET=0
for arg in "$@"; do
  if [[ "$arg" == "-x" ]]; then
    SHOW_SECRET=1
  fi
done

boolean_risk() {
  case "$1" in
    true)  echo "Disabled" ;;
    false) echo "Enabled (SECURITY RISK)" ;;
    *)     echo "Undefined (???)" ;;
  esac
}

get_smb_multichannel_status() {
  nasSmb3Mlt="Unavailable"
  local enabled statusLine
  declare -A pid_ip_map
  declare -A ip_iface_map
  ipMatch=()

  # Check if multichannel is enabled
  enabled=$(testparm -s 2>/dev/null | awk -F= '/^[[:space:]]*server multi channel support/ { gsub(/[[:space:]]*/, "", $2); print tolower($2) }')

  if [[ "$enabled" == "yes" && -x "$(command -v smbstatus)" ]]; then
    statusLine=$(smbstatus -v --show-multichannel 2>/dev/null)

    # Build mapping of interface IPs
    while IFS= read -r line; do
      iface=${line%%:*}
      ip=$(xargs <<< "${line#*: }")
      ip_iface_map["$ip"]="$iface"
    done <<< "$nasIntrnIP"

    # Group server IPs by their PID
    while read -r pid _ srvip _; do
      ip_clean=$(sed -E 's/^ipv4:|:[0-9]+$//g' <<< "$srvip")
      pid_ip_map["$pid"]+="$ip_clean "
    done <<< "$(awk '/^ *[0-9]+ +[0-9]+ +ipv4:/' <<< "$statusLine")"

    # Loop over all PIDs to find valid multichannel groups
    for pid in "${!pid_ip_map[@]}"; do
      IFS=' ' read -r -a ip_list <<< "${pid_ip_map[$pid]}"
      if ((${#ip_list[@]} >= 2)); then
        for ip in "${ip_list[@]}"; do
          iface="${ip_iface_map[$ip]}"
          if [[ -n "$iface" ]]; then
            ipMatch+=("$ip ($iface) [SMBMC Pid: $pid]")
          fi
        done
      fi
    done

    if ((${#ipMatch[@]})); then
      nasSmb3Mlt="Enabled (active)"
      nasIntrnIP=$(printf "%s\n" "${ipMatch[@]}")
    else
      nasSmb3Mlt="Enabled (inactive)"
    fi
  else
    nasSmb3Mlt="Disabled"
  fi
}

# Function to get NAS information
get_nas_info() {
  nasHwModel=$(cat /proc/sys/kernel/syno_hw_version)                                              # NAS model
  nasMchArch=$(uname --machine)                                                                   # NAS machine architecture
  case "$nasMchArch" in
    i686)    nasMchArch="x86" ;;                                                                  # " override match for i686
    armv7l)  nasMchArch="armv7neon" ;;                                                            # " override match for armv71
  esac
  nasMchProc=$(uname -a | awk '{split($NF, a, "_"); print a[2]}')                                 # NAS processor platform
  nasNodeNam=$(uname --nodename)                                                                  # NAS network hostname
  nasMchKern=$(uname --kernel-name)                                                               # NAS kernel name
  nasMchKver=$(uname --kernel-release)                                                            # NAS kernel version
  nasMchKlcs=$(echo "$nasMchKern" | awk '{ print tolower($0) }')                                  # NAS kernel name (lowercase)
  nasBashVer=$(bash --version | head -n 1 | awk '{print $4}')                                     # NAS bash version
  nasTimZone=$(readlink /etc/localtime | sed 's|.*/zoneinfo/||')                                  # NAS time zone configuration
  nasAdminXp=$(boolean_risk "$(synouser --get admin | awk -F '[][{}]' '/Expired/ { print $2 }')") # NAS admin account check
  nasIntrnIP=$(                                                                                   # NAS all ethernet IPs
    ip -f inet -o addr show | awk '$2 ~ /^(eth|enp|bond|br)/ { split($4, a, "/"); print $2 ": " a[1] }')
  nasSysUpTm=$(                                                                                   # NAS system uptime
    uptime | awk -F'( |,|:)+' '{d=h=m=0; if ($7=="min") m=$6; else { \
    if ($7~/^day/) {d=$6; h=$8; m=$9} else {h=$6; m=$7}}} \
    {print d+0,"days,",h+0,"hours,",m+0,"minutes"}'
  )
}
get_nas_info

get_smb_multichannel_status

# Function to get ISP information
get_isp_info() {                                                                                  # NAS external IP address
  ispExtrnIP=$(nslookup myip.opendns.com resolver1.opendns.com 2>/dev/null | awk '/^Address: / { print $2 }' | tail -n1) 
}
get_isp_info

# Function to get DSM information
get_dsm_info() {
  dsmPrdctNm=$(grep -i "productversion=" "/etc.defaults/VERSION" | cut -d"\"" -f 2)               # DSM product version
  dsmBuildNm=$(grep -i "buildnumber="    "/etc.defaults/VERSION" | cut -d"\"" -f 2)               # DSM build number
  dsmMinorVr=$(grep -i "smallfixnumber=" "/etc.defaults/VERSION" | cut -d"\"" -f 2)               # DSM minor version
  if [ -n "$dsmMinorVr" ]; then
    dsmFullVer="$dsmPrdctNm-$dsmBuildNm Update $dsmMinorVr"
  else
    dsmFullVer="$dsmPrdctNm-$dsmBuildNm"
  fi
}
get_dsm_info

# Function to get PMS Media Server information
get_pms_info() {
  pmsVersion=$(synopkg version "PlexMediaServer")                                                 # PMS version
  pmsSTarget=$(readlink /var/packages/PlexMediaServer/target)                                     # PMS target symbolic link
  pmsApplDir="$pmsSTarget"                                                                        # PMS application directory
  pmsSShares=$(readlink /var/packages/PlexMediaServer/shares/PlexMediaServer)                     # PMS shares symbolic link
  pmsDataDir="$pmsSShares/AppData/Plex Media Server"                                              # PMS data directory
  pmsTrnscdr=$("$pmsApplDir/Plex Transcoder" -version -hide_banner | head -n 1 | cut -d " " -f 1) # PMS transcoder app
  pmsTrnscdV=$("$pmsApplDir/Plex Transcoder" -version -hide_banner | head -n 1 | cut -d " " -f 3) # PMS transcoder version
  pmsCdcsDir="$pmsDataDir/Codecs"                                                                 # PMS codecs directory
  pmsCdcVDir=$(find "$pmsDataDir/Codecs" -type d -name "$pmsTrnscdV-$nasMchKlcs-$nasMchArch")     # PMS transcoder version codecs directory
  pmsTrnscdT=$(grep -oP "TranscoderTempDirectory=\"\K[^\"]+" "$pmsDataDir/Preferences.xml")       # PMS transcoder temp directory
  pmsFrnName=$(grep -oP "FriendlyName=\"\K[^\"]+" "$pmsDataDir/Preferences.xml")                  # PMS friendly name
  pmsDevicID=$(head -n 1 "$pmsCdcsDir/.device-id")                                                # PMS device ID
  pmsMachnID=$(grep -oP "ProcessedMachineIdentifier=\"\K[^\"]+" "$pmsDataDir/Preferences.xml")    # PMS machine ID
  pmsOnlnTkn=$(grep -oP "PlexOnlineToken=\"\K[^\"]+" "$pmsDataDir/Preferences.xml")               # PMS online token
  pmsChannel=$(grep -oP "ButlerUpdateChannel=\"\K[^\"]+" "$pmsDataDir/Preferences.xml")           # PMS update channel
  if [ -z "$pmsChannel" ]; then
    pmsChannel=Public
  else
    if [ "$pmsChannel" -eq "0" ]; then
      pmsChannel=Public
    elif [ "$pmsChannel" -eq "8" ]; then
      pmsChannel=Beta
    else
      pmsChannel="Undefined (???)"
    fi
  fi
  pmsAutTrsh=$(grep -oP "autoEmptyTrash=\"\K[^\"]+" "$pmsDataDir/Preferences.xml")                # PMS auto empty trash
  if [ -z "$pmsAutTrsh" ]; then
    pmsAutTrsh="Manual"
  else
    if [ "$pmsAutTrsh" -eq "0" ]; then
      pmsAutTrsh="Manual"
    elif [ "$pmsAutTrsh" -eq "1" ]; then
      pmsAutTrsh="Automatic (DISCONNECTION RISK)"
    else
      pmsAutTrsh="Undefined (???)"
    fi
  fi
  pmsProcsID=$(pgrep -f "Plex Media Server")
  # Check if the PID was found
  if [ -n "$pmsProcsID" ]; then
    # Get the elapsed time for the process and format the output
    pmsRunUpTm=$(ps -p "$pmsProcsID" -o etime= | awk '
      {
        split($1, t, "[-:]")
        d=h=m=0
        if (length(t) == 4) { d = t[1]; h = t[2]; m = t[3] }
        else if (length(t) == 3) { h = t[1]; m = t[2] }
        else if (length(t) == 2) { m = t[1] }
          print d+0,"days,",h+0,"hours,",m+0,"minutes"
      }
    ')
  else
      echo "Plex Media Server is not running."
  fi
}
get_pms_info

# Function to get PMS Codec Preloader information
get_pcp_info() {
  pmsCdcsArc="$srcDirctry/Archive/Codecs"                                                         # PMS codecs archive directory
  pmsCdcADir="$pmsCdcsArc/$pmsTrnscdV-$nasMchKlcs-$nasMchArch"                                    # PMS transcoder version codecs archive directory
}
get_pcp_info

# Function to load Config settings
get_config_info() {
  if [ -f "$srcDirctry/config.ini" ]; then
    source "$srcDirctry/config.ini"
  fi
}
get_config_info

# Function to summarize data
print_summary() {
  # Print our glorious header because we are full of ourselves
  printf "\n%s\n\n" "SYNO.PLEX INFO SCRIPT v$srcScrpVer for DSM 7"

  # Print the collected information
  printf '\n%s\n\n'  "SYNOLOGY NAS INFO"
  printf '%16s %s\n' "Nodename:"        "$nasNodeNam"
  printf '%16s %s\n' "DSM ver:"         "$dsmFullVer"
  printf '%16s %s\n' "Model:"           "$nasHwModel"
  printf '%16s %s\n' "Architecture:"    "$nasMchArch ($nasMchProc)"
  printf '%16s %s\n' "Kernel:"          "$nasMchKern ($nasMchKver)"
  printf '%16s %s\n' "Bash:"            "$nasBashVer"
  printf '%16s %s\n' "SMB MC:"          "$nasSmb3Mlt"
  first=1
  while IFS= read -r line; do
    if (( first )); then
      printf '%16s %s\n' "Internal IP:" "$line"
      first=0
    else
      printf '%16s %s\n' ":" "$line"
    fi
  done <<< "$nasIntrnIP"
  printf '%16s %s\n' "External IP:"     "$ispExtrnIP"
  printf '%16s %s\n' "Time Zone:"       "$nasTimZone"
  printf '%16s %s\n' "Admin account:"   "$nasAdminXp"
  printf '%16s %s\n' "System Uptime:"   "$nasSysUpTm"
  printf "\n"

  printf '\n%s\n\n'  "PLEX MEDIA SERVER INFO"
  printf '%16s %s\n' "Friendly Name:"   "$pmsFrnName"
  printf '%16s %s\n' "PMS ver:"         "$pmsVersion"
  printf '%16s %s\n' "Update Channel:"  "$pmsChannel"
  printf '%16s %s\n' "Empty Trash:"     "$pmsAutTrsh"
  printf '%16s %s\n' "Transcoder:"      "$pmsTrnscdr ($pmsTrnscdV)"
  printf '%16s %s\n' "PMS Uptime:"      "$pmsRunUpTm"
  printf "\n"

  printf '\n%s\n\n'  "PLEX DIRECTORY REFERENCE"
  [ -d "$pmsApplDir" ]          && printf '%16s %s\n' "Applications:"   "$pmsApplDir"
  [ -d "$pmsDataDir" ]          && printf '%16s %s\n' "AppData:"        "$pmsDataDir"
  [ -d "$pmsDataDir/Cache" ]    && printf '%16s %s\n' "Cache:"          " \" /Cache"
  [ -d "$pmsCdcVDir" ]          && printf '%16s %s\n' "Codecs:"         " \" /Codecs/$pmsTrnscdV-$nasMchKlcs-$nasMchArch"
  [ -d "$pmsDataDir/Logs" ]     && printf '%16s %s\n' "Crash Reports:"  " \" /Crash Reports"
  [ -d "$pmsDataDir/Logs" ]     && printf '%16s %s\n' "Logs:"           " \" /Logs"
  [ -d "$pmsDataDir/Plug-ins" ] && printf '%16s %s\n' "Plug-ins:"       " \" /Plug-ins"
  [ -d "$pmsDataDir/Scanners" ] && printf '%16s %s\n' "Scanners:"       " \" /Scanners"
  printf "\n"

  printf '\n%s\n\n'  "PLEX MEDIA SERVER IDs (DO NOT SHARE)"
    if (( SHOW_SECRET )); then
    printf '%16s %s
' "Device-ID:"     "$pmsDevicID"
    printf '%16s %s
' "Machine-ID:"    "$pmsMachnID"
    printf '%16s %s
' "Online Token:"  "$pmsOnlnTkn"
  else
    printf '%16s %s
' "Device-ID:"     "[REDACTED]"
    printf '%16s %s
' "Machine-ID:"    "[REDACTED]"
    printf '%16s %s
' "Online Token:"  "[REDACTED]"
  fi
  printf "\n"
}
print_summary

stop_logging_redirect
