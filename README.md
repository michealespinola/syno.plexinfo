# syno.plexinfo

A bash script to dump diagnostic info for Plex Media Server on Synology NAS.

`-x` will expose `[REDACTED]` private data (e.g. IP addresses, etc)  
`--xxx` will expose `[REDACTED]` private and secrets data (e.g. Plex identifiers and Tokens)

# Utilization and example output:

```
# bash syno.plexinfo.sh

SYNO.PLEX INFO SCRIPT v2.4.0 for DSM 7


SYNOLOGY NAS INFO

       Nodename: SYNOLOGY
        DSM ver: 7.3.2-86009 Update 3
          Model: DS1019+
   Architecture: x86_64 (apollolake)
   Total Memory: 16.62 GB
  System Memory: 2.15 GB (12.92%)
  Docker Memory: 404.22 MB (2.43%)
         Kernel: Linux (4.4.302+)
           Bash: 4.4.23(1)-release
            SSH: OpenSSH_8.2p1, OpenSSL 1.1.1u
         SMB MC: Enabled (active)
    Internal IP: 172.16.172.88 (eth0) [SMBMC Pid: 14149]
               : 172.16.172.87 (eth1) [SMBMC Pid: 14149]
    External IP: [REDACTED]
      Time Zone: US/Pacific
  Admin Account: Disabled
  Guest Account: Disabled
  System Uptime: 37 days, 16 hours, 1 minutes


PLEX MEDIA SERVER INFO

  Friendly Name: Synology
        PMS ver: 1.43.1.10611-720010611
     PMS Memory: 256.48 MB (1.54%)
 Update Channel: Public
    Empty Trash: Manual
     Transcoder: ffmpeg (cc4757f-e75de90df4cf308fb2840af9)
  Remote Access: 172.16.172.88:32400 <- [REDACTED]:[REDACTED] <- Internet
     PMS Uptime: 13 days, 5 hours, 10 minutes


PLEX DIRECTORY REFERENCE

   Applications: /volume1/@appstore/PlexMediaServer
        AppData: /volume4/PlexMediaServer/AppData/Plex Media Server
          Cache:  " /Cache
         Codecs:  " /Codecs/cc4757f-e75de90df4cf308fb2840af9-linux-x86_64
  Crash Reports:  " /Crash Reports
      Databases:  " /Plug-in Support/Databases
           Logs:  " /Logs
       Metadata:  " /Metadata
       Plug-ins:  " /Plug-ins
       Scanners:  " /Scanners


PLEX PLATFORM IDENTIFIERS

      Device-ID: [REDACTED]
     Machine-ID: [REDACTED]
   Online Token: [REDACTED]
```
