# syno.plexinfo

A bash script to dump diagnostic info for Plex Media Server on Synology NAS.

`-x` will expose `[REDACTED]` private data (e.g. IP addresses, etc)  
`--xxx` will expose `[REDACTED]` secrets data (e.g. Plex identifiers and Tokens)

# Utilization and example output:

    # bash syno.plexinfo.sh

    SYNO.PLEX INFO SCRIPT v2.2.0 for DSM 7
    
    
    SYNOLOGY NAS INFO
    
           Nodename: SYNOLOGY
            DSM ver: 7.3.2-86009 Update 0
              Model: DS1019+
       Architecture: x86_64 (apollolake)
             Kernel: Linux (4.4.302+)
               Bash: 4.4.23(1)-release
             SMB MC: Enabled (active)
        Internal IP: 172.16.172.88 (eth0) [SMBMC Pid: 23997]
                   : 172.16.172.87 (eth1) [SMBMC Pid: 23997]
        External IP: [REDACTED]
          Time Zone: US/Pacific
      Admin account: Disabled
      Guest account: Disabled
      System Uptime: 6 days, 19 hours, 41 minutes
    
    
    PLEX MEDIA SERVER INFO
    
      Friendly Name: Synology
            PMS ver: 1.42.2.10156-720010156
     Update Channel: Public
        Empty Trash: Manual
         Transcoder: ffmpeg (46f74ab-560174306fe167a5978a79dd)
      Remote Access: 172.16.172.88:32400 <- [REDACTED]:52400 <- Internet
         PMS Uptime: 6 days, 19 hours, 39 minutes
    
    
    PLEX DIRECTORY REFERENCE
    
       Applications: /volume1/@appstore/PlexMediaServer
            AppData: /volume4/PlexMediaServer/AppData/Plex Media Server
              Cache:  " /Cache
             Codecs:  " /Codecs/46f74ab-560174306fe167a5978a79dd-linux-x86_64
      Crash Reports:  " /Crash Reports
               Logs:  " /Logs
           Plug-ins:  " /Plug-ins
           Scanners:  " /Scanners
    
    
    PLEX PLATFORM IDENTIFIERS
    
          Device-ID: [REDACTED]
         Machine-ID: [REDACTED]
       Online Token: [REDACTED]
