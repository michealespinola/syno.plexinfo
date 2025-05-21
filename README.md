# syno.plexinfo

A bash script to dump diagnostic info for Plex Media Server on Synology NAS.

`-x` will expose `[REDACTED]` private data

# Utilization and example output:

    # bash syno.plexinfo.sh
    
    SYNO.PLEX INFO SCRIPT v2.1.1 for DSM 7
    
    
    SYNOLOGY NAS INFO
    
           Nodename: SYNOLOGY
            DSM ver: 7.2.2-72806 Update 3
              Model: DS1019+
       Architecture: x86_64 (apollolake)
             Kernel: Linux (4.4.302+)
               Bash: 4.4.23(1)-release
             SMB MC: Enabled (active)
        Internal IP: ###.###.###.### (eth0) [SMBMC Pid: #####]
                   : ###.###.###.### (eth1) [SMBMC Pid: #####]
        External IP: ###.###.###.###
          Time Zone: US/Pacific
      Admin account: Disabled
      System Uptime: 9 days, 10 hours, 43 minutes
    
    
    PLEX MEDIA SERVER INFO
    
      Friendly Name: Synology
            PMS ver: 1.41.7.9799-72009799
     Update Channel: Public
        Empty Trash: Manual
         Transcoder: ffmpeg (1c96867-c7c51eae1050ee8a09ae8dc1)
         PMS Uptime: 0 days, 13 hours, 1 minutes
    
    
    PLEX DIRECTORY REFERENCE
    
       Applications: /volume4/@appstore/PlexMediaServer
            AppData: /volume4/PlexMediaServer/AppData/Plex Media Server
              Cache:  " /Cache
             Codecs:  " /Codecs/1c96867-c7c51eae1050ee8a09ae8dc1-linux-x86_64
      Crash Reports:  " /Crash Reports
               Logs:  " /Logs
           Plug-ins:  " /Plug-ins
           Scanners:  " /Scanners
    
    
    PLEX MEDIA SERVER IDs (DO NOT SHARE)
    
          Device-ID: [REDACTED]
         Machine-ID: [REDACTED]
       Online Token: [REDACTED]
