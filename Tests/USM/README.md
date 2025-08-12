USM Test files
---
### default.[h264,ivf,m1v]
AV Sync test video courtesy of Twitch (can be found at https://archive.org/details/twitch-sync-footage-v1)

Produced with
```bash
ffmpeg -i Sync-Footage-V1-H264.mp4 -an -map_metadata -1 -t 8s -c:v mpeg1video default.m1v
ffmpeg -i Sync-Footage-V1-H264.mp4 -an -map_metadata -1 -t 8s -c:v libx264 default.h264
ffmpeg -i Sync-Footage-V1-H264.mp4 -an -map_metadata -1 -t 8s -c:v libvpx default.ivf
```
