WAV Test files
---
### default.wav
AV Sync test audio courtesy of Twitch (can be found at https://archive.org/details/twitch-sync-footage-v1)

Produced with
```bash
ffmpeg -i Sync-Footage-V1-H264.mp4 -vn -c:a pcm_s16le -map_metadata -1 -fflags +bitexact -t 8s default.wav
```
