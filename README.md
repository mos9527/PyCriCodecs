# PyCriCodecsEx
A continuation of @Youjose's work on Criware formats. Feautres are still in flux and subject to change. When in doubt, Refer to the [original repo](https://github.com/Youjose/PyCriCodecs) for more information.

# Installation
```bash
pip install PyCriCodecsEx
```

For USM features, you need `ffmpeg` installed and available in your PATH. See also https://github.com/kkroening/ffmpeg-python?tab=readme-ov-file#installing-ffmpeg

## Features
If not otherwise mentioned, all features marked with [x] are considered working, and has been verified with official tools.

### ACB Cue sheets (also AWB)
- [x] Editing & Saving (Scripting APIs. Helper functions TODO. see examples in [Tests](https://github.com/mos9527/PyCriCodecsEx/tree/main/Tests))
### USM Sofdec2 (Encode & Decode)
#### Audio Stream
For audio to be muxed in, you need a PCM WAV sample with NO metadata, which can be produced with e.g.:
```bash
ffmpeg -i input.mp3 -vn -c:a pcm_s16le -map_metadata -1 output.wav
```
Decoding and Encoded format can be the following:
- [x] HCA
- [x] ADX
#### Video Stream
**NOTE**: You definitely want to tweak these encode settings a bit.
- [x] Sofdec Prime (MPEG1, from `.m1v` container)
    - Prepare source file with: `ffmpeg -i <input_file> -c:v mpeg1video -an <output_file>.m1v`
- [x] H264 (from `.h264` raw container)
    - Prepare source file with: `ffmpeg -i <input_file> -c:v libx264 -an <output_file>.h264`
- [x] VP9 (from `.ivf` container)
    - Prepare source file with: `ffmpeg -i <input_file> -c:v libvpx -an <output_file>.ivf`
### HCA Audio Codec
- [x] Decoding (up to version 3.0)
- [x] Encoding (up to version 3.0)
### ADX Audio Codec
- [x] Decoding
- [x] Encoding
### CPK
- [x] Unpacking
- [x] Packing

## Roadmap
- [ ] ACB Extraction (Massive TODO. see also https://github.com/mos9527/PyCriCodecsEx/blob/main/Research/ACBSchema.py)
- [ ] Interface for encode tasks (CLI then maybe GUI?)
- [ ] Documentation
- [ ] C/C++ port + FFI
## Currently Known Bugs
- USM seeking does not work. Though most games don't use it anyways.
- Not important, and might not fix: ADX encoding and decoding at higher bitdepths (11-15) adds popping noise.
- Some CPK's that has the same filename for every file in the entry will overwrite each other.
- Probably many more I am unaware of, report if you find any.

# Credits
- https://github.com/Youjose/PyCriCodecs
- https://github.com/Mikewando/PyCriCodecs ([PR#1 on USM](https://github.com/mos9527/PyCriCodecsEx/pull/1))
- https://github.com/donmai-me/WannaCRI
- https://github.com/vgmstream/vgmstream
- https://github.com/K0lb3/UnityPy (For CI script)