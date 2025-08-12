# PyCriCodecs
A continuation of @Youjose's work on Criware formats. Feautres are still in flux and subject to change. When in doubt, Refer to the [original repo](https://github.com/Youjose/PyCriCodecs) for more information.

# Installation
This is not available at PyPI yet. Meanwhile, you can install it manually from the source.
```bash
pip install -U git+https://github.com/mos9527/PyCriCodecs.git
```

For USM features, you need `ffmpeg` installed and available in your PATH. See also https://github.com/kkroening/ffmpeg-python?tab=readme-ov-file#installing-ffmpeg

## Features
If not otherwise mentioned, all features marked with [x] are considered working, and has been verified with official tools.

### ACB Cue sheets (also AWB)
- [x] Editing & Saving (Scripting APIs. Helper functions TODO. see examples in [Tests](https://github.com/mos9527/PyCriCodecs/tree/main/Tests))
### USM Sofdec2 (Encode & Decode)
#### Audio Stream
- [x] HCA
- [x] ADX
#### Video Stream
**NOTE**: You definitely want to tweak these encode settings a bit.
- [x] Sofdec Prime (MPEG1, from `.mp4` container)
    - Prepare source file with: `ffmpeg -i <input_file> -c:v mpeg1video -an <output_file>.mp4`
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
- [ ] Unpacking (untested)
- [ ] Packing (untested)

## Roadmap
- [ ] ACB Extraction (Massive TODO. see also https://github.com/mos9527/PyCriCodecs/blob/main/Research/ACBSchema.py)
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
- https://github.com/Mikewando/PyCriCodecs ([PR#1 on USM](https://github.com/mos9527/PyCriCodecs/pull/1))
- https://github.com/donmai-me/WannaCRI
- https://github.com/vgmstream/vgmstream