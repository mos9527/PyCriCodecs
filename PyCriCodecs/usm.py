import os
import itertools
from typing import BinaryIO, List
from io import FileIO, BytesIO

from .chunk import *
from .utf import UTF, UTFBuilder
from .adx import ADX
from .hca import HCA

import ffmpeg

# Big thanks and credit for k0lb3 and 9th helping me write this specific code.
# Also credit for the original C++ code from Nyagamon/bnnm.

# Apparently there is an older USM format called SofDec? This is for SofDec2 though.
# Extraction working only for now, although check https://github.com/donmai-me/WannaCRI/
# code for a complete breakdown of the USM format.


class USMCrypt:
    videomask1: bytearray
    videomask2: bytearray
    audiomask: bytearray

    def init_key(self, key: str):
        if type(key) == str:
            if len(key) <= 16:
                key = key.rjust(16, "0")
                key1 = bytes.fromhex(key[8:])
                key2 = bytes.fromhex(key[:8])
            else:
                raise ValueError("Invalid input key.")
        elif type(key) == int:
            key1 = int.to_bytes(key & 0xFFFFFFFF, 4, "big")
            key2 = int.to_bytes(key >> 32, 4, "big")
        else:
            raise ValueError(
                "Invalid key format, must be either a string or an integer."
            )
        t = bytearray(0x20)
        t[0x00:0x09] = [
            key1[3],
            key1[2],
            key1[1],
            (key1[0] - 0x34) % 0x100,
            (key2[3] + 0xF9) % 0x100,
            (key2[2] ^ 0x13) % 0x100,
            (key2[1] + 0x61) % 0x100,
            (key1[3] ^ 0xFF) % 0x100,
            (key1[1] + key1[2]) % 0x100,
        ]
        t[0x09:0x0C] = [
            (t[0x01] - t[0x07]) % 0x100,
            (t[0x02] ^ 0xFF) % 0x100,
            (t[0x01] ^ 0xFF) % 0x100,
        ]
        t[0x0C:0x0E] = [
            (t[0x0B] + t[0x09]) % 0x100,
            (t[0x08] - t[0x03]) % 0x100,
        ]
        t[0x0E:0x10] = [
            (t[0x0D] ^ 0xFF) % 0x100,
            (t[0x0A] - t[0x0B]) % 0x100,
        ]
        t[0x10] = (t[0x08] - t[0x0F]) % 0x100
        t[0x11:0x17] = [
            (t[0x10] ^ t[0x07]) % 0x100,
            (t[0x0F] ^ 0xFF) % 0x100,
            (t[0x03] ^ 0x10) % 0x100,
            (t[0x04] - 0x32) % 0x100,
            (t[0x05] + 0xED) % 0x100,
            (t[0x06] ^ 0xF3) % 0x100,
        ]
        t[0x17:0x1A] = [
            (t[0x13] - t[0x0F]) % 0x100,
            (t[0x15] + t[0x07]) % 0x100,
            (0x21 - t[0x13]) % 0x100,
        ]
        t[0x1A:0x1C] = [
            (t[0x14] ^ t[0x17]) % 0x100,
            (t[0x16] + t[0x16]) % 0x100,
        ]
        t[0x1C:0x1F] = [
            (t[0x17] + 0x44) % 0x100,
            (t[0x03] + t[0x04]) % 0x100,
            (t[0x05] - t[0x16]) % 0x100,
        ]
        t[0x1F] = (t[0x1D] ^ t[0x13]) % 0x100
        t2 = [b"U", b"R", b"U", b"C"]
        self.videomask1 = t
        self.videomask2 = bytearray(map(lambda x: x ^ 0xFF, t))
        self.audiomask = bytearray(0x20)
        for x in range(0x20):
            if (x & 1) == 1:
                self.audiomask[x] = ord(t2[(x >> 1) & 3])
            else:
                self.audiomask[x] = self.videomask2[x]

    # Decrypt SFV chunks or ALP chunks, should only be used if the video data is encrypted.
    def VideoMask(self, memObj: bytearray) -> bytearray:
        head = memObj[:0x40]
        memObj = memObj[0x40:]
        size = len(memObj)
        # memObj len is a cached property, very fast to lookup
        if size <= 0x200:
            return head + memObj
        data_view = memoryview(memObj).cast("Q")

        # mask 2
        mask = bytearray(self.videomask2)
        mask_view = memoryview(mask).cast("Q")
        vmask = self.videomask2
        vmask_view = memoryview(vmask).cast("Q")

        mask_index = 0

        for i in range(32, size // 8):
            data_view[i] ^= mask_view[mask_index]
            mask_view[mask_index] = data_view[i] ^ vmask_view[mask_index]
            mask_index = (mask_index + 1) % 4

        # mask 1
        mask = bytearray(self.videomask1)
        mask_view = memoryview(mask).cast("Q")
        mask_index = 0
        for i in range(32):
            mask_view[mask_index] ^= data_view[i + 32]
            data_view[i] ^= mask_view[mask_index]
            mask_index = (mask_index + 1) % 4

        return head + memObj

    # Decrypts SFA chunks, should just be used with ADX files.
    def AudioMask(self, memObj: bytearray) -> bytearray:
        head = memObj[:0x140]
        memObj = memObj[0x140:]
        size = len(memObj)
        data_view = memoryview(memObj).cast("Q")
        mask = bytearray(self.audiomask)
        mask_view = memoryview(mask).cast("Q")
        for i in range(size // 8):
            data_view[i] ^= mask_view[i % 4]
        return head + memObj


class USM(USMCrypt):
    """USM class for extracting infromation and data from a USM file."""

    filename: str
    decrypt: bool
    stream: BinaryIO
    CRIDObj: UTF
    output: dict[str, bytes]
    size: int
    codec: int
    demuxed: bool

    __fileinfo: list

    def __init__(self, filename, key: str = False):
        """
        Sets the decryption status, if the key is not given, it will return the plain SFV data.
        If the key is given the code will decrypt SFA data if it was ADX, otherwise return plain SFA data.
        """
        self.filename = filename
        self.decrypt = False

        if key and type(key) != bool:
            self.decrypt = True
            self.init_key(key)
        self.load_file()

    # Loads in the file and check if it's an USM file.
    def load_file(self):
        self.stream = open(self.filename, "rb")
        self.stream.seek(0, 2)
        self.size = self.stream.tell()
        self.stream.seek(0)
        header = self.stream.read(4)
        if header != USMChunckHeaderType.CRID.value:
            raise NotImplementedError(f"Unsupported file type: {header}")
        self.stream.seek(0)
        self.demux()

    # Demuxes the USM
    def demux(self) -> None:
        """Gets data from USM chunks and assignes them to output."""
        self.stream.seek(0)
        self.__fileinfo = list()  # Prototype, should be improved.
        (
            header,
            chuncksize,
            unk08,
            offset,
            padding,
            chno,
            unk0D,
            unk0E,
            type,
            frametime,
            framerate,
            unk18,
            unk1C,
        ) = USMChunkHeader.unpack(self.stream.read(USMChunkHeader.size))
        chuncksize -= 0x18
        offset -= 0x18
        self.CRIDObj = UTF(self.stream.read(chuncksize))
        CRID_payload = self.CRIDObj.dictarray
        self.__fileinfo.append({self.CRIDObj.table_name: CRID_payload})
        headers = [
            (int.to_bytes(x["stmid"][1], 4, "big")).decode() for x in CRID_payload[1:]
        ]
        chnos = [x["chno"][1] for x in CRID_payload[1:]]
        output = dict()
        for i in range(len(headers)):
            output[headers[i] + "_" + str(chnos[i])] = bytearray()
        while self.stream.tell() < self.size:
            header: bytes
            (
                header,
                chuncksize,
                unk08,
                offset,
                padding,
                chno,
                unk0D,
                unk0E,
                type,
                frametime,
                framerate,
                unk18,
                unk1C,
            ) = USMChunkHeader.unpack(self.stream.read(USMChunkHeader.size))
            chuncksize -= 0x18
            offset -= 0x18
            if header.decode() in headers:
                if type == 0:
                    data = self.reader(chuncksize, offset, padding, header)
                    output[header.decode() + "_" + str(chno)].extend(data)
                elif type == 1 or type == 3:
                    ChunkObj = UTF(self.stream.read(chuncksize))
                    self.__fileinfo.append({ChunkObj.table_name: ChunkObj.dictarray})
                    if type == 1 and header == USMChunckHeaderType.SFA.value:
                        codec = ChunkObj.dictarray[0]
                        self.codec = codec["audio_codec"][
                            1
                        ]  # So far, audio_codec of 2, means ADX, while audio_codec 4 means HCA.
                else:
                    self.stream.seek(chuncksize, 1)
            else:
                # It is likely impossible for the code to reach here, since the code right now is suitable
                # for any chunk type specified in the CRID header.
                # But just incase somehow there's an extra chunk, this code might handle it.
                if header in [chunk.value for chunk in USMChunckHeaderType]:
                    if type == 0:
                        output[header.decode() + "_0"] = bytearray()
                        data = self.reader(chuncksize, offset, padding, header)
                        output[header.decode() + "_0"].extend(
                            data
                        )  # No channel number info, code here assumes it's a one channel data type.
                    elif type == 1 or type == 3:
                        ChunkObj = UTF(self.stream.read(chuncksize))
                        self.__fileinfo.append(
                            {ChunkObj.table_name: ChunkObj.dictarray}
                        )
                        if type == 1 and header == USMChunckHeaderType.SFA.value:
                            codec = ChunkObj.dictarray[0]
                            self.codec = codec["audio_codec"][1]
                    else:
                        self.stream.seek(chuncksize, 1)
                else:
                    raise NotImplementedError(f"Unsupported chunk type: {header}")
        self.output = output
        self.demuxed = True

    def extract(self, dirname: str = ""):
        """Extracts all USM contents."""
        self.stream.seek(0)
        if not self.demuxed:
            self.demux()
        table = self.CRIDObj.dictarray
        point = 0  # My method is not ideal here, but it'll hopefully work.
        dirname = dirname  # You can add a directory where all extracted data goes into.
        filenames = []
        for i in table[1:]:  # Skips the CRID table since it has no actual file.
            filename: str = i["filename"][1]

            # Adjust filenames and/or paths to extract them into the current directory.
            if ":\\" in filename:  # Absolute paths.
                filename = filename.split(":\\", 1)[1]
            elif ":/" in filename:  # Absolute paths.
                filename = filename.split(":/", 1)[1]
            elif ":" + os.sep in filename:  # Absolute paths.
                filename = filename.split(":" + os.sep, 1)[1]
            elif ".." + os.sep in filename:  # Relative paths.
                filename = filename.rsplit(".." + os.sep, 1)[1]
            elif "../" in filename:  # Relative paths.
                filename = filename.rsplit("../", 1)[1]
            elif "..\\" in filename:  # Relative paths.
                filename = filename.rsplit("..\\", 1)[1]
            filename = "".join(
                x for x in filename if x not in ':?*<>|"'
            )  # removes illegal characters.

            filename = os.path.join(
                dirname, filename
            )  # Preserves the path structure if there's one.
            if filename not in filenames:
                filenames.append(filename)
            else:
                if "." in filename:
                    fl = filename.rsplit(".", 1)
                    filenames.append(fl[0] + "_" + str(point) + "." + fl[1])
                    point += 1
                else:
                    filenames.append(filename + "_" + str(point))
                    point += 1

        point = 0
        for chunk, data in self.output.items():
            chunk = chunk.rsplit("_", 1)[0]
            if (
                dirname
                or "\\" in filenames[point]
                or "/" in filenames[point]
                or os.sep in filenames[point]
            ):
                os.makedirs(os.path.dirname(filenames[point]), exist_ok=True)
            if chunk == USMChunckHeaderType.SBT.value.decode():
                # Subtitle information.
                texts = self.sbt_to_srt(data)
                for i in range(len(texts)):
                    filename = filenames[point]
                    if "." in filename:
                        fl = filename.rsplit(".", 1)
                        filename = fl[0] + "_" + str(i) + ".srt"
                    else:
                        filename = filename + "_" + str(i)
                    open(filename, "w", encoding="utf-8").write(texts[i])
                else:
                    open(filenames[point], "wb").write(data)
                    point += 1
            elif chunk == USMChunckHeaderType.CUE.value.decode():
                # CUE chunks is actually just metadata.
                # and can be accessed by .metadata after demuxing or extracting.
                point += 1
            elif data == bytearray():
                # This means it has no data, and just like the CUE, it might be just metadata.
                point += 1
            elif filenames[point] == "":
                # Rare case and might never happen unless the USM is artificially edited.
                fl = (
                    table[0]["filename"][1].rsplit(".", 1)[0]
                    + "_"
                    + str(point)
                    + ".bin"
                )
                open(fl, "wb").write(data)
                point += 1
            else:
                open(filenames[point], "wb").write(data)
                point += 1

    def reader(self, chuncksize, offset, padding, header) -> bytearray:
        """Chunks reader function, reads all data in a chunk and returns a bytearray."""
        data = bytearray(self.stream.read(chuncksize)[offset:])
        if (
            header == USMChunckHeaderType.SFV.value
            or header == USMChunckHeaderType.ALP.value
        ):
            data = self.VideoMask(data) if self.decrypt else data
        elif header == USMChunckHeaderType.SFA.value:
            data = self.AudioMask(data) if (self.codec == 2 and self.decrypt) else data
        if padding:
            data = data[:-padding]
        return data

    def sbt_to_srt(self, stream: bytearray) -> list:
        """Convert SBT chunks info to SRT."""
        # After searching, I found how the SBT format is actually made.
        # But the use case for them is not ideal as they are proprietary.
        # So I will just convert them to SRT.
        size = len(stream)
        stream: BytesIO = BytesIO(stream)
        out = dict()
        while stream.tell() < size:
            langid, framerate, frametime, duration, data_size = SBTChunkHeader.unpack(
                stream.read(SBTChunkHeader.size)
            )
            # Language ID's are arbitrary, so they could be anything.
            duration_in_ms = frametime
            ms = duration_in_ms % framerate
            sec = (duration_in_ms // framerate) % 60
            mins = (duration_in_ms // (framerate * 60)) % 60
            hrs = (duration_in_ms // (framerate * 60 * 60)) % 24
            start = f"{hrs:0>2.0f}:{mins:0>2.0f}:{sec:0>2.0f},{ms:0>3.0f}"

            duration_in_ms = frametime + duration
            ms = duration_in_ms % framerate
            sec = (duration_in_ms // framerate) % 60
            mins = (duration_in_ms // (framerate * 60)) % 60
            hrs = (duration_in_ms // (framerate * 60 * 60)) % 24
            end = f"{hrs:0>2.0f}:{mins:0>2.0f}:{sec:0>2.0f},{ms:0>3.0f}"

            text = stream.read(data_size)
            if text.endswith(b"\x00\x00"):
                text = text[:-2].decode("utf-8", errors="ignore") + "\n\n"
            else:
                text = text.decode("utf-8", errors="ignore")
            if langid in out:
                out[langid].append(
                    str(int(out[langid][-1].split("\n", 1)[0]) + 1)
                    + "\n"
                    + start
                    + " --> "
                    + end
                    + "\n"
                    + text
                )
            else:
                out[langid] = [str(1) + "\n" + start + " --> " + end + "\n" + text]
        out = ["".join(v) for k, v in out.items()]
        return out

    @property
    def metadata(self):
        """Function to return USM metadata after demuxing."""
        return self.__fileinfo

# There are a lot of unknowns, minbuf(minimum buffer of what?) and avbps(average bitrate per second)
# are still unknown how to derive them, at least video wise it is possible, no idea how it's calculated audio wise nor anything else
# seems like it could be random values and the USM would still work.
class FFmpegParser:    

    filename : str
    filesize : int
    
    info : dict
    file : FileIO
        
    minchk: int
    minbuf: int
    avbps: int

    def __init__(self, filename : str):
        self.filename = os.path.abspath(filename)
        self.info = ffmpeg.probe(self.filename, show_entries="packet=dts,pts_time,pos,flags")
        self.file = open(self.filename, "rb")
        self.filesize = os.path.getsize(self.filename)

    @property
    def format(self):
        return self.info['format']['format_name']
    
    @property
    def stream(self):
        return self.info['streams'][0]
    
    @property
    def codec(self):
        return self.stream['codec_name']

    @property
    def framerate(self):
        num, denom = self.stream['r_frame_rate'].split('/')
        return int(int(num) / int(denom))
    
    @property
    def packets(self):
        return self.info['packets']

    @property
    def width(self):
        return self.stream['width']

    @property
    def height(self):
        return self.stream['height']

    @property
    def frame_count(self):
        return len(self.packets)

    def frames(self):
        '''frame data, frame dict, is keyframe'''
        offsets = [int(packet['pos']) for packet in self.packets] + [self.filesize]
        for i, frame in enumerate(self.packets):
            frame_size = offsets[i + 1] - offsets[i]
            self.file.seek(offsets[i])
            raw_frame = self.file.read(frame_size)
            yield raw_frame, frame, frame['flags'][0] == 'K'

    def generate_SFV(self, builder : "USMBuilder"):        
        v_framerate = int(self.framerate)
        current_interval = 0
        #########################################
        # SFV chunks generator.
        #########################################
        SFV_list = []
        SFV_chunk = b""
        count = 0
        self.minchk = 0
        self.minbuf = 0
        bitrate = 0
        for data, _, is_keyframe in self.frames():
            # SFV has priority in chunks, it comes first.
            datalen = len(data)
            padlen = 0x20 - (datalen % 0x20) if datalen % 0x20 != 0 else 0
            SFV_chunk = USMChunkHeader.pack(
                USMChunckHeaderType.SFV.value,
                datalen + 0x18 + padlen,
                0,
                0x18,
                padlen,
                0,
                0,
                0,
                0,
                int(current_interval),
                v_framerate,
                0,
                0,
            )
            if builder.encrypt:
                data = builder.VideoMask(data)
            SFV_chunk += data
            SFV_chunk = SFV_chunk.ljust(datalen + 0x18 + padlen + 0x8, b"\x00")
            SFV_list.append(SFV_chunk)
            count += 1
            current_interval = round(count / self.framerate, 1)
            if is_keyframe:
                self.minchk += 1
            if self.minbuf < datalen:
                self.minbuf = datalen
            bitrate += datalen * 8 * v_framerate
        else:
            self.avbps = int(bitrate / count)
            SFV_chunk = USMChunkHeader.pack(
                USMChunckHeaderType.SFV.value, 0x38, 0, 0x18, 0, 0, 0, 0, 2, 0, 30, 0, 0
            )
            SFV_chunk += b"#CONTENTS END   ===============\x00"
            SFV_list.append(SFV_chunk)
        return SFV_list

class VP9Encoder(FFmpegParser):
    MPEG_CODEC = 9
    MPEG_DCPREC = 0
    VERSION = 16777984
    def __init__(self, filename):
        super().__init__(filename)
        assert self.format == 'ivf', "must be ivf format."
class H264Encoder(FFmpegParser):
    MPEG_CODEC = 5
    MPEG_DCPREC = 11
    VERSION = 0
    
    def __init__(self, filename):
        super().__init__(filename)
        assert self.format == 'h264', "must be raw h264 data. transcode with '.h264' suffix as output"
class MPEG1Encoder(FFmpegParser):
    MPEG_CODEC = 1
    MPEG_DCPREC = 11
    VERSION = 0

class HCAEncoder(HCA):
    AUDIO_CODEC = 4
    METADATA_COUNT = 1
    
    filename : str

    chnls : int
    sampling_rate : int
    total_samples : int
    
    avbps: int
    
    filesize : int
    def __init__(self, stream, filename: str, key = 0, subkey = 0):
        self.filename = filename
        super().__init__(stream, key, subkey)
        if self.filetype == 'wav':
            self.encode(
                force_not_looping=True,
                encrypt=key != 0,
                keyless=False,
            )
        self.hcastream.seek(0, 2)
        self.filesize = self.hcastream.tell()
        self.hcastream.seek(0)

        if self.filetype == "wav":
            self.chnls = self.fmtChannelCount
            self.sampling_rate = self.fmtSamplingRate
            self.total_samples = int(self.dataSize // self.fmtSamplingSize)
        else:
            self.chnls = self.hca["ChannelCount"]
            self.sampling_rate = self.hca["SamplingRate"]
            self.total_samples = self.hca["FrameCount"]
        # I don't know how this is derived so I am putting my best guess here. TODO
        self.avbps = int(self.filesize / self.chnls)

    def generate_SFA(self, builder: "USMBuilder"):
        current_interval = 0
        padding = (
            0x20 - (self.hca["HeaderSize"] % 0x20)
            if self.hca["HeaderSize"] % 0x20 != 0
            else 0
        )
        SFA_chunk = USMChunkHeader.pack(
            USMChunckHeaderType.SFA.value,
            self.hca["HeaderSize"] + 0x18 + padding,
            0,
            0x18,
            padding,
            i,
            0,
            0,
            0,
            current_interval,
            2997,
            0,
            0,
        )
        SFA_chunk += self.get_header().ljust(
            self.hca["HeaderSize"] + padding, b"\x00"
        )
        res = []
        res.append(SFA_chunk)
        for i, frame in enumerate(self.get_frames(), start=1):
            padding = (
                0x20 - (self.hca["FrameSize"] % 0x20)
                if self.hca["FrameSize"] % 0x20 != 0
                else 0
            )
            SFA_chunk = USMChunkHeader.pack(
                USMChunckHeaderType.SFA.value,
                self.hca["FrameSize"] + 0x18 + padding,
                0,
                0x18,
                padding,
                i,
                0,
                0,
                0,
                current_interval,
                2997,
                0,
                0,
            )
            SFA_chunk += frame[1].ljust(
                self.hca["FrameSize"] + padding, b"\x00"
            )
            current_interval = round(
                i
                * self.base_interval_per_SFA_chunk[
                    i
                ]
            )
            res.append(SFA_chunk)
        else:
            SFA_chunk = USMChunkHeader.pack(
                USMChunckHeaderType.SFA.value,
                0x38,
                0,
                0x18,
                0,
                i,
                0,
                0,
                2,
                0,
                30,
                0,
                0,
            )
            SFA_chunk += b"#CONTENTS END   ===============\x00"
            res[-1] += SFA_chunk      
        
        return res  
    
    def get_metadata(self):
        payload = [
            dict(hca_header=(UTFTypeValues.bytes, self.get_header()))
        ]
        p = UTFBuilder(payload, table_name="AUDIO_HEADER")
        p.strings = b"<NULL>\x00" + p.strings     
        return p.bytes()   
    
    @property
    def extra_hdrinfo(self):
        return {"ambisonics": (UTFTypeValues.uint, 0)}

class USMBuilder(USMCrypt):
    
    enable_audio: bool
    audio_streams: List[HCAEncoder]    

    video_stream : VP9Encoder | H264Encoder | MPEG1Encoder
    
    key: int
    encrypt: bool
    encrypt_audio: bool
        
    def __init__(
        self,
        video : str,
        audio: List[str] | str = None,
        key=False,
        audio_codec = 'hca',
        encrypt_audio: bool = False,
    ) -> None:
        """USM constructor, needs a video to build a USM."""        
        self.audio_codec = audio_codec.lower()
        self.encrypt = False
        self.enable_audio = False
        self.encrypt_audio = encrypt_audio
        self.key = 0
        if encrypt_audio and not key:
            raise ValueError("Cannot encrypt Audio without key.")
        if key:
            self.init_key(key)
            self.encrypt = True
        self.load_video(video)
        self.audio_streams = []
        if audio:
            self.load_audio(audio)
            self.enable_audio = True

    def load_video(self, video):
        temp_stream = FFmpegParser(video)
        self.video_stream = None
        match temp_stream.stream['codec_name']:
            case 'h264':
                self.video_stream = H264Encoder(video)
            case 'vp9':
                self.video_stream = VP9Encoder(video)
            case 'mpeg1video':
                self.video_stream = MPEG1Encoder(video)
        assert self.video_stream, "fail to match suitable video codec. Codec=%s" % temp_stream.stream['codec_name']

    def load_audio(self, audio):
        self.audio_filenames = []
        if type(audio) == list:
            count = 0
            for track in audio:
                if type(track) == str:
                    self.audio_filenames.append(os.path.basename(track))
                else:
                    self.audio_filenames.append("{:02d}.sfa".format(count))
                    count += 1
        else:
            if type(audio) == str:
                self.audio_filenames.append(os.path.basename(audio))
            else:
                self.audio_filenames.append("00.sfa")

        self.audio_streams = []
        if self.audio_codec == "hca":
            if type(audio) == list:
                for track in audio:
                    if type(track) == str:
                        fn = os.path.basename(track)
                    else:
                        fn = "{:02d}.sfa".format(count)                        
                    hcaObj = HCAEncoder(track, fn, key=self.key if self.enable_audio else 0)
                    self.audio_streams.append(hcaObj)
            else:
                if type(audio) == str:
                    fn = os.path.basename(audio)
                else:
                    fn = "00.sfa"
                hcaObj = HCAEncoder(track, fn, key=self.key if self.enable_audio else 0)
                self.audio_streams.append(hcaObj)
        
        assert self.audio_streams, "fail to match suitable audio codec given option: %s" % self.audio_codec
    
    def build(self) -> bytes:                
        SFV_list = self.video_stream.generate_SFV(self)        
        if self.enable_audio:
            SFA_chunks = [s.generate_SFA(self) for s in self.audio_streams]         
        else:
            SFA_chunks = []
        SBT_chunks = [] # TODO: Subtitles       
        header = self._build_header(SFV_list, SFA_chunks, SBT_chunks)        
        chunks = list(itertools.chain(SFV_list, *SFA_chunks))
        def chunk_key_sort(chunk):
            (
                header,
                chuncksize,
                unk08,
                offset,
                padding,
                chno,
                unk0D,
                unk0E,
                type,
                frametime,
                framerate,
                unk18,
                unk1C,
            ) = USMChunkHeader.unpack(chunk[: USMChunkHeader.size])
            prio = 0 if header.decode() == "@SFV" else 1
            # all stream chunks before section_end chunks, then sort by frametime, with SFV chunks before SFA chunks
            return (type, frametime, prio)
        chunks.sort(key=chunk_key_sort)
        self.usm = header
        for chunk in chunks:
            self.usm += chunk
        return self.usm

    def _build_header(
        self, SFV_list: list, SFA_chunks: list, SBT_chunks : list # TODO: Not used
    ) -> bytes:
        # Main USM file
        CRIUSF_DIR_STREAM = [
            dict(
                fmtver=(UTFTypeValues.uint, self.video_stream.VERSION),
                filename=(
                    UTFTypeValues.string,
                    os.path.splitext(os.path.basename(self.video_stream.filename))[0] + '.usm'
                ),
                filesize=(UTFTypeValues.uint, -1),  # Will be updated later.
                datasize=(UTFTypeValues.uint, 0),
                stmid=(UTFTypeValues.uint, 0),
                chno=(UTFTypeValues.ushort, 0xFFFF),
                minchk=(UTFTypeValues.ushort, 1),
                minbuf=(UTFTypeValues.uint, -1),  # Will be updated later.
                avbps=(UTFTypeValues.uint, -1),  # Will be updated later.
            )
        ]

        total_avbps = self.video_stream.avbps
        minbuf = 4 + self.video_stream.minbuf

        v_filesize = self.video_stream.filesize        

        video_dict = dict(
            fmtver=(UTFTypeValues.uint, self.video_stream.VERSION),
            filename=(UTFTypeValues.string, os.path.basename(self.video_stream.filename)),
            filesize=(UTFTypeValues.uint, v_filesize),
            datasize=(UTFTypeValues.uint, 0),
            stmid=(
                UTFTypeValues.uint,
                int.from_bytes(USMChunckHeaderType.SFV.value, "big"),
            ),
            chno=(UTFTypeValues.ushort, 0),
            minchk=(UTFTypeValues.ushort, self.video_stream.minchk),
            minbuf=(UTFTypeValues.uint, self.video_stream.minbuf),
            avbps=(UTFTypeValues.uint, self.video_stream.avbps),
        )
        CRIUSF_DIR_STREAM.append(video_dict)

        if self.enable_audio:
            chno = 0
            for stream in self.audio_streams:
                avbps = stream.avbps
                total_avbps += avbps
                minbuf += 27860
                audio_dict = dict(
                    fmtver=(UTFTypeValues.uint, 0),
                    filename=(UTFTypeValues.string, self.audio_filenames[chno]),
                    filesize=(UTFTypeValues.uint, stream.filesize),
                    datasize=(UTFTypeValues.uint, 0),
                    chno=(UTFTypeValues.ushort, chno),
                    stmid=(
                        UTFTypeValues.uint,
                        int.from_bytes(USMChunckHeaderType.SFA.value, "big"),
                    ),
                    minchk=(UTFTypeValues.ushort, 1),
                    minbuf=(
                        UTFTypeValues.uint,
                        27860,
                    ),  # minbuf is fixed at that for audio.
                    avbps=(UTFTypeValues.uint, avbps),
                )
                CRIUSF_DIR_STREAM.append(audio_dict)
                chno += 1

        CRIUSF_DIR_STREAM[0]["avbps"] = (UTFTypeValues.uint, total_avbps)
        CRIUSF_DIR_STREAM[0]["minbuf"] = (
            UTFTypeValues.uint,
            minbuf,
        )  # Wrong. TODO Despite being fixed per SFA stream, seems to change internally before summation.

        VIDEO_HDRINFO = [
            {
                "width": (UTFTypeValues.uint, self.video_stream.width),
                "height": (UTFTypeValues.uint, self.video_stream.height),
                "mat_width": (UTFTypeValues.uint, self.video_stream.width),
                "mat_height": (UTFTypeValues.uint, self.video_stream.height),
                "disp_width": (UTFTypeValues.uint, self.video_stream.width),
                "disp_height": (UTFTypeValues.uint, self.video_stream.height),
                "scrn_width": (UTFTypeValues.uint, 0),
                "mpeg_dcprec": (UTFTypeValues.uchar, self.video_stream.MPEG_DCPREC),
                "mpeg_codec": (UTFTypeValues.uchar, self.video_stream.MPEG_CODEC),
                "alpha_type": (UTFTypeValues.uint, 0),
                "total_frames": (UTFTypeValues.uint, self.video_stream.frame_count),
                "framerate_n": (UTFTypeValues.uint, self.video_stream.framerate * 1000),
                "framerate_d": (UTFTypeValues.uint, 1000), # Denominator
                "metadata_count": (
                    UTFTypeValues.uint,
                    1,
                ),  # Could be 0 and ignore metadata?
                "metadata_size": (
                    UTFTypeValues.uint,
                    224,
                ), 
                "ixsize": (UTFTypeValues.uint, self.video_stream.minbuf),
                "pre_padding": (UTFTypeValues.uint, 0),
                "max_picture_size": (UTFTypeValues.uint, 0),
                "color_space": (UTFTypeValues.uint, 0),
                "picture_type": (UTFTypeValues.uint, 0),
            }
        ]
        v = UTFBuilder(VIDEO_HDRINFO, table_name="VIDEO_HDRINFO")
        v.strings = b"<NULL>\x00" + v.strings
        VIDEO_HDRINFO = v.bytes()
        padding = (
            0x20 - (len(VIDEO_HDRINFO) % 0x20)
            if (len(VIDEO_HDRINFO) % 0x20) != 0
            else 0
        )
        chk = USMChunkHeader.pack(
            USMChunckHeaderType.SFV.value,
            len(VIDEO_HDRINFO) + 0x18 + padding,
            0,
            0x18,
            padding,
            0,
            0,
            0,
            1,
            0,
            30,
            0,
            0,
        )
        chk += VIDEO_HDRINFO.ljust(len(VIDEO_HDRINFO) + padding, b"\x00")
        VIDEO_HDRINFO = chk

        audio_metadata = []
        if self.enable_audio:
            chno = 0
            for stream in self.audio_streams:                    
                metadata = stream.get_metadata()
                if not metadata:
                    audio_metadata.append(b"")
                else:
                    padding = (
                        0x20 - (len(metadata) % 0x20)
                        if len(metadata) % 0x20 != 0
                        else 0
                    )
                    chk = USMChunkHeader.pack(
                        USMChunckHeaderType.SFA.value,
                        len(metadata) + 0x18 + padding,
                        0,
                        0x18,
                        padding,
                        chno,
                        0,
                        0,
                        3,
                        0,
                        30,
                        0,
                        0,
                    )
                    chk += metadata.ljust(len(metadata) + padding, b"\x00")
                    audio_metadata.append(chk)
                chno += 1

            audio_headers = []
            chno = 0
            for stream in self.audio_streams:
                AUDIO_HDRINFO = [
                    {
                        "audio_codec": (
                            UTFTypeValues.uchar,
                            stream.AUDIO_CODEC
                        ),
                        "ixsize": (UTFTypeValues.uint, 27860),
                        "metadata_count": (
                            UTFTypeValues.uint,
                            stream.METADATA_COUNT
                        ),
                        "metadat_size": (
                            UTFTypeValues.uint,
                            len(audio_metadata[chno])
                        ),
                        "num_channels": (UTFTypeValues.uchar, stream.chnls),
                        "sampling_rate": (UTFTypeValues.uint, stream.sampling_rate),
                        "total_samples": (UTFTypeValues.uint, stream.total_samples),
                    }
                ]               
                if stream.extra_hdrinfo:
                    AUDIO_HDRINFO[0].update(stream.extra_hdrinfo)
                p = UTFBuilder(AUDIO_HDRINFO, table_name="AUDIO_HDRINFO")
                p.strings = b"<NULL>\x00" + p.strings
                header = p.bytes()
                padding = (
                    0x20 - (len(header) % 0x20) if (len(header) % 0x20) != 0 else 0
                )
                chk = USMChunkHeader.pack(
                    USMChunckHeaderType.SFA.value,
                    len(header) + 0x18 + padding,
                    0,
                    0x18,
                    padding,
                    chno,
                    0,
                    0,
                    1,
                    0,
                    30,
                    0,
                    0,
                )
                chk += header.ljust(len(header) + padding, b"\x00")
                audio_headers.append(chk)
                chno += 1

        keyframes = [(data['pos'], i) for i, (frame, data, is_keyframe) in enumerate(self.video_stream.frames()) if is_keyframe]
        def comp_seek_info(first_chk_ofs):
            seek = [
                {
                    "ofs_byte": (UTFTypeValues.ullong, first_chk_ofs + int(pos)),
                    "ofs_frmid": (UTFTypeValues.int, i),
                    "num_skip": (UTFTypeValues.short, 0),
                    "resv": (UTFTypeValues.short, 0),
                } for pos, i in keyframes
            ]
            seek = UTFBuilder(seek, table_name="VIDEO_SEEKINFO")
            seek.strings = b"<NULL>\x00" + seek.strings
            seek = seek.bytes()
            padding = (
                0x20 - len(seek) % 0x20 if len(seek) % 0x20 != 0 else 0
            )
            seekinf = USMChunkHeader.pack(
                USMChunckHeaderType.SFV.value,
                len(seek) + 0x18 + padding,
                0,
                0x18,
                padding,
                0,
                0,
                0,
                3,
                0,
                30,
                0,
                0,
            )
            seekinf += seek.ljust(len(seek) + padding, b"\x00")
            return seekinf
        len_seek = len(comp_seek_info(0))
        first_chk_ofs = (
            0x800
            + len(VIDEO_HDRINFO)
            + len_seek
            + 0x40 * len(self.audio_streams)
            + 128
            + (
                0
                if not self.enable_audio
                else sum([len(x) + 0x40 for x in audio_headers])
                + (
                    sum([(len(x) + 0x40) if len(x) else 0 for x in audio_metadata])
                )
            )
        )        
        VIDEO_SEEKINFO = comp_seek_info(first_chk_ofs)
        total_len = sum([len(x) for x in SFV_list]) + first_chk_ofs
        if self.enable_audio:
            sum_len = 0
            for stream in SFA_chunks:
                for x in stream:
                    sum_len += len(x)
            total_len += sum_len

        CRIUSF_DIR_STREAM[0]["filesize"] = (UTFTypeValues.uint, total_len)
        CRIUSF_DIR_STREAM = UTFBuilder(
            CRIUSF_DIR_STREAM, table_name="CRIUSF_DIR_STREAM"
        )
        CRIUSF_DIR_STREAM.strings = b"<NULL>\x00" + CRIUSF_DIR_STREAM.strings
        CRIUSF_DIR_STREAM = CRIUSF_DIR_STREAM.bytes()

        ##############################################
        # Parsing everything.
        ##############################################
        header = bytes()
        # CRID
        padding = 0x800 - len(CRIUSF_DIR_STREAM)
        CRID = USMChunkHeader.pack(
            USMChunckHeaderType.CRID.value,
            0x800 - 0x8,
            0,
            0x18,
            padding - 0x20,
            0,
            0,
            0,
            1,
            0,
            30,
            0,
            0,
        )
        CRID += CRIUSF_DIR_STREAM.ljust(0x800 - 0x20, b"\x00")
        header += CRID

        # Header chunks
        header += VIDEO_HDRINFO
        if self.enable_audio:
            SFA_END = []
            count = 0
            for chunk in audio_headers:
                header += chunk
                SFA_chk_END = USMChunkHeader.pack(
                    USMChunckHeaderType.SFA.value,
                    0x38,
                    0,
                    0x18,
                    0x0,
                    count,
                    0x0,
                    0x0,
                    2,
                    0,
                    30,
                    0,
                    0,
                )
                SFA_END.append(SFA_chk_END + b"#HEADER END     ===============\x00")
                count += 1
        SFV_END = USMChunkHeader.pack(
            USMChunckHeaderType.SFV.value,
            0x38,
            0,
            0x18,
            0x0,
            0x0,
            0x0,
            0x0,
            2,
            0,
            30,
            0,
            0,
        )
        SFV_END += b"#HEADER END     ===============\x00"

        header += SFV_END
        if self.enable_audio:
            for chk in SFA_END:
                header += chk


        header += VIDEO_SEEKINFO

        if self.enable_audio:
            count = 0
            metadata_end = []
            for metadata in audio_metadata:
                if not metadata:
                    break
                header += metadata
                SFA_chk_END = USMChunkHeader.pack(
                    USMChunckHeaderType.SFA.value,
                    0x38,
                    0,
                    0x18,
                    0x0,
                    count,
                    0x0,
                    0x0,
                    2,
                    0,
                    30,
                    0,
                    0,
                )
                metadata_end.append(
                    SFA_chk_END + b"#METADATA END   ===============\x00"
                )
                count += 1
        SFV_END = USMChunkHeader.pack(
            USMChunckHeaderType.SFV.value,
            0x38,
            0,
            0x18,
            0x0,
            0x0,
            0x0,
            0x0,
            2,
            0,
            30,
            0,
            0,
        )
        SFV_END += b"#METADATA END   ===============\x00"
        header += SFV_END

        if self.enable_audio and self.audio_codec == "hca":
            for chk in metadata_end:
                header += chk

        return header
