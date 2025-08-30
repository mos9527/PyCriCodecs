import os
import itertools, shutil
from typing import BinaryIO, List
from io import FileIO, BytesIO
from functools import cached_property

from PyCriCodecsEx.chunk import *
from PyCriCodecsEx.utf import UTF, UTFBuilder
try:
    import ffmpeg
except ImportError:
    raise ImportError("ffmpeg-python is required for USM support. Install via PyCriCodecsEx[usm] extra.")
import tempfile

# Big thanks and credit for k0lb3 and 9th helping me write this specific code.
# Also credit for the original C++ code from Nyagamon/bnnm and https://github.com/donmai-me/WannaCRI/

class USMCrypt:
    """USM related crypto functions"""
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


# There are a lot of unknowns, minbuf(minimum buffer of what?) and avbps(average bitrate per second)
# are still unknown how to derive them, at least video wise it is possible, no idea how it's calculated audio wise nor anything else
# seems like it could be random values and the USM would still work.
class FFmpegCodec:
    """Base codec for FFMpeg-based Video streams"""
    filename: str
    filesize: int

    info: dict
    file: FileIO

    minchk: int
    minbuf: int
    avbps: int

    def __init__(self, stream: str | bytes):
        """Initialize FFmpegCodec with a media stream, gathering metadata and frame info.

        Args:
            stream (str | bytes): The media stream to process.
        NOTE:
            A temp file maybe created for probing only. Which will be deleted after use.
        """
        if type(stream) == str:
            self.filename = stream
        else:
            self.tempfile = tempfile.NamedTemporaryFile(delete=False)
            self.tempfile.write(stream)
            self.tempfile.close()
            self.filename = self.tempfile.name
        self.info = ffmpeg.probe(
            self.filename, show_entries="packet=dts,pts_time,pos,flags,duration_time"
        )
        if type(stream) == str:
            self.file = open(self.filename, "rb")            
            self.filesize = os.path.getsize(self.filename)
        else:
            os.unlink(self.tempfile.name)
            self.file = BytesIO(stream)
            self.filesize = len(stream)

    @property
    def format(self):
        return self.info["format"]["format_name"]

    @property
    def stream(self) -> dict:
        return self.info["streams"][0]

    @property
    def codec(self):
        return self.stream["codec_name"]
    
    @cached_property
    def framerate(self):
        """Running framerate (max frame rate)"""        
        # Lesson learned. Do NOT trust the metadata.
        # num, denom = self.stream["r_frame_rate"].split("/")
        # return int(int(num) / int(denom))
        return 1 / min((dt for _, _, _, dt in self.frames()))

    @cached_property
    def avg_framerate(self):
        """Average framerate"""
        # avg_frame_rate = self.stream.get("avg_frame_rate", None)
        # if avg_frame_rate:
        #     num, denom = avg_frame_rate.split("/")
        #     return int(int(num) / int(denom))
        return self.frame_count / sum((dt for _, _, _, dt in self.frames()))

    @property
    def packets(self):
        return self.info["packets"]

    @property
    def width(self):
        return self.stream["width"]

    @property
    def height(self):
        return self.stream["height"]

    @property
    def frame_count(self):
        return len(self.packets)

    def frames(self):
        """Generator of [frame data, frame dict, is keyframe, duration]"""
        offsets = [int(packet["pos"]) for packet in self.packets] + [self.filesize]
        for i, frame in enumerate(self.packets):
            frame_size = offsets[i + 1] - offsets[i]
            self.file.seek(offsets[i])
            raw_frame = self.file.read(frame_size)
            yield raw_frame, frame, frame["flags"][0] == "K", float(frame["duration_time"])

    def generate_SFV(self, builder: "USMBuilder"):        
        v_framerate = int(self.framerate)
        current_interval = 0
        SFV_list = []
        SFV_chunk = b""
        count = 0
        self.minchk = 0
        self.minbuf = 0
        bitrate = 0
        for data, _, is_keyframe, dt in self.frames():
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
            current_interval += 2997 * dt # 29.97 as base
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

    def save(self, filepath: str):
        '''Saves the underlying video stream to a file.'''
        tell = self.file.tell()
        self.file.seek(0)
        shutil.copyfileobj(self.file, open(filepath, 'wb'))
        self.file.seek(tell)

class VP9Codec(FFmpegCodec):
    """VP9 Video stream codec.
    
    Only streams with `.ivf` containers are supported."""
    MPEG_CODEC = 9
    MPEG_DCPREC = 0
    VERSION = 16777984

    def __init__(self, filename: str | bytes):
        super().__init__(filename)
        assert self.format == "ivf", "must be ivf format."
class H264Codec(FFmpegCodec):
    """H264 Video stream codec.

    Only streams with `.h264` containers are supported."""
    MPEG_CODEC = 5
    MPEG_DCPREC = 11
    VERSION = 0

    def __init__(self, filename : str | bytes):
        super().__init__(filename)
        assert (
            self.format == "h264"
        ), "must be raw h264 data. transcode with '.h264' suffix as output"
class MPEG1Codec(FFmpegCodec):
    """MPEG1 Video stream codec.

    Only streams with `.mpeg1` containers are supported."""
    MPEG_CODEC = 1
    MPEG_DCPREC = 11
    VERSION = 0

    def __init__(self, stream : str | bytes):
        super().__init__(stream)
        assert self.format == "mpegvideo", "must be m1v format (mpegvideo)."

from PyCriCodecsEx.hca import HCACodec
from PyCriCodecsEx.adx import ADXCodec

class USM(USMCrypt):
    """Use this class to extract infromation and data from a USM file."""

    filename: str
    decrypt: bool
    stream: BinaryIO
    CRIDObj: UTF
    output: dict[str, bytes]
    size: int
    demuxed: bool

    audio_codec: int
    video_codec: int

    metadata: list

    def __init__(self, filename : str | BinaryIO, key: str | int = None):
        """Loads a USM file into memory and prepares it for processing.

        Args:
            filename (str): The path to the USM file.
            key (str, optional): The decryption key. Either int64 or a hex string. Defaults to None.
        """
        self.filename = filename
        self.decrypt = False

        if key:
            self.decrypt = True
            self.init_key(key)
        self._load_file()
    
    def _load_file(self):
        if type(self.filename) == str:
            self.stream = open(self.filename, "rb")
        else:
            self.stream = self.filename
        self.stream.seek(0, 2)
        self.size = self.stream.tell()
        self.stream.seek(0)
        header = self.stream.read(4)
        if header != USMChunckHeaderType.CRID.value:
            raise NotImplementedError(f"Unsupported file type: {header}")
        self.stream.seek(0)
        self._demux()

    def _demux(self) -> None:
        """Gets data from USM chunks and assignes them to output."""
        self.stream.seek(0)
        self.metadata = list()
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
                    data = self._reader(chuncksize, offset, padding, header)
                    output[header.decode() + "_" + str(chno)].extend(data)
                elif type == 1 or type == 3:
                    ChunkObj = UTF(self.stream.read(chuncksize))
                    self.metadata.append(ChunkObj)
                    if type == 1:
                        if header == USMChunckHeaderType.SFA.value:
                            codec = ChunkObj.dictarray[0]
                            self.audio_codec = codec["audio_codec"][1]  
                            # So far, audio_codec of 2, means ADX, while audio_codec 4 means HCA.
                        if header == USMChunckHeaderType.SFV.value:                            
                            self.video_codec = ChunkObj.dictarray[0]['mpeg_codec'][1]
                else:
                    self.stream.seek(chuncksize, 1)
            else:
                # It is likely impossible for the code to reach here, since the code right now is suitable
                # for any chunk type specified in the CRID header.
                # But just incase somehow there's an extra chunk, this code might handle it.
                if header in [chunk.value for chunk in USMChunckHeaderType]:
                    if type == 0:
                        output[header.decode() + "_0"] = bytearray()
                        data = self._reader(chuncksize, offset, padding, header)
                        output[header.decode() + "_0"].extend(
                            data
                        )  # No channel number info, code here assumes it's a one channel data type.
                    elif type == 1 or type == 3:
                        ChunkObj = UTF(self.stream.read(chuncksize))
                        self.metadata.append(ChunkObj)
                        if type == 1 and header == USMChunckHeaderType.SFA.value:
                            codec = ChunkObj.dictarray[0]
                            self.audio_codec = codec["audio_codec"][1]
                    else:
                        self.stream.seek(chuncksize, 1)
                else:
                    raise NotImplementedError(f"Unsupported chunk type: {header}")
        self.output = output
        self.demuxed = True

    def _reader(self, chuncksize, offset, padding, header) -> bytearray:
        """Chunks reader function, reads all data in a chunk and returns a bytearray."""
        data = bytearray(self.stream.read(chuncksize)[offset:])
        if (
            header == USMChunckHeaderType.SFV.value
            or header == USMChunckHeaderType.ALP.value
        ):
            data = self.VideoMask(data) if self.decrypt else data
        elif header == USMChunckHeaderType.SFA.value:
            data = self.AudioMask(data) if (self.audio_codec == 2 and self.decrypt) else data
        if padding:
            data = data[:-padding]
        return data

    @property
    def streams(self):
        """Generator of Tuple[Stream Type ("@SFV", "@SFA"), File name, Raw stream data]"""
        for stream in self.CRIDObj.dictarray[1:]:
            filename, stmid, chno = stream["filename"][1], stream["stmid"][1], stream["chno"][1]
            stmid = int.to_bytes(stmid, 4, 'big', signed='False')
            yield stmid, str(filename), self.output.get(f'{stmid.decode()}_{chno}', None)
    
    def get_video(self) -> VP9Codec | H264Codec | MPEG1Codec:
        """Create a video codec from the available streams.

        NOTE: A temporary file may be created with this process to determine the stream information."""
        stype, sfname, sraw = next(filter(lambda x: x[0] == USMChunckHeaderType.SFV.value, self.streams), (None, None, None))
        stream = None
        match self.video_codec:
            case MPEG1Codec.MPEG_CODEC:
                stream = MPEG1Codec(sraw)
            case H264Codec.MPEG_CODEC:
                stream = H264Codec(sraw)
            case VP9Codec.MPEG_CODEC:
                stream = VP9Codec(sraw)
            case _:
                raise NotImplementedError(f"Unsupported video codec: {self.video_codec}")
        stream.filename = sfname
        return stream

    def get_audios(self) -> List[ADXCodec | HCACodec]:
        """Create a list of audio codecs from the available streams."""
        match self.audio_codec:
            case ADXCodec.AUDIO_CODEC:
                return [ADXCodec(s[2], s[1]) for s in self.streams if s[0] == USMChunckHeaderType.SFA.value]
            case HCACodec.AUDIO_CODEC:
                return [HCACodec(s[2], s[1]) for s in self.streams if s[0] == USMChunckHeaderType.SFA.value] # HCAs are never encrypted in USM
            case _:
                return []

class USMBuilder(USMCrypt):
    """Use this class to build USM files."""
    video_stream: VP9Codec | H264Codec | MPEG1Codec
    audio_streams: List[HCACodec | ADXCodec]

    key: int = None
    encrypt: bool = False
    encrypt_audio: bool = False

    def __init__(
        self,
        key = None,
        encrypt_audio = False
    ) -> None:
        """Initialize the USMBuilder from set source files.

        Args:
            key (str | int, optional): The encryption key. Either int64 or a hex string. Defaults to None.
            encrypt_audio (bool, optional): Whether to also encrypt the audio. Defaults to False.
        """
        if key:
            self.init_key(key)
            self.encrypt = True
        self.encrypt_audio = encrypt_audio
        self.audio_streams = []

    def add_video(self, video : str | H264Codec | VP9Codec | MPEG1Codec):
        """Sets the video stream from the specified video file.

        USMs only support one video stream. Consecutive calls to this method will replace the existing video stream.

        When `video` is str - it will be treated as a file path. The video source format will be used to map accordingly to the ones Sofdec use.
            - MPEG1 (with M1V container): MPEG1 Codec (Sofdec Prime)
            - H264 (with H264 container): H264 Codec
            - VP9 (with IVF container): VP9 Codec
            
        Args:
            video (str | FFmpegCodec): The path to the video file or an FFmpegCodec instance.
        """
        if isinstance(video, str):
            temp_stream = FFmpegCodec(video)
            self.video_stream = None
            match temp_stream.stream["codec_name"]:
                case "h264":
                    self.video_stream = H264Codec(video)
                case "vp9":
                    self.video_stream = VP9Codec(video)
                case "mpeg1video":
                    self.video_stream = MPEG1Codec(video)
            assert self.video_stream, (
                "fail to match suitable video codec. Codec=%s"
                % temp_stream.stream["codec_name"]
            )
        else:
            self.video_stream = video

    def add_audio(self, audio : ADXCodec | HCACodec):
        """Append the audio stream(s) from the specified audio file(s).

        Args:
            audio (ADXCodec | HCACodec): The path(s) to the audio file(s).
        """
        self.audio_streams.append(audio)

    def build(self) -> bytes:
        """Build the USM payload"""
        SFV_list = self.video_stream.generate_SFV(self)
        if self.audio_streams:
            SFA_chunks = [s.generate_SFA(i, self) for i, s in enumerate(self.audio_streams) ]
        else:
            SFA_chunks = []
        SBT_chunks = []  # TODO: Subtitles
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
            prio = 0 if header == USMChunckHeaderType.SFV else 1
            # all stream chunks before section_end chunks, then sort by frametime, with SFV chunks before SFA chunks
            return (type, frametime, prio)

        chunks.sort(key=chunk_key_sort)        
        self.usm = header
        chunks = b''.join(chunks)
        self.usm += chunks
        return self.usm

    def _build_header(
        self, SFV_list: list, SFA_chunks: list, SBT_chunks: list  # TODO: Not used
    ) -> bytes:
        # Main USM file
        CRIUSF_DIR_STREAM = [
            dict(
                fmtver=(UTFTypeValues.uint, self.video_stream.VERSION),
                filename=(
                    UTFTypeValues.string,
                    os.path.splitext(os.path.basename(self.video_stream.filename))[0]
                    + ".usm",
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
            filename=(
                UTFTypeValues.string,
                os.path.basename(self.video_stream.filename),
            ),
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

        if self.audio_streams:
            chno = 0
            for stream in self.audio_streams:
                avbps = stream.avbps
                total_avbps += avbps
                minbuf += 27860
                audio_dict = dict(
                    fmtver=(UTFTypeValues.uint, 0),
                    filename=(UTFTypeValues.string, stream.filename),
                    filesize=(UTFTypeValues.uint, stream.filesize),
                    datasize=(UTFTypeValues.uint, 0),
                    stmid=(
                        UTFTypeValues.uint,
                        int.from_bytes(USMChunckHeaderType.SFA.value, "big"),
                    ),
                    chno=(UTFTypeValues.ushort, chno),
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

        def gen_video_hdr_info(metadata_size: int):
            hdr = [
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
                    "framerate_n": (
                        UTFTypeValues.uint,
                        int(self.video_stream.framerate * 1000),
                    ),
                    "framerate_d": (UTFTypeValues.uint, 1000),  # Denominator
                    "metadata_count": (
                        UTFTypeValues.uint,
                        1,
                    ),  # Could be 0 and ignore metadata?
                    "metadata_size": (
                        UTFTypeValues.uint,
                        metadata_size,
                    ),
                    "ixsize": (UTFTypeValues.uint, self.video_stream.minbuf),
                    "pre_padding": (UTFTypeValues.uint, 0),
                    "max_picture_size": (UTFTypeValues.uint, 0),
                    "color_space": (UTFTypeValues.uint, 0),
                    "picture_type": (UTFTypeValues.uint, 0),
                }
            ]
            v = UTFBuilder(hdr, table_name="VIDEO_HDRINFO")
            v.strings = b"<NULL>\x00" + v.strings
            hdr = v.bytes()
            padding = 0x20 - (len(hdr) % 0x20) if (len(hdr) % 0x20) != 0 else 0
            chk = USMChunkHeader.pack(
                USMChunckHeaderType.SFV.value,
                len(hdr) + 0x18 + padding,
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
            chk += hdr.ljust(len(hdr) + padding, b"\x00")
            return chk

        audio_metadata = []
        audio_headers = []
        if self.audio_streams:
            chno = 0
            for stream in self.audio_streams:
                metadata = stream.get_metadata()
                if not metadata:
                    break
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

            chno = 0
            for stream in self.audio_streams:
                AUDIO_HDRINFO = [
                    {
                        "audio_codec": (UTFTypeValues.uchar, stream.AUDIO_CODEC),
                        "sampling_rate": (UTFTypeValues.uint, stream.sampling_rate),
                        "total_samples": (UTFTypeValues.uint, stream.total_samples),
                        "num_channels": (UTFTypeValues.uchar, stream.chnls),
                        "metadata_count": (UTFTypeValues.uint, stream.METADATA_COUNT),
                        "metadat_size": (UTFTypeValues.uint, len(audio_metadata[chno]) if audio_metadata else 0),
                        "ixsize": (UTFTypeValues.uint, 27860),
                        "ambisonics": (UTFTypeValues.uint, 0)
                    }
                ]                
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

        keyframes = [
            (data["pos"], i)
            for i, (frame, data, is_keyframe, duration) in enumerate(self.video_stream.frames())
            if is_keyframe
        ]

        def comp_seek_info(first_chk_ofs):
            seek = [
                {
                    "ofs_byte": (UTFTypeValues.ullong, first_chk_ofs + int(pos)),
                    "ofs_frmid": (UTFTypeValues.int, i),
                    "num_skip": (UTFTypeValues.short, 0),
                    "resv": (UTFTypeValues.short, 0),
                }
                for pos, i in keyframes
            ]
            seek = UTFBuilder(seek, table_name="VIDEO_SEEKINFO")
            seek.strings = b"<NULL>\x00" + seek.strings
            seek = seek.bytes()
            padding = 0x20 - len(seek) % 0x20 if len(seek) % 0x20 != 0 else 0
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
        len_audio_headers = sum([len(x) + 0x40 for x in audio_headers])
        len_audio_metadata = sum([len(x) + 0x40 for x in audio_metadata])
        first_chk_ofs = (
            0x800 # CRID
            + 512 # VIDEO_HDRINFO
            + len_seek
            + 128 # SFV_END * 2
            + len_audio_headers
            + len_audio_metadata
        )
        VIDEO_SEEKINFO = comp_seek_info(first_chk_ofs)
        VIDEO_HDRINFO = gen_video_hdr_info(len(VIDEO_SEEKINFO))

        total_len = sum([len(x) for x in SFV_list]) + first_chk_ofs
        if self.audio_streams:
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
        if self.audio_streams:
            header += b''.join(audio_headers)            
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

        SFA_chk_END  = b'' # Maybe reused
        if self.audio_streams:
            SFA_chk_END  = b''.join([
                USMChunkHeader.pack(
                    USMChunckHeaderType.SFA.value,
                    0x38,
                    0,
                    0x18,
                    0x0,
                    i,
                    0x0,
                    0x0,
                    2,
                    0,
                    30,
                    0,
                    0,
                ) + b"#HEADER END     ===============\x00" for i in range(len(audio_headers))
            ])
        header += SFA_chk_END # Ends audio_headers
        header += VIDEO_SEEKINFO

        if self.audio_streams:
            header += b''.join(audio_metadata)
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

        if audio_metadata:
            SFA_chk_END  = b''.join([
                USMChunkHeader.pack(
                    USMChunckHeaderType.SFA.value,
                    0x38,
                    0,
                    0x18,
                    0x0,
                    i,
                    0x0,
                    0x0,
                    2,
                    0,
                    30,
                    0,
                    0,
                ) + b"#METADATA END   ===============\x00" for i in range(len(audio_headers))
            ])
            header += SFA_chk_END # Ends audio_headers

        return header
