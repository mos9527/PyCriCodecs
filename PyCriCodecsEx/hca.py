from io import BytesIO, FileIO
from struct import *
from typing import BinaryIO
from array import array
import CriCodecsEx

from PyCriCodecsEx.chunk import *
from PyCriCodecsEx.utf import UTFTypeValues, UTFBuilder
HcaHeaderStruct = Struct(">4sHH")
HcaFmtHeaderStruct = Struct(">4sIIHH")
HcaCompHeaderStruct = Struct(">4sHBBBBBBBBBB")
HcaDecHeaderStruct = Struct(">4sHBBBBBB")
HcaLoopHeaderStruct = Struct(">4sIIHH")
HcaAthHeaderStruct = Struct(">4sH")
HcaVbrHeaderStruct = Struct(">4sHH")
HcaCiphHeaderStruct = Struct(">4sH")
HcaRvaHeaderStruct = Struct(">4sf")

class HCA:
    """HCA class for decoding and encoding HCA files

    **NOTE:** Direct usage of this class is not recommended, use the `HCACodec` wrapper instead.
    """
    stream: BinaryIO
    hcastream: BinaryIO
    HcaSig: bytes
    version: int
    header_size: int
    key: int
    subkey: int
    hca: dict
    filetype: str
    wavbytes: bytearray
    hcabytes: bytearray
    riffSignature: bytes
    riffSize: int
    wave: bytes
    fmt: bytes
    fmtSize: int
    fmtType: int
    fmtChannelCount: int
    fmtSamplingRate: int
    fmtSamplesPerSec: int
    fmtSamplingSize: int
    fmtBitCount: int
    dataSig: bytes
    dataSize: int
    encrypted: bool
    enc_table: array
    table: array
    looping: bool

    def __init__(self, stream: str | BinaryIO, key: int = 0, subkey: int = 0) -> None:
        """Initializes the HCA encoder/decoder

        Args:
            stream (str | BinaryIO): Path to the HCA or WAV file, or a BinaryIO stream.
            key (int, optional): HCA key. Defaults to 0.
            subkey (int, optional): HCA subkey. Defaults to 0.
        """
        if type(stream) == str:
            self.stream = FileIO(stream)
            self.hcastream = FileIO(stream)
        else:
            # copying since for encryption and decryption we use the internal buffer in C++. 
            stream = bytearray(stream).copy()
            self.stream = BytesIO(stream)
            self.hcastream = BytesIO(stream)
        if type(key) == str:
            self.key = int(key, 16)
        else:
            self.key = key
        if type(subkey) == str:
            self.subkey = int(subkey, 16)
        else:
            self.subkey = subkey
        self.hcabytes: bytearray = b''
        self.enc_table: array = b''
        self.table: array = b''
        self._Pyparse_header()
    

    def _Pyparse_header(self) -> None:
        self.HcaSig, self.version, self.header_size = HcaHeaderStruct.unpack(
            self.hcastream.read(HcaHeaderStruct.size)
        )
        if self.HcaSig in [HCAType.HCA.value, HCAType.EHCA.value]:
            if not self.hcabytes:
                self.filetype = "hca"
            if self.HcaSig == HCAType.EHCA.value:
                self.encrypted = True
            else:
                self.encrypted = False
            if self.HcaSig != HCAType.HCA.value and self.HcaSig != HCAType.EHCA.value:
                raise ValueError("Invalid HCA file.")
            elif self.HcaSig == HCAType.EHCA.value and not self.key:
                self.key = 0xCF222F1FE0748978 # Default HCA key.
            elif self.key < 0:
                raise ValueError("HCA key cannot be a negative.")
            elif self.key > 0xFFFFFFFFFFFFFFFF:
                raise OverflowError("HCA key cannot exceed the maximum size of 8 bytes.")
            elif self.subkey < 0:
                raise ValueError("HCA subkey cannot be a negative.")
            elif self.subkey > 0xFFFF:
                raise OverflowError("HCA subkey cannot exceed 65535.")
            
            fmtsig, temp, framecount, encoder_delay, encoder_padding = HcaFmtHeaderStruct.unpack(
                self.hcastream.read(HcaFmtHeaderStruct.size)
            )
            channelcount = temp >> 24
            samplerate = temp & 0x00FFFFFF

            self.hca = dict(
                Encrypted = self.encrypted,
                Header=self.HcaSig,
                version=hex(self.version),
                HeaderSize=self.header_size,
                FmtSig = fmtsig,
                ChannelCount = channelcount,
                SampleRate = samplerate,
                FrameCount = framecount,
                EncoderDelay = encoder_delay,
                EncoderPadding = encoder_padding,
            )

            while True:
                sig = unpack(">I", self.hcastream.read(4))[0]
                self.hcastream.seek(-4, 1)
                sig = int.to_bytes(sig & 0x7F7F7F7F, 4, "big")
                if sig == b"comp":
                    compsig, framesize, minres, maxres, trackcount, channelconfig, totalbandcount, basebandcount, stereobandcount, bandsperhfrgroup, r1, r2 = HcaCompHeaderStruct.unpack(
                        self.hcastream.read(HcaCompHeaderStruct.size)
                    )
                    self.hca.update(
                        dict(
                            CompSig = compsig,
                            FrameSize = framesize,
                            MinResolution = minres,
                            MaxResolution = maxres,
                            TrackCount = trackcount,
                            ChannelConfig = channelconfig,
                            TotalBandCount = totalbandcount,
                            BaseBandCount = basebandcount, 
                            StereoBandCount = stereobandcount,
                            BandsPerHfrGroup = bandsperhfrgroup,
                            ReservedByte1 = r1,
                            ReservedByte2 = r2
                        )
                    )
                elif sig == b"ciph":
                    ciphsig, ciphertype = HcaCiphHeaderStruct.unpack(
                        self.hcastream.read(HcaCiphHeaderStruct.size)
                    )
                    if ciphertype == 1:
                        self.encrypted = True
                    self.hca.update(dict(CiphSig = ciphsig, CipherType = ciphertype))
                elif sig == b"loop":
                    self.looping = True
                    loopsig, loopstart, loopend, loopstartdelay, loopendpadding = HcaLoopHeaderStruct.unpack(
                        self.hcastream.read(HcaLoopHeaderStruct.size)
                    )
                    self.hca.update(dict(LoopSig = loopsig, LoopStart = loopstart, LoopEnd = loopend, LoopStartDelay = loopstartdelay, LoopEndPadding = loopendpadding))
                elif sig == b"dec\00":
                    decsig, framesize, maxres, minres, totalbandcount, basebandcount, temp, stereotype = HcaDecHeaderStruct.unpack(
                        self.hcastream.read(HcaDecHeaderStruct.size)
                    )
                    trackcount = temp >> 4
                    channelconfig = temp & 0xF
                    self.hca.update(
                        dict(
                            DecSig = decsig,
                            FrameSize = framesize,
                            MinResolution = minres,
                            MaxResolution = maxres,
                            TotalBandCount = totalbandcount,
                            BaseBandCoung = basebandcount, 
                            TrackCount = trackcount,
                            ChannelConfig = channelconfig,
                            StereoType = stereotype
                        )
                    )
                elif sig == b"ath\00":
                    athsig, tabletype = HcaAthHeaderStruct.unpack(
                        self.hcastream.read(HcaAthHeaderStruct.size)
                    )
                    self.hca.update(dict(AthSig = athsig, TableType = tabletype))
                elif sig == b"vbr\00":
                    vbrsig, maxframesize, noiselevel = HcaVbrHeaderStruct.unpack(
                        self.hcastream.read(HcaVbrHeaderStruct.size)
                    )
                    self.hca.update(dict(VbrSig = vbrsig, MaxFrameSize = maxframesize, NoiseLevel = noiselevel))
                elif sig == b"rva\00":
                    rvasig, volume = HcaRvaHeaderStruct.unpack(
                        self.hcastream.read(HcaRvaHeaderStruct.size)
                    )
                    self.hca.update(dict(RvaSig = rvasig, Volume = volume))
                else:
                    break
            Crc16 = self.hcastream.read(2)
            self.hca.update(dict(Crc16 = Crc16))

        elif self.HcaSig == b"RIFF":
            self.filetype = "wav"
            self.riffSignature, self.riffSize, self.wave, self.fmt, self.fmtSize, self.fmtType, self.fmtChannelCount, self.fmtSamplingRate, self.fmtSamplesPerSec, self.fmtSamplingSize, self.fmtBitCount = WavHeaderStruct.unpack(
                self.stream.read(WavHeaderStruct.size)
            )
            if self.riffSignature == b"RIFF" and self.wave == b'WAVE' and self.fmt == b'fmt ':
                if self.fmtBitCount != 16:
                    raise ValueError(f"WAV bitdepth of {self.fmtBitCount} is not supported, only 16 bit WAV files are supported.")
                elif self.fmtSize != 16:
                    raise ValueError(f"WAV file has an FMT chunk of an unsupported size: {self.fmtSize}, the only supported size is 16.")
                while (hdr := self.stream.read(4)):
                    size = int.from_bytes(self.stream.read(4), 'little')
                    size += (size & 1) # padding
                    offset = self.stream.tell()
                    match hdr:
                        case b"smpl":
                            self.stream.seek(-4, 1)
                            self.looping = True
                            # Will just be naming the important things here.
                            smplsig, smplesize, _, _, _, _, _, _, _, self.LoopCount, _, _, _, self.LoopStartSample, self.LoopEndSample, _, _ = WavSmplHeaderStruct.unpack(
                                self.stream.read(WavSmplHeaderStruct.size)
                            )
                            if self.LoopCount != 1:
                                self.looping = False # Unsupported multiple looping points, so backtracks, and ignores looping data.
                                self.stream.seek(-WavSmplHeaderStruct.size, 1)
                                self.stream.seek(8 + smplesize, 1)
                        case b"data":
                            self.stream.seek(-4, 1)
                            self.dataSig, self.dataSize = WavDataHeaderStruct.unpack(
                                self.stream.read(WavDataHeaderStruct.size)
                            )
                    self.stream.seek(offset + size, 0)
        else:
            raise ValueError("Invalid HCA or WAV file.")
        self.stream.seek(0)
        self.hcastream.seek(0)
    
    def info(self) -> dict:
        """Returns info related to the input file. """
        if self.filetype == "hca":
            return self.hca
        elif self.filetype == "wav":
            wav = dict(RiffSignature=self.riffSignature.decode(), riffSize=self.riffSize, WaveSignature=self.wave.decode(), fmtSignature=self.fmt.decode(), fmtSize=self.fmtSize, fmtType=self.fmtType, fmtChannelCount=self.fmtChannelCount, fmtSamplingRate=self.fmtSamplingRate, fmtSamplesPerSec=self.fmtSamplesPerSec, fmtSamplingSize=self.fmtSamplingSize, fmtBitCount=self.fmtBitCount, dataSignature=self.dataSig.decode(), dataSize=self.dataSize)
            return wav
    
    def decode(self) -> bytes:
        """Decodes the HCA or WAV file to WAV bytes. """
        if self.filetype == "wav":
            raise ValueError("Input type for decoding must be an HCA file.")
        self.hcastream.seek(0)
        self.wavbytes = CriCodecsEx.HcaDecode(self.hcastream.read(), self.header_size, self.key, self.subkey)
        self.stream = BytesIO(self.wavbytes)
        self.hcastream.seek(0)
        return bytes(self.wavbytes)
    
    def encode(self, force_not_looping: bool = False, encrypt: bool = False, keyless: bool = False, quality_level: CriHcaQuality = CriHcaQuality.High) -> bytes:
        """Encodes the WAV file to HCA bytes."""
        if self.filetype == "hca":
            raise ValueError("Input type for encoding must be a WAV file.")
        if force_not_looping == False:
            force_not_looping = 0
        elif force_not_looping == True:
            force_not_looping = 1
        else:
            raise ValueError("Forcing the encoder to not loop is by either False or True.")
        if quality_level not in list(CriHcaQuality):
            raise ValueError("Chosen quality level is not valid or is not the appropiate enumeration value.")
        self.stream.seek(0)
        self.hcabytes = CriCodecsEx.HcaEncode(self.stream.read(), force_not_looping, quality_level.value)
        self.hcastream = BytesIO(self.hcabytes)
        self._Pyparse_header()
        if encrypt:
            if self.key == 0 and not keyless:
                self.key = 0xCF222F1FE0748978 # Default key.
            self._encrypt(self.key, keyless)
        return self.get_hca()
 
    def _encrypt(self, keycode: int, subkey: int = 0, keyless: bool = False) -> None:
        if(self.encrypted):
            raise ValueError("HCA is already encrypted.")
        self.encrypted = True
        enc = CriCodecsEx.HcaCrypt(self.get_hca(), 1, self.header_size, (1 if keyless else 56), keycode, subkey)
        self.hcastream = BytesIO(enc)

    def _decrypt(self, keycode: int, subkey: int = 0) -> None:
        if(not self.encrypted):
            raise ValueError("HCA is already decrypted.")
        self.encrypted = False
        dec = CriCodecsEx.HcaCrypt(self.get_hca(), 0, self.header_size, 0, keycode, subkey)
        self.hcastream = BytesIO(dec)

    def get_hca(self) -> bytes:
        """Get the HCA file bytes after encrypting or decrypting. """
        self.hcastream.seek(0)
        fl: bytes = self.hcastream.read()
        self.hcastream.seek(0)
        return fl
    
    def get_frames(self):
        """Generator function to yield Frame number, and Frame data. """
        self.hcastream.seek(self.header_size, 0)
        for i in range(self.hca['FrameCount']):
            yield (i, self.hcastream.read(self.hca['FrameSize']))
    
    def get_header(self) -> bytes:
        """Get the HCA Header. """
        self.hcastream.seek(0)
        header = self.hcastream.read(self.header_size)
        self.hcastream.seek(0)
        return header


class HCACodec(HCA):
    """Use this class for encoding and decoding HCA files, from and to WAV."""
    CHUNK_INTERVAL = 64
    BASE_FRAMERATE = 2997 # dt = CHUNK_INTERVAL / BASE_FRAMERATE
    AUDIO_CODEC = 4
    METADATA_COUNT = 1

    filename: str

    chnls: int
    sampling_rate: int
    total_samples: int
    avbps: int

    filesize: int

    def __init__(self, stream: str | bytes, filename: str = "default.hca", quality: CriHcaQuality = CriHcaQuality.High, key=0, subkey=0, **kwargs):
        """Initializes the HCA encoder/decoder

        Args:
            stream (str | bytes): Path to the HCA or WAV file, or a BinaryIO stream. WAV files will be automatically encoded with the given settings first.
            filename (str, optional): Filename, used by USMBuilder. Defaults to "default.hca".
            quality (CriHcaQuality, optional): Encoding quality. Defaults to CriHcaQuality.High.
            key (int, optional): HCA key. Defaults to 0.
            subkey (int, optional): HCA subkey. Defaults to 0.
        """
        self.filename = filename
        super().__init__(stream, key, subkey)
        if self.filetype == "wav":
            self.encode(
                force_not_looping=True,
                encrypt=key != 0,
                keyless=False,
                quality_level=quality
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
            self.sampling_rate = self.hca["SampleRate"]
            self.total_samples = self.hca["FrameCount"]
        # I don't know how this is derived so I am putting my best guess here. TODO
        self.avbps = int(self.filesize / self.chnls)

    def generate_SFA(self, index: int, builder):
        # USMBuilder usage
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
            index,
            0,
            0,
            0,
            current_interval,
            self.BASE_FRAMERATE,
            0,
            0,
        )
        SFA_chunk += self.get_header().ljust(self.hca["HeaderSize"] + padding, b"\x00")
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
                index,
                0,
                0,
                0,
                current_interval,
                self.BASE_FRAMERATE,
                0,
                0,
            )
            SFA_chunk += frame[1].ljust(self.hca["FrameSize"] + padding, b"\x00")
            current_interval = round(i * self.CHUNK_INTERVAL)            
            res.append(SFA_chunk)
        else:
            SFA_chunk = USMChunkHeader.pack(
                USMChunckHeaderType.SFA.value,
                0x38,
                0,
                0x18,
                0,
                index,
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
        payload = [dict(hca_header=(UTFTypeValues.bytes, self.get_header()))]
        p = UTFBuilder(payload, table_name="AUDIO_HEADER")
        p.strings = b"<NULL>\x00" + p.strings
        return p.bytes()

    def get_encoded(self) -> bytes:
        """Gets the encoded HCA audio data."""
        self.hcastream.seek(0)
        res = self.hcastream.read()
        self.hcastream.seek(0)
        return res
    
    def save(self, filepath: str | BinaryIO):
        """Saves the decoded WAV audio to filepath or a writable stream"""
        if type(filepath) == str:
            with open(filepath, "wb") as f:
                f.write(self.decode())
        else:
            filepath.write(self.decode())
