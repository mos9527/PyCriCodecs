from typing import BinaryIO
from io import BytesIO
from PyCriCodecsEx.chunk import *
import CriCodecsEx
class ADX:
    """ADX class for decoding and encoding ADX files, pass the either `adx file` or `wav file` in bytes to either `decode` or `encode` respectively.

    **NOTE:** Direct usage of this class is not recommended, use the `ADXCodec` wrapper instead.
    """

    # Decodes ADX to WAV.
    @staticmethod
    def decode(data: bytes) -> bytes:
        """ Decodes ADX to WAV. """
        return CriCodecsEx.AdxDecode(bytes(data))
            
    # Encodes WAV to ADX.
    @staticmethod
    def encode(data: bytes, BitDepth = 0x4, Blocksize = 0x12, Encoding = 3, AdxVersion = 0x4, Highpass_Frequency = 0x1F4, Filter = 0, force_not_looping = False) -> bytes:
        """ Encodes WAV to ADX. """
        return CriCodecsEx.AdxEncode(bytes(data), BitDepth, Blocksize, Encoding, Highpass_Frequency, Filter, AdxVersion, force_not_looping)
    
class ADXCodec(ADX):
    """Use this class for encoding and decoding ADX files, from and to WAV."""

    CHUNK_INTERVAL = 99.9
    BASE_FRAMERATE = 2997
    # TODO: Move these to an enum
    AUDIO_CODEC = 2
    METADATA_COUNT = 0

    filename : str
    filesize : int

    adx : bytes
    header : bytes
    sfaStream: BinaryIO    

    AdxDataOffset: int
    AdxEncoding: int
    AdxBlocksize: int
    AdxSampleBitdepth: int
    AdxChannelCount: int
    AdxSamplingRate: int
    AdxSampleCount: int
    AdxHighpassFrequency: int
    AdxVersion: int
    AdxFlags: int

    chnls: int
    sampling_rate: int
    total_samples: int
    avbps: int

    def __init__(self, stream: str | bytes, filename: str = "default.adx", bitdepth: int = 4, **kwargs):
        """Initializes the ADX encoder/decoder

        Args:
            stream (str | bytes): Path to the ADX or WAV file, or a BinaryIO stream. WAV files will be automatically encoded with the given settings first.
            filename (str, optional): Filename, used by USMBuilder. Defaults to "default.adx".
            bitdepth (int, optional): Audio bit depth within [2,15]. Defaults to 4.
        """
        if type(stream) == str:
            self.adx = open(stream, "rb").read()
        else:
            self.adx = stream
        self.filename = filename
        self.filesize = len(self.adx)
        magic = self.adx[:4]
        if magic == b"RIFF":
            self.adx = self.encode(self.adx, bitdepth, force_not_looping=True)        
        self.sfaStream = BytesIO(self.adx)
        header = AdxHeaderStruct.unpack(self.sfaStream.read(AdxHeaderStruct.size))
        FourCC, self.AdxDataOffset, self.AdxEncoding, self.AdxBlocksize, self.AdxSampleBitdepth, self.AdxChannelCount, self.AdxSamplingRate, self.AdxSampleCount, self.AdxHighpassFrequency, self.AdxVersion, self.AdxFlags = header
        assert FourCC == 0x8000, "either ADX or WAV is supported"
        assert self.AdxVersion in {3,4}, "unsupported ADX version"
        if self.AdxVersion == 4:
            self.sfaStream.seek(4 + 4  * self.AdxChannelCount, 1)  # Padding + Hist values, they always seem to be 0.
        self.sfaStream.seek(0)
        self.chnls = self.AdxChannelCount
        self.sampling_rate = self.AdxSamplingRate
        self.total_samples = self.AdxSampleCount
        self.avbps = int(self.filesize * 8 * self.chnls) - self.filesize
    
    def generate_SFA(self, index: int, builder):
        # USMBuilder usage
        current_interval = 0
        stream_size = len(self.adx) - self.AdxBlocksize
        chunk_size = int(self.AdxSamplingRate // (self.BASE_FRAMERATE / 100) // 32) * (self.AdxBlocksize * self.AdxChannelCount)
        self.sfaStream.seek(0)
        res = []
        while self.sfaStream.tell() < stream_size:
            if self.sfaStream.tell() > 0:
                if self.sfaStream.tell() + chunk_size < stream_size:
                    datalen = chunk_size
                else:
                    datalen = (stream_size - (self.AdxDataOffset + 4) - chunk_size) % chunk_size
            else:
                datalen = self.AdxDataOffset + 4
            if not datalen:
                break
            padding = (0x20 - (datalen % 0x20) if datalen % 0x20 != 0 else 0)
            SFA_chunk = USMChunkHeader.pack(
                    USMChunckHeaderType.SFA.value,
                    datalen + 0x18 + padding,
                    0,
                    0x18,
                    padding,
                    index,
                    0,
                    0,
                    0,
                    round(current_interval),
                    self.BASE_FRAMERATE,
                    0,
                    0
                    )
            chunk_data = self.sfaStream.read(datalen)
            if builder.encrypt_audio:
                SFA_chunk = builder.AudioMask(chunk_data)
            SFA_chunk += chunk_data.ljust(datalen + padding, b"\x00")            
            current_interval += self.CHUNK_INTERVAL
            res.append(SFA_chunk)
        # ---
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
                    0
                    )
        SFA_chunk += b"#CONTENTS END   ===============\x00"
        res[-1] += SFA_chunk
        return res

    def get_metadata(self):
        return None

    def get_encoded(self) -> bytes:
        """Gets the encoded ADX audio data."""
        return self.adx

    def save(self, filepath: str | BinaryIO):
        """Saves the decoded WAV audio to filepath or a writable stream"""
        if type(filepath) == str:
            with open(filepath, "wb") as f:
                f.write(self.decode(self.adx))
        else:
            filepath.write(self.decode(self.adx))

