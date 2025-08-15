# Credit:
# - github.com/vgmstream/vgmstream which is why this is possible at all
# - Original work by https://github.com/Youjose/PyCriCodecs
# See Research/ACBSchema.py for more details.

from typing import Generator, List, Tuple, BinaryIO
from PyCriCodecsEx.chunk import *
from PyCriCodecsEx.utf import UTF, UTFBuilder, UTFViewer
from PyCriCodecsEx.hca import HCACodec
from PyCriCodecsEx.adx import ADXCodec
from PyCriCodecsEx.awb import AWB, AWBBuilder
from dataclasses import dataclass
from copy import deepcopy

class CueNameTable(UTFViewer):
    CueIndex: int
    '''Index into CueTable'''
    CueName: str
    '''Name of the cue'''


class CueTable(UTFViewer):
    CueId: int
    '''Corresponds to the cue index found in CueNameTable'''
    Length: int
    '''Duration of the cue in milliseconds'''
    ReferenceIndex: int
    ReferenceType: int


class SequenceTable(UTFViewer):
    NumTracks : int
    TrackIndex: bytes
    Type: int


class SynthTable(UTFViewer):
    ReferenceItems: bytes


class TrackEventTable(UTFViewer):
    Command: bytes


class TrackTable(UTFViewer):
    EventIndex: int


class WaveformTable(UTFViewer):
    EncodeType: int
    MemoryAwbId: int
    NumChannels: int
    NumSamples: int
    SamplingRate: int
    Streaming: int


class ACBTable(UTFViewer):
    '''ACB Table View'''

    AcbGuid: bytes
    '''GUID of the ACB. This SHOULD be different for each ACB file.'''
    Name: str
    '''Name of the ACB. This is usually the name of the sound bank.'''
    Version: int    
    VersionString: str

    AwbFile: bytes
    CueNameTable: List[CueNameTable]
    '''A list of cue names with their corresponding indices into CueTable'''
    CueTable: List[CueTable]
    '''A list of cues with their corresponding references'''

    SequenceTable: List[SequenceTable]
    SynthTable: List[SynthTable]
    TrackEventTable: List[TrackEventTable]
    TrackTable: List[TrackTable]
    WaveformTable: List[WaveformTable]

    @staticmethod
    def _decode_tlv(data : bytes):
        pos = 0
        while pos < len(data):
            tag = data[pos : pos + 2]
            length = data[pos + 3]            
            value = data[pos + 4 : pos + 4 + length]
            pos += 3 + length
            yield (tag, value)

    def _waveform_of_track(self, index: int):
        tlv = self._decode_tlv(self.TrackEventTable[index])
        def noteOn(data: bytes):
            # Handle note on event
            tlv_type, tlv_index = AcbTrackCommandNoteOnStruct.unpack(data[:AcbTrackCommandNoteOnStruct.size])
            match tlv_type:
                case 0x02: # Synth
                    yield from self._waveform_of_synth(tlv_index)
                case 0x03: # Sequence
                    yield from self._waveform_of_sequence(tlv_index)
                # Ignore others silently                
        for code, data in tlv:
            match code:
                case 2000:
                    yield from noteOn(data)
                case 2003:
                    yield from noteOn(data)            

    def _waveform_of_sequence(self, index : int):
        seq = self.SequenceTable[index]
        for i in range(seq.NumTracks):
            track_index = int.from_bytes(seq.TrackIndex[i*2:i*2+2], 'big')
            yield self.WaveformTable[track_index]

    def _waveform_of_synth(self, index: int):        
        item_type, item_index = AcbSynthReferenceStruct.unpack(self.SynthTable[index].ReferenceItems)
        match item_type:
            case 0x00: # No audio
                return
            case 0x01: # Waveform
                yield self.WaveformTable[item_index]
            case 0x02: # Yet another synth...
                yield from self._waveform_of_synth(item_index)
            case 0x03: # Sequence
                yield from self._waveform_of_sequence(item_index)
            case _:
                raise NotImplementedError(f"Unknown synth reference type: {item_type} at index {index}")

    def waveform_of(self, index : int) -> List["WaveformTable"]:
        """Retrieves the waveform(s) associated with a cue.

        Cues may reference multiple waveforms, which could also be reused."""
        cue = next(filter(lambda c: c.CueId == index, self.CueTable), None)
        assert cue, "cue of index %d not found" % index
        match cue.ReferenceType:
            case 0x01:
                return [self.WaveformTable[index]]
            case 0x02:
                return list(self._waveform_of_synth(index))
            case 0x03:
                return list(self._waveform_of_sequence(index))
            case 0x08:
                raise NotImplementedError("BlockSequence type not implemented yet")
            case _:
                raise NotImplementedError(f"Unknown cue reference type: {cue.ReferenceType}")

@dataclass(frozen=True)
class CueItem:
    CueId: int
    CueName: str
    Length: float
    Waveforms: list[int] # List of waveform IDs

class ACB(UTF):
    """Use this class to read, and modify ACB files in memory."""
    def __init__(self, stream : str | BinaryIO) -> None:
        """Loads an ACB file from the given stream.

        Args:
            stream (str | BinaryIO): The path to the ACB file or a BinaryIO stream containing the ACB data.
        """
        super().__init__(stream, recursive=True)

    @property
    def payload(self) -> dict:
        """Retrives the only UTF table dict within the ACB file."""
        return self.dictarray[0]

    @property
    def view(self) -> ACBTable:
        """Returns a view of the ACB file, with all known tables mapped to their respective classes.
        
        * Use this to interact with the ACB payload instead of `payload` for helper functions, etc"""
        return ACBTable(self.payload)

    @property
    def name(self) -> str:
        """Returns the name of the ACB file."""
        return self.view.Name

    @property
    def awb(self) -> AWB:
        """Returns the AWB object associated with the ACB."""
        return AWB(self.view.AwbFile)

    def get_waveforms(self) -> List[HCACodec | ADXCodec | Tuple[AcbEncodeTypes, int, int, int,  bytes]]:
        """Returns a list of decoded waveforms.

        Item may be a codec (if known), or a tuple of (Codec ID, Channel Count, Sample Count, Sample Rate, Raw data).
        """
        CODEC_TABLE = {
            AcbEncodeTypes.ADX: ADXCodec,
            AcbEncodeTypes.HCA: HCACodec,
            AcbEncodeTypes.HCAMX: HCACodec,
        }
        awb = self.awb
        wavs = []        
        for wav in self.view.WaveformTable:
            encode = AcbEncodeTypes(wav.EncodeType)
            codec = (CODEC_TABLE.get(encode, None))
            if codec:
                wavs.append(codec(awb.get_file_at(wav.MemoryAwbId)))
            else:
                wavs.append((encode, wav.NumChannels, wav.NumSamples, wav.SamplingRate, awb.get_file_at(wav.MemoryAwbId)))
        return wavs

    def set_waveforms(self, value: List[HCACodec | ADXCodec | Tuple[AcbEncodeTypes, int, int, int, bytes]]):
        """Sets the waveform data.

        Input item may be a codec (if known), or a tuple of (Codec ID, Channel Count, Sample Count, Sample Rate, Raw data).

        NOTE: Cue duration is not set. You need to change that manually.
        """
        WAVEFORM = self.view.WaveformTable[0]._payload.copy()
        encoded = []
        tables = self.view.WaveformTable
        tables.clear()
        for i, codec in enumerate(value):
            if type(codec) == HCACodec:
                encoded.append(codec.get_encoded())
                tables.append(WaveformTable(WAVEFORM.copy()))
                entry = tables[-1]
                entry.EncodeType = AcbEncodeTypes.HCA.value
                entry.NumChannels = codec.chnls
                entry.NumSamples = codec.total_samples
                entry.SamplingRate = codec.sampling_rate
            elif type(codec) == ADXCodec:
                encoded.append(codec.get_encoded())
                tables.append(WaveformTable(WAVEFORM.copy()))
                entry = tables[-1]
                entry.EncodeType = AcbEncodeTypes.ADX.value
                entry.NumChannels = codec.chnls
                entry.NumSamples = codec.total_samples
                entry.SamplingRate = codec.sampling_rate                
            elif isinstance(codec, tuple):
                e_type, e_channels, e_samples, e_rate, e_data = codec
                encoded.append(e_data)
                tables.append(WaveformTable(WAVEFORM.copy()))
                entry = tables[-1]
                entry.EncodeType = e_type.value
                entry.NumChannels = e_channels
                entry.NumSamples = e_samples
                entry.SamplingRate = e_rate
            else:
                raise TypeError(f"Unsupported codec type: {type(codec)}")
            tables[-1].MemoryAwbId = i
        awb = self.awb
        self.view.AwbFile = AWBBuilder(encoded, awb.subkey, awb.version, align=awb.align).build()
        pass

    @property
    def cues(self) -> Generator[CueItem, None, None]:
        """Returns a generator of **read-only** Cues.

        Cues reference waveform bytes by their AWB IDs, which can be accessed via `waveforms`.
        To modify cues, use the `view` property instead.
        """
        for name, cue in zip(self.view.CueNameTable, self.view.CueTable):
            waveforms = self.view.waveform_of(cue.CueId)
            yield CueItem(cue.CueId, name.CueName, cue.Length / 1000.0, [waveform.MemoryAwbId for waveform in waveforms])

class ACBBuilder:
    """Use this class to build ACB files from an existing ACB object."""
    acb: ACB

    def __init__(self, acb: ACB) -> None:
        """Initializes the ACBBuilder with an existing ACB object.
        
        Args:
            acb (ACB): The ACB object to build from.

        Building ACB from scratch isn't planned for now since:
                
            * We don't know how SeqCommandTable TLVs work. This is the biggest issue.
            * Many fields are unknown or not well understood
            - Games may expect AcfReferenceTable, Asiac stuff etc to be present for their own assets in conjunction
                with their own ACF table. Missing these is not a fun debugging experience.
            * ACB tables differ a LOT from game to game (e.g. Lipsync info), contary to USM formats.

        Maybe one day I'll get around to this. But otherwise starting from nothing is a WONTFIX for now.
        """
        self.acb = acb

    def build(self) -> bytes:
        """Builds an ACB binary blob from the current ACB object.

        The object may be modified in place before building, which will be reflected in the output binary.
        """
        # Check whether all AWB indices are valid
        assert all(
            waveform.MemoryAwbId < self.acb.awb.numfiles for waveform in self.acb.view.WaveformTable
        ), "one or more AWB indices are out of range"
        binary = UTFBuilder(self.acb.dictarray, encoding=self.acb.encoding, table_name=self.acb.table_name)
        return binary.bytes()
