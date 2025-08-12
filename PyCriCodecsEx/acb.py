from struct import iter_unpack
from typing import BinaryIO, List
from io import BytesIO
from PyCriCodecsEx.chunk import *
from PyCriCodecsEx.utf import UTF, UTFBuilder, UTFViewer
from PyCriCodecsEx.awb import AWB, AWBBuilder
from PyCriCodecsEx.hca import HCA
from copy import deepcopy
import os

# Credit:
# - github.com/vgmstream/vgmstream which is why this is possible at all
# - Original work by https://github.com/Youjose/PyCriCodecs
# See Research/ACBSchema.py for more details.

class CueNameTable(UTFViewer):
    CueIndex: int
    CueName: str


class CueTable(UTFViewer):
    CueId: int
    ReferenceIndex: int
    ReferenceType: int


class SequenceTable(UTFViewer):
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
    AcbGuid: bytes
    Name: str
    Version: int
    VersionString: str

    AwbFile: bytes
    CueNameTable: List[CueNameTable]
    CueTable: List[CueTable]
    SequenceTable: List[SequenceTable]
    SynthTable: List[SynthTable]
    TrackEventTable: List[TrackEventTable]
    TrackTable: List[TrackTable]
    WaveformTable: List[WaveformTable]


class ACB(UTF):
    """An ACB is basically a giant @UTF table. Use this class to extract any ACB, and potentially modifiy it in place."""
    def __init__(self, filename) -> None:
        super().__init__(filename,recursive=True)

    @property
    def payload(self) -> dict:
        """Retrives the only top-level UTF table dict within the ACB file."""
        return self.dictarray[0]

    @property
    def view(self) -> ACBTable:
        """Returns a view of the ACB file, with all known tables mapped to their respective classes."""
        return ACBTable(self.payload)

    # TODO: Extraction routines
    # See Research/ACBSchema.py. vgmstream presented 4 possible permutations of subsong retrieval.

class ACBBuilder:
    acb: ACB

    def __init__(self, acb: ACB) -> None:
        self.acb = acb

    def build(self) -> bytes:
        """Builds an ACB binary blob from the current ACB object.

        The object may be modified in place before building, which will be reflected in the output binary.
        """
        payload = deepcopy(self.acb.dictarray)
        binary = UTFBuilder(payload, encoding=self.acb.encoding, table_name=self.acb.table_name)
        return binary.bytes()
