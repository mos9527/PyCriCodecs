from struct import iter_unpack
from typing import BinaryIO, List
from io import BytesIO
from .chunk import *
from .utf import UTF, UTFBuilder, UTFViewer
from .awb import AWB, AWBBuilder
from .hca import HCA
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

    __slots__ = ["filename", "_payload", "filename", "_table_names"]
    _payload: list
    filename: str
    _table_names: dict  # XXX: Hacky. Though with current routines this would be otherwise dropped, decoders need this.

    def __init__(self, filename) -> None:
        self._payload = UTF(filename).get_payload()
        self.filename = filename
        self._table_names = {}
        self.acbparse(self._payload)
        # TODO check on ACB version.

    def acbparse(self, payload: list) -> None:
        """Recursively parse the payload."""
        for dict in range(len(payload)):
            for k, v in payload[dict].items():
                if v[0] == UTFTypeValues.bytes:
                    if v[1].startswith(
                        UTFType.UTF.value
                    ):  # or v[1].startswith(UTFType.EUTF.value): # ACB's never gets encrypted?
                        par = UTF(v[1])
                        self._table_names[(dict, k)] = par.table_name
                        par = par.get_payload()
                        payload[dict][k] = par
                        self.acbparse(par)

    @property
    def payload(self) -> dict:
        """Retrives the only top-level UTF table dict within the ACB file."""
        return self._payload[0]

    @property
    def view(self) -> ACBTable:
        """Returns a view of the ACB file, with all known tables mapped to their respective classes."""
        return ACBTable(self.payload)


class ACBBuilder(UTFBuilder):
    acb: ACB

    def __init__(self, acb: ACB) -> None:
        self.acb = acb

    def acbunparse(self, payload: list, name="Header") -> None:
        """Recursively packs the potentially unpacked payload data back into binary format"""
        for dict in range(len(payload)):
            for k, v in payload[dict].items():
                if type(v) == list:
                    payload[dict][k] = (
                        UTFTypeValues.bytes,
                        self.acbunparse(v, self.acb._table_names[(dict, k)]),
                    )
        return UTFBuilder(payload, table_name=name).parse()

    def build(self) -> bytes:
        """Builds an ACB file from the current ACB object.

        The object may be modified in place before building, which will be reflected in the output binary.
        """
        acb = deepcopy(self.acb)
        binary = self.acbunparse(acb._payload)
        return binary
