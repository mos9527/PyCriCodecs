from struct import iter_unpack
from typing import BinaryIO
from io import BytesIO
from .chunk import *
from .utf import UTF, UTFBuilder, UTFViewer
from .awb import AWB, AWBBuilder
from .hca import HCA
import os

# Credit:
# - https://github.com/vgmstream/vgmstream/blob/master/src/meta/acb.c
# - Original work by https://github.com/Youjose/PyCriCodecs

class CueName(UTFViewer):
    CueIndex : int
    CueName : str
class ACB(UTF):
    """ An ACB is basically a giant @UTF table. Use this class to extract any ACB, and potentially modifiy it in place. """
    __slots__ = ["filename", "_payload", "filename", "_table_names"]
    _payload: list
    filename: str
    _table_names : dict # XXX: Hacky. Though with current routines this would be otherwise dropped, decoders need this.

    def __init__(self, filename) -> None:
        self._payload = UTF(filename).get_payload()
        self.filename = filename
        self._table_names = {}
        self.acbparse(self._payload)       
        # TODO check on ACB version.
    
    def acbparse(self, payload: list) -> None:
        """Recursively parse the payload. """
        for dict in range(len(payload)):
            for k, v in payload[dict].items():
                if v[0] == UTFTypeValues.bytes:
                    if v[1].startswith(UTFType.UTF.value): #or v[1].startswith(UTFType.EUTF.value): # ACB's never gets encrypted? 
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
    def awb(self) -> AWB:
        # There are two types of ACB's, one that has an AWB file inside it,
        # and one with an AWB pair.
        if self.payload['AwbFile'][1] == b'':
            # External AWB files
            if type(self.filename) == str:
                awbObj = AWB(os.path.join(os.path.dirname(self.filename), self.payload['Name'][1]+".awb"))
            else:
                awbObj = AWB(self.payload['Name'][1]+".awb")
        else:
            # Bytes array
            awbObj = AWB(self.payload['AwbFile'][1])
        return awbObj
    
    @awb.setter
    def awb(self, awb: bytes | None) -> None:
        ''' Sets the *packed* AWB payload from AWBBuilder.build()
        
        If awb is None, the decoder should look for external AWB file based on the ACB Name field.
        '''
        payload = self._payload[0]
        if type(awb) == bytes:
            payload['AwbFile'] = (UTFTypeValues.bytes, awb)
        elif awb is None:
            payload['AwbFile'] = (UTFTypeValues.bytes, b'')
        else:
            raise TypeError("AWB must be a string or bytes, got %s" % type(awb))

class ACBBuilder(UTFBuilder):
    acb : ACB
    def __init__(self, acb: ACB) -> None:
        self.acb = acb

    def acbunparse(self, payload: list, name='Header') -> None:
        """Recursively packs the potentially unpacked payload data back into binary format"""
        for dict in range(len(payload)):
            for k, v in payload[dict].items():
                if type(v) == list:
                    payload[dict][k] = (UTFTypeValues.bytes, self.acbunparse(v, self.acb._table_names[(dict,k)]))
        return UTFBuilder(payload, table_name=name).parse()
    
    def build(self) -> bytes:
        """ Builds an ACB file from the current ACB object.
        
        The object may be modified in place before building, which will be reflected in the output binary."""
        binary = self.acbunparse(self.acb._payload)
        return binary