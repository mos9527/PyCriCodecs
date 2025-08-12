from typing import BinaryIO
from io import BytesIO, FileIO
import os
from .chunk import *
from .utf import UTF, UTFBuilder
import CriCodecs
from dataclasses import dataclass

@dataclass
class CPKFile():
    stream: BinaryIO
    path: str
    offset: int   
    size : int 
    compressed : bool = False

    def get_bytes(self) -> bytes:
        self.stream.seek(self.offset)
        data = self.stream.read(self.size)
        if self.compressed:
            data = CriCodecs.CriLaylaDecompress(data)
        return data

    def save(self, path : str):
        with open(path, "wb") as f:
            f.write(self.get_bytes())
class TOC():
    magic: bytes
    encflag: int
    packet_size: int
    unk0C: int
    stream: BinaryIO
    table: dict
    def __init__(self, stream: bytes) -> None:
        self.stream = BytesIO(stream)
        self.magic, self.encflag, self.packet_size, self.unk0C = CPKChunkHeader.unpack(
            self.stream.read(CPKChunkHeader.size)
        )
        if self.magic not in [header.value for header in CPKChunkHeaderType]:
            raise ValueError(f"{self.magic} header not supported.")
        self.table = UTF(self.stream.read()).table

class CPK:
    magic: bytes
    encflag: int
    packet_size: int
    unk0C: int
    stream: BinaryIO
    tables: dict
    filename: str
    def __init__(self, filename) -> None:
        if type(filename) == str:
            self.filename = filename
            self.stream = FileIO(filename)
        else:
            self.stream = BytesIO(filename)
            self.filename = ''
        self.magic, self.encflag, self.packet_size, self.unk0C = CPKChunkHeader.unpack(
            self.stream.read(CPKChunkHeader.size)
        )
        if self.magic != CPKChunkHeaderType.CPK.value:
            raise ValueError("Invalid CPK file.")
        self.tables = dict(CPK = UTF(self.stream.read(0x800-CPKChunkHeader.size)).table)
        self._load_tocs()
    
    def _load_tocs(self) -> None:
        for key, value in self.tables["CPK"].items():
            if key == "TocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["TOC"] = TOC(self.stream.read(self.tables['CPK']["TocSize"][0])).table
            elif key == "ItocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["ITOC"] = TOC(self.stream.read(self.tables['CPK']["ItocSize"][0])).table
                    if "DataL" in self.tables["ITOC"]:
                        self.tables["ITOC"]['DataL'][0] = UTF(self.tables["ITOC"]['DataL'][0]).table
                    if "DataH" in self.tables["ITOC"]:
                        self.tables["ITOC"]['DataH'][0] = UTF(self.tables["ITOC"]['DataH'][0]).table
            elif key == "HtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["HTOC"] = TOC(self.stream.read(self.tables['CPK']["HtocSize"][0])).table
            elif key == "GtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["GTOC"] = TOC(self.stream.read(self.tables['CPK']["GtocSize"][0])).table
                    if "AttrData" in self.tables["GTOC"]:
                        self.tables["GTOC"]['AttrData'][0] = UTF(self.tables["GTOC"]['AttrData'][0]).table
                    if "Fdata" in self.tables["GTOC"]:
                        self.tables["GTOC"]['Fdata'][0] = UTF(self.tables["GTOC"]['Fdata'][0]).table
                    if "Gdata" in self.tables["GTOC"]:
                        self.tables["GTOC"]['Gdata'][0] = UTF(self.tables["GTOC"]['Gdata'][0]).table
            elif key == "HgtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["HGTOC"] = TOC(self.stream.read(self.tables['CPK']["HgtocSize"][0])).table
            elif key == "EtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["ETOC"] = TOC(self.stream.read(self.tables['CPK']["EtocSize"][0])).table
    
    @property
    def files(self):
        """Retrieves a list of all files in the CPK archive."""
        if "TOC" in self.tables:
            toctable = self.tables['TOC']
            rel_off = 0x800
            for i in range(len(toctable['FileName'])):
                dirname = toctable["DirName"][i%len(toctable["DirName"])] 
                filename = toctable['FileName'][i]
                if len(filename) >= 255:
                    filename = filename[:250] + "_" + str(i) # 250 because i might be 4 digits long.
                if toctable['ExtractSize'][i] > toctable['FileSize'][i]:
                    self.stream.seek(rel_off+toctable["FileOffset"][i], 0)
                    yield CPKFile(self.stream, os.path.join(dirname,filename), self.stream.tell(), toctable['FileSize'][i], compressed=True)
                else:
                    self.stream.seek(rel_off+toctable["FileOffset"][i], 0)
                    yield CPKFile(self.stream, os.path.join(dirname,filename), self.stream.tell(), toctable['FileSize'][i])                    
        elif "ITOC" in self.tables:
            toctableL = self.tables["ITOC"]['DataL'][0]
            toctableH = self.tables["ITOC"]['DataH'][0]
            align = self.tables['CPK']["Align"][0]
            offset = self.tables["CPK"]["ContentOffset"][0]
            files = self.tables["CPK"]["Files"][0]
            self.stream.seek(offset, 0)
            for i in sorted(toctableH['ID']+toctableL['ID']):
                if i in toctableH['ID']:
                    idx = toctableH['ID'].index(i)
                    if toctableH['ExtractSize'][idx] > toctableH['FileSize'][idx]:
                        yield CPKFile(self.stream, str(i), self.stream.tell(), toctableH['FileSize'][idx], compressed=True)
                    else:
                        yield CPKFile(self.stream, str(i), self.stream.tell(), toctableH['FileSize'][idx])
                    if toctableH['FileSize'][idx] % align != 0:
                        seek_size = (align - toctableH['FileSize'][idx] % align)
                        self.stream.seek(seek_size, 1)
                elif i in toctableL['ID']:
                    idx = toctableL['ID'].index(i)
                    if toctableL['ExtractSize'][idx] > toctableL['FileSize'][idx]:
                        yield CPKFile(self.stream, str(i), self.stream.tell(), toctableL['FileSize'][idx], compressed=True)
                    else:
                        yield CPKFile(self.stream, str(i), self.stream.tell(), toctableL['FileSize'][idx])
                    if toctableL['FileSize'][idx] % align != 0:
                        seek_size = (align - toctableL['FileSize'][idx] % align)
                        self.stream.seek(seek_size, 1)
class CPKBuilder:
    """ Use this class to build semi-custom CPK archives. """
    CpkMode: int 
    # CPK mode dictates (at least from what I saw) the use of filenames in TOC or the use of
    # ITOC without any filenames (Use of ID's only, will be sorted).
    # CPK mode of 0 = Use of ITOC only, CPK mode = 1, use of TOC, ITOC and optionally ETOC?
    Tver: str
    # Seems to be CPKMaker/CPKDLL version, I will put in one of the few ones I found as default.
    # I am not sure if this affects the modding these files.
    # However, you can change it.
    dirname: str
    itoc_size: int
    encrypt: bool
    encoding: str
    files: list
    fileslen: int
    ITOCdata: bytearray
    TOCdata: bytearray
    CPKdata: bytearray
    ContentSize: int
    EnabledDataSize: int
    EnabledPackedSize: int
    outfile: str
    compress: bool
    init_toc_len: int # This is a bit of a redundancy, but some CPK's need it.

    def __init__(self, dirname: str, outfile: str, CpkMode: int = 1, Tver: str = False, encrypt: bool = False, encoding: str = "utf-8", compress: bool = False) -> None:
        self.CpkMode = CpkMode
        self.compress = False
        if not Tver:
            # Some default ones I found with the matching CpkMode, hope they are good enough for all cases.
            if self.CpkMode == 0:
                self.Tver = 'CPKMC2.18.04, DLL2.78.04'
            elif self.CpkMode == 1:
                self.Tver = 'CPKMC2.45.00, DLL3.15.00'
            elif self.CpkMode == 2:
                self.Tver = 'CPKMC2.49.32, DLL3.24.00'
            elif self.CpkMode == 3:
                self.Tver = 'CPKFBSTD1.49.35, DLL3.24.00'
            else:
                raise ValueError("Unknown CpkMode.")
        else:
            self.Tver = Tver
        if dirname == "":
            raise ValueError("Invalid directory name/path.")
        elif self.CpkMode not in [0, 1, 2, 3]:
            raise ValueError("Unknown CpkMode.")
        elif self.CpkMode == 0 and self.compress:
            # CpkMode of 0 is a bit hard to do with compression, as I don't know where the actual data would be
            # categorized (either H or L) after compression. Needs proper testing for me to implement.
            raise NotImplementedError("CpkMode of 0 with compression is not supported yet.")
        self.dirname = dirname
        self.encrypt = encrypt
        self.encoding = encoding
        self.EnabledDataSize = 0
        self.EnabledPackedSize = 0
        self.ContentSize = 0
        self.outfile = outfile
        self.compress = compress
        self.generate_payload()
    
    def generate_payload(self):
        if self.encrypt:
            encflag = 0
        else:
            encflag = 0xFF
        if self.CpkMode == 3:
            self.TOCdata = self.generate_TOC()
            self.TOCdata = bytearray(CPKChunkHeader.pack(b'TOC ', encflag, len(self.TOCdata), 0)) + self.TOCdata
            self.TOCdata = self.TOCdata.ljust(len(self.TOCdata) + (0x800 - len(self.TOCdata) % 0x800), b'\x00')
            assert self.init_toc_len == len(self.TOCdata)
            self.GTOCdata = self.generate_GTOC()
            self.GTOCdata = bytearray(CPKChunkHeader.pack(b'GTOC', encflag, len(self.GTOCdata), 0)) + self.GTOCdata
            self.GTOCdata = self.GTOCdata.ljust(len(self.GTOCdata) + (0x800 - len(self.GTOCdata) % 0x800), b'\x00')
            self.CPKdata = self.generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.TOCdata + self.GTOCdata
            self.writetofile(data)
        elif self.CpkMode == 2:
            self.TOCdata = self.generate_TOC()
            self.TOCdata = bytearray(CPKChunkHeader.pack(b'TOC ', encflag, len(self.TOCdata), 0)) + self.TOCdata
            self.TOCdata = self.TOCdata.ljust(len(self.TOCdata) + (0x800 - len(self.TOCdata) % 0x800), b'\x00')
            assert self.init_toc_len == len(self.TOCdata)
            self.ITOCdata = self.generate_ITOC()
            self.ITOCdata = bytearray(CPKChunkHeader.pack(b'ITOC', encflag, len(self.ITOCdata), 0)) + self.ITOCdata
            self.ITOCdata = self.ITOCdata.ljust(len(self.ITOCdata) + (0x800 - len(self.ITOCdata) % 0x800), b'\x00')
            self.CPKdata = self.generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.TOCdata + self.ITOCdata
            self.writetofile(data)
        elif self.CpkMode == 1:
            self.TOCdata = self.generate_TOC()
            self.TOCdata = bytearray(CPKChunkHeader.pack(b'TOC ', encflag, len(self.TOCdata), 0)) + self.TOCdata
            self.TOCdata = self.TOCdata.ljust(len(self.TOCdata) + (0x800 - len(self.TOCdata) % 0x800), b'\x00')
            assert self.init_toc_len == len(self.TOCdata)
            self.CPKdata = self.generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.TOCdata
            self.writetofile(data)
        elif self.CpkMode == 0:
            self.ITOCdata = self.generate_ITOC()
            self.ITOCdata = bytearray(CPKChunkHeader.pack(b'ITOC', encflag, len(self.ITOCdata), 0)) + self.ITOCdata
            self.ITOCdata = self.ITOCdata.ljust(len(self.ITOCdata) + (0x800 - len(self.ITOCdata) % 0x800), b'\x00')
            self.CPKdata = self.generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.ITOCdata
            self.writetofile(data)
        
    def writetofile(self, data) -> None:
        out = open(self.outfile, "wb")
        out.write(data)
        if self.compress:
            for d in self.files:
                if len(d) % 0x800 != 0:
                    d = d.ljust(len(d) + (0x800 - len(d) % 0x800), b"\x00")
                out.write(d)
            out.close()
        else:
            for i in self.files:
                d = open(i, "rb").read()
                if len(d) % 0x800 != 0:
                    d = d.ljust(len(d) + (0x800 - len(d) % 0x800), b"\x00")
                out.write(d)
            out.close()
    
    def generate_GTOC(self) -> bytearray:
        # I have no idea why are those numbers here.
        Gdata = [
            {
                "Gname": (UTFTypeValues.string, ""),
                "Child": (UTFTypeValues.int, -1),
                "Next": (UTFTypeValues.int, 0)
            },
            {
                "Gname": (UTFTypeValues.string, "(none)"),
                "Child": (UTFTypeValues.int, 0),
                "Next": (UTFTypeValues.int, 0)
            }
        ]
        Fdata = [
            {
             "Next": (UTFTypeValues.int, -1),
             "Child": (UTFTypeValues.int, -1),
             "SortFlink": (UTFTypeValues.int, 2),
             "Aindex": (UTFTypeValues.ushort, 0)
            },
            {
             "Next": (UTFTypeValues.int, 2),
             "Child": (UTFTypeValues.int, 0),
             "SortFlink": (UTFTypeValues.int, 1),
             "Aindex": (UTFTypeValues.ushort, 0)
            },
            {
             "Next": (UTFTypeValues.int, 0),
             "Child": (UTFTypeValues.int, 1),
             "SortFlink": (UTFTypeValues.int, 2),
             "Aindex": (UTFTypeValues.ushort, 0)
            }
        ]
        Attrdata = [
            {
                "Aname": (UTFTypeValues.string, ""),
                "Align": (UTFTypeValues.ushort, 0x800),
                "Files": (UTFTypeValues.uint, 0),
                "FileSize": (UTFTypeValues.uint, 0)
            }
        ]
        payload = [
            {
                "Glink": (UTFTypeValues.uint, 2),
                "Flink": (UTFTypeValues.uint, 3),
                "Attr" : (UTFTypeValues.uint, 1),
                "Gdata": (UTFTypeValues.bytes, UTFBuilder(Gdata, encrypt=False, encoding=self.encoding, table_name="CpkGtocGlink").bytes()),
                "Fdata": (UTFTypeValues.bytes, UTFBuilder(Fdata, encrypt=False, encoding=self.encoding, table_name="CpkGtocFlink").bytes()),
                "Attrdata": (UTFTypeValues.bytes, UTFBuilder(Attrdata, encrypt=False, encoding=self.encoding, table_name="CpkGtocAttr").bytes()),
            }
        ]
        return UTFBuilder(payload, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkGtocInfo").bytes()

    def generate_ETOC(self) -> bytearray:
        """ This is now unused, a CPK won't be unfuctional without it. I will leave it here for reference. """
        payload = [
            {
                "UpdateDateTime": (UTFTypeValues.ullong, 0),
                "LocalDir": (UTFTypeValues.string, self.dirname)
            }
        ]
        return UTFBuilder(payload, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkEtocInfo").bytes()

    def generate_TOC(self) -> bytearray:
        payload = []
        self.files = []
        temp = []
        self.get_files(sorted(os.listdir(self.dirname), key=lambda x: "".join([s if s != '_' else "~" for s in x]).lower()), self.dirname)
        count = 0
        lent = 0
        switch = False
        sf = set()
        sd = set()
        for i in self.files:
            # Dirname management.
            dirname = os.path.dirname(i.split(self.dirname)[1])
            if dirname.startswith(os.sep) or dirname.startswith("\\"):
                dirname = dirname[1:]
            if "\\" in dirname or os.sep in dirname:
                dirname = dirname.replace("\\", "/")
                dirname = dirname.replace(os.sep, "/")
            if dirname not in sd:
                switch = True
                lent += len(dirname) + 1
                sd.update({dirname})
            
            # Filename management.
            flname = os.path.basename(i)
            if flname not in sf:
                lent += len(flname) + 1
                sf.update({flname})
            count += 1
        
        # This estimates how large the TOC table size is.
        if switch and len(sd) != 1:
            lent = (lent + (4 + 4 + 4 + 4 + 8 + 4) * count + 0x47 + 0x51) # 0x47 is header len when there are mutiple dirs.
        else:
            lent = (lent + (4 + 4 + 4 + 8 + 4) * count + 0x4B + 0x51) # 0x4B is header len when there is only one dir.
        if lent % 8 != 0:
            lent = 8 + (lent - 8) + (8 - (lent - 8) % 8)
        lent += 0x10
        lent = lent + (0x800 - lent % 0x800)
        # init_toc_len will also be the first file offset.
        # Used to assert that the estimated TOC length is equal to the actual length, just in case the estimating went wrong. 
        self.init_toc_len = lent

        self.fileslen = count
        count = 0
        for file in self.files:
            sz = os.stat(file).st_size
            fz = sz
            if sz > 0xFFFFFFFF:
                raise OverflowError("4GBs is the max size of a single file that can be bundled in a CPK archive of mode 1.")
            if self.compress:
                self.EnabledPackedSize += sz
                comp_data = CriCodecs.CriLaylaCompress(open(file, "rb").read())
                temp.append(comp_data)
                fz = len(comp_data)
                self.EnabledDataSize += fz
                if fz % 0x800 != 0:
                    self.ContentSize += fz + (0x800 - fz % 0x800)
                else:
                    self.ContentSize += fz
            else:
                self.EnabledDataSize += sz
                self.EnabledPackedSize += sz
                if sz % 0x800 != 0:
                    self.ContentSize += sz + (0x800 - sz % 0x800)
                else:
                    self.ContentSize += sz
            dirname = os.path.dirname(file.split(self.dirname)[1])
            if dirname.startswith(os.sep) or dirname.startswith("\\"):
                dirname = dirname[1:]
            if "\\" in dirname or os.sep in dirname:
                dirname = dirname.replace("\\", "/")
                dirname = dirname.replace(os.sep, "/")
            payload.append(
                {
                    "DirName": (UTFTypeValues.string, dirname),
                    "FileName": (UTFTypeValues.string, os.path.basename(file)),
                    "FileSize": (UTFTypeValues.uint, sz),
                    "ExtractSize": (UTFTypeValues.uint, (sz if not self.compress else fz)),
                    "FileOffset": (UTFTypeValues.ullong, lent),
                    "ID": (UTFTypeValues.uint, count),
                    "UserString": (UTFTypeValues.string, "<NULL>")
                }
            )
            count += 1
            sz = fz
            if sz % 0x800 != 0:
                lent += sz + (0x800 - sz % 0x800)
            else:
                lent += sz
        if self.compress:
            self.files = temp
        return UTFBuilder(payload, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkTocInfo").bytes()

    def get_files(self, lyst, root):
        for i in lyst:
            name = os.path.join(root, i)
            if os.path.isdir(name):
                self.get_files(sorted(os.listdir(name), key=lambda x: "".join([s if s != '_' else "~" for s in x]).lower()), name)
            else:
                self.files.append(name)

    def generate_CPK(self) -> bytearray:
        if self.CpkMode == 3:
            ContentOffset = (0x800+len(self.TOCdata)+len(self.GTOCdata))
            CpkHeader = [
                {
                    "UpdateDateTime": (UTFTypeValues.ullong, 0),
                    "ContentOffset": (UTFTypeValues.ullong, ContentOffset),
                    "ContentSize": (UTFTypeValues.ullong, self.ContentSize),
                    "TocOffset": (UTFTypeValues.ullong, 0x800),
                    "TocSize": (UTFTypeValues.ullong, len(self.TOCdata)),
                    "EtocOffset": (UTFTypeValues.ullong, None),
                    "EtocSize": (UTFTypeValues.ullong, None),
                    "GtocOffset": (UTFTypeValues.ullong, 0x800+len(self.TOCdata)),
                    "GtocSize": (UTFTypeValues.ullong, len(self.GTOCdata)),                    
                    "EnabledPackedSize": (UTFTypeValues.ullong, self.EnabledPackedSize),
                    "EnabledDataSize": (UTFTypeValues.ullong, self.EnabledDataSize),
                    "Files": (UTFTypeValues.uint, self.fileslen),
                    "Groups": (UTFTypeValues.uint, 0),
                    "Attrs": (UTFTypeValues.uint, 0),
                    "Version": (UTFTypeValues.ushort, 7),
                    "Revision": (UTFTypeValues.ushort, 14),
                    "Align": (UTFTypeValues.ushort, 0x800),
                    "Sorted": (UTFTypeValues.ushort, 1),
                    "EnableFileName": (UTFTypeValues.ushort, 1),
                    "CpkMode": (UTFTypeValues.uint, self.CpkMode),
                    "Tvers": (UTFTypeValues.string, self.Tver),
                    "Codec": (UTFTypeValues.uint, 0),
                    "DpkItoc": (UTFTypeValues.uint, 0),
                    "EnableTocCrc": (UTFTypeValues.ushort, None),
                    "EnableFileCrc": (UTFTypeValues.ushort, None),
                    "CrcMode": (UTFTypeValues.uint, None),
                    "CrcTable": (UTFTypeValues.bytes, b''),
                    "FileSize": (UTFTypeValues.ullong, None),
                    "TocCrc": (UTFTypeValues.uint, None),
                    "HtocOffset": (UTFTypeValues.ullong, None),
                    "HtocSize": (UTFTypeValues.ullong, None),
                    "ItocOffset": (UTFTypeValues.ullong, None),
                    "ItocSize": (UTFTypeValues.ullong, None),
                    "ItocCrc": (UTFTypeValues.uint, None),
                    "GtocCrc": (UTFTypeValues.uint, None),
                    "HgtocOffset": (UTFTypeValues.ullong, None),
                    "HgtocSize": (UTFTypeValues.ullong, None),
                    "TotalDataSize": (UTFTypeValues.ullong, None),
                    "Tocs": (UTFTypeValues.uint, None),
                    "TotalFiles": (UTFTypeValues.uint, None),
                    "Directories": (UTFTypeValues.uint, None),
                    "Updates": (UTFTypeValues.uint, None),
                    "EID": (UTFTypeValues.ushort, None),
                    "Comment": (UTFTypeValues.string, '<NULL>'),
                }
            ]
        elif self.CpkMode == 2:
            ContentOffset = 0x800+len(self.TOCdata)+len(self.ITOCdata)
            CpkHeader = [
                {
                    "UpdateDateTime": (UTFTypeValues.ullong, 0),
                    "ContentOffset": (UTFTypeValues.ullong, ContentOffset),
                    "ContentSize": (UTFTypeValues.ullong, self.ContentSize),
                    "TocOffset": (UTFTypeValues.ullong, 0x800),
                    "TocSize": (UTFTypeValues.ullong, len(self.TOCdata)),
                    "EtocOffset": (UTFTypeValues.ullong, None),
                    "EtocSize": (UTFTypeValues.ullong, None),
                    "ItocOffset": (UTFTypeValues.ullong, 0x800+len(self.TOCdata)),
                    "ItocSize": (UTFTypeValues.ullong, len(self.ITOCdata)),
                    "EnabledPackedSize": (UTFTypeValues.ullong, self.EnabledPackedSize),
                    "EnabledDataSize": (UTFTypeValues.ullong, self.EnabledDataSize),
                    "Files": (UTFTypeValues.uint, self.fileslen),
                    "Groups": (UTFTypeValues.uint, 0),
                    "Attrs": (UTFTypeValues.uint, 0),
                    "Version": (UTFTypeValues.ushort, 7),
                    "Revision": (UTFTypeValues.ushort, 14),
                    "Align": (UTFTypeValues.ushort, 0x800),
                    "Sorted": (UTFTypeValues.ushort, 1),
                    "EnableFileName": (UTFTypeValues.ushort, 1),
                    "EID": (UTFTypeValues.ushort, None),
                    "CpkMode": (UTFTypeValues.uint, self.CpkMode),
                    "Tvers": (UTFTypeValues.string, self.Tver),
                    "Codec": (UTFTypeValues.uint, 0),
                    "DpkItoc": (UTFTypeValues.uint, 0),
                    "EnableTocCrc": (UTFTypeValues.ushort, None),
                    "EnableFileCrc": (UTFTypeValues.ushort, None),
                    "CrcMode": (UTFTypeValues.uint, None),
                    "CrcTable": (UTFTypeValues.bytes, b''),
                    "FileSize": (UTFTypeValues.ullong, None),
                    "TocCrc": (UTFTypeValues.uint, None),
                    "HtocOffset": (UTFTypeValues.ullong, None),
                    "HtocSize": (UTFTypeValues.ullong, None),
                    "ItocCrc": (UTFTypeValues.uint, None),
                    "GtocOffset": (UTFTypeValues.ullong, None),
                    "GtocSize": (UTFTypeValues.ullong, None),                    
                    "HgtocOffset": (UTFTypeValues.ullong, None),
                    "HgtocSize": (UTFTypeValues.ullong, None),
                    "TotalDataSize": (UTFTypeValues.ullong, None),
                    "Tocs": (UTFTypeValues.uint, None),
                    "TotalFiles": (UTFTypeValues.uint, None),
                    "Directories": (UTFTypeValues.uint, None),
                    "Updates": (UTFTypeValues.uint, None),
                    "Comment": (UTFTypeValues.string, '<NULL>'),
                }
            ]
        elif self.CpkMode == 1:
            ContentOffset = 0x800 + len(self.TOCdata)
            CpkHeader = [
                {
                    "UpdateDateTime": (UTFTypeValues.ullong, 0),
                    "FileSize": (UTFTypeValues.ullong, None),
                    "ContentOffset": (UTFTypeValues.ullong, ContentOffset),
                    "ContentSize": (UTFTypeValues.ullong, self.ContentSize),
                    "TocOffset": (UTFTypeValues.ullong, 0x800),
                    "TocSize": (UTFTypeValues.ullong, len(self.TOCdata)),
                    "TocCrc": (UTFTypeValues.uint, None),
                    "EtocOffset": (UTFTypeValues.ullong, None),
                    "EtocSize": (UTFTypeValues.ullong, None),
                    "ItocOffset": (UTFTypeValues.ullong, None),
                    "ItocSize": (UTFTypeValues.ullong, None),
                    "ItocCrc": (UTFTypeValues.uint, None),
                    "GtocOffset": (UTFTypeValues.ullong, None),
                    "GtocSize": (UTFTypeValues.ullong, None),
                    "GtocCrc": (UTFTypeValues.uint, None),               
                    "EnabledPackedSize": (UTFTypeValues.ullong, self.EnabledPackedSize),
                    "EnabledDataSize": (UTFTypeValues.ullong, self.EnabledDataSize),
                    "TotalDataSize": (UTFTypeValues.ullong, None),
                    "Tocs": (UTFTypeValues.uint, None),
                    "Files": (UTFTypeValues.uint, self.fileslen),
                    "Groups": (UTFTypeValues.uint, 0),
                    "Attrs": (UTFTypeValues.uint, 0),
                    "TotalFiles": (UTFTypeValues.uint, None),
                    "Directories": (UTFTypeValues.uint, None),
                    "Updates": (UTFTypeValues.uint, None),
                    "Version": (UTFTypeValues.ushort, 7),
                    "Revision": (UTFTypeValues.ushort, 1),
                    "Align": (UTFTypeValues.ushort, 0x800),
                    "Sorted": (UTFTypeValues.ushort, 1),
                    "EID": (UTFTypeValues.ushort, None),
                    "CpkMode": (UTFTypeValues.uint, self.CpkMode),
                    "Tvers": (UTFTypeValues.string, self.Tver),
                    "Comment": (UTFTypeValues.string, '<NULL>'),
                    "Codec": (UTFTypeValues.uint, 0),
                    "DpkItoc": (UTFTypeValues.uint, 0),
                    "EnableFileName": (UTFTypeValues.ushort, 1),
                    "EnableTocCrc": (UTFTypeValues.ushort, None),
                    "EnableFileCrc": (UTFTypeValues.ushort, None),
                    "CrcMode": (UTFTypeValues.uint, None),
                    "CrcTable": (UTFTypeValues.bytes, b''),
                    "HtocOffset": (UTFTypeValues.ullong, None),
                    "HtocSize": (UTFTypeValues.ullong, None),
                    "HgtocOffset": (UTFTypeValues.ullong, None),
                    "HgtocSize": (UTFTypeValues.ullong, None),
                }
            ]
        elif self.CpkMode == 0:
            CpkHeader = [
                {
                    "UpdateDateTime": (UTFTypeValues.ullong, 0),
                    "ContentOffset": (UTFTypeValues.ullong, 0x800+len(self.ITOCdata)),
                    "ContentSize": (UTFTypeValues.ullong, self.ContentSize),
                    "ItocOffset": (UTFTypeValues.ullong, 0x800),
                    "ItocSize": (UTFTypeValues.ullong, len(self.ITOCdata)),
                    "EnabledPackedSize": (UTFTypeValues.ullong, self.EnabledPackedSize),
                    "EnabledDataSize": (UTFTypeValues.ullong, self.EnabledDataSize),
                    "Files": (UTFTypeValues.uint, self.fileslen),
                    "Groups": (UTFTypeValues.uint, 0),
                    "Attrs": (UTFTypeValues.uint, 0),
                    "Version": (UTFTypeValues.ushort, 7), # 7?
                    "Revision": (UTFTypeValues.ushort, 0),
                    "Align": (UTFTypeValues.ushort, 0x800),
                    "Sorted": (UTFTypeValues.ushort, 0),
                    "EID": (UTFTypeValues.ushort, None),
                    "CpkMode": (UTFTypeValues.uint, self.CpkMode),
                    "Tvers": (UTFTypeValues.string, self.Tver),
                    "Codec": (UTFTypeValues.uint, 0),
                    "DpkItoc": (UTFTypeValues.uint, 0),
                    "FileSize": (UTFTypeValues.ullong, None),
                    "TocOffset": (UTFTypeValues.ullong, None),
                    "TocSize": (UTFTypeValues.ullong, None),
                    "TocCrc": (UTFTypeValues.uint, None),
                    "EtocOffset": (UTFTypeValues.ullong, None),
                    "EtocSize": (UTFTypeValues.ullong, None),
                    "ItocCrc": (UTFTypeValues.uint, None),
                    "GtocOffset": (UTFTypeValues.ullong, None),
                    "GtocSize": (UTFTypeValues.ullong, None),
                    "GtocCrc": (UTFTypeValues.uint, None),
                    "TotalDataSize": (UTFTypeValues.ullong, None),
                    "Tocs": (UTFTypeValues.uint, None),
                    "TotalFiles": (UTFTypeValues.uint, None),
                    "Directories": (UTFTypeValues.uint, None),
                    "Updates": (UTFTypeValues.uint, None),
                    "Comment": (UTFTypeValues.string, '<NULL>'),
                }
            ]
        return UTFBuilder(CpkHeader, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkHeader").bytes()
    
    def generate_ITOC(self) -> bytearray:
        if self.CpkMode == 2:
            payload = []
            for i in range(len(self.files)):
                payload.append(
                    {
                        "ID": (UTFTypeValues.int, i),
                        "TocIndex": (UTFTypeValues.int, i)
                    }
                )
            return UTFBuilder(payload, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkExtendId").bytes()
        else:
            try:
                files = sorted(os.listdir(self.dirname), key=int)
            except:
                raise ValueError("CpkMode of 0 requires filenames to be integers.")
            self.files = [os.path.join(self.dirname, i) for i in files]
            if len(files) == 0:
                raise ValueError("No files are present in the given directory.")
            elif len(files) > 0xFFFF:
                raise OverflowError("CpkMode of 0 can only contain 65535 files at max.")
            self.fileslen = len(files)
            datal = []
            datah = []
            for i in files:
                sz = os.stat(os.path.join(self.dirname, i)).st_size
                self.EnabledDataSize += sz
                if sz % 0x800 != 0:
                    self.ContentSize += sz + (0x800 - sz % 0x800)
                else:
                    self.ContentSize += sz
                if sz > 0xFFFF:
                    dicth = {
                        "ID": (UTFTypeValues.ushort, int(i)),
                        "FileSize": (UTFTypeValues.uint, sz),
                        "ExtractSize": (UTFTypeValues.uint, sz)
                    }
                    datah.append(dicth)
                else:
                    dictl = {
                        "ID": (UTFTypeValues.ushort, int(i)),
                        "FileSize": (UTFTypeValues.ushort, sz),
                        "ExtractSize": (UTFTypeValues.ushort, sz)
                    }
                    datal.append(dictl)
            datallen = len(datal)
            datahlen = len(datah)
            self.EnabledPackedSize = self.EnabledDataSize
            if len(datal) == 0:
                datal.append({"ID": (UTFTypeValues.ushort, 0), "FileSize": (UTFTypeValues.ushort, 0), "ExtractSize": (UTFTypeValues.ushort, 0)})
            elif len(datah) == 0:
                datah.append({"ID": (UTFTypeValues.uint, 0), "FileSize": (UTFTypeValues.uint, 0), "ExtractSize": (UTFTypeValues.uint, 0)})
            payload = [
                {
                   "FilesL" : (UTFTypeValues.uint, datallen),
                   "FilesH" : (UTFTypeValues.uint, datahlen),
                   "DataL" : (UTFTypeValues.bytes, UTFBuilder(datal, table_name="CpkItocL", encrypt=False, encoding=self.encoding).bytes()),
                   "DataH" : (UTFTypeValues.bytes, UTFBuilder(datah, table_name="CpkItocH", encrypt=False, encoding=self.encoding).bytes())
                }
            ]
            return UTFBuilder(payload, table_name="CpkItocInfo", encrypt=self.encrypt, encoding=self.encoding).bytes()