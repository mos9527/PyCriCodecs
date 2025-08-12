import os
from typing import BinaryIO
from io import BytesIO, FileIO
from PyCriCodecsEx.chunk import *
from PyCriCodecsEx.utf import UTF, UTFBuilder
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed
from tempfile import NamedTemporaryFile
import CriCodecsEx

def worker_do_compression(src : str, dst: str):
    with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
        data = fsrc.read()
        compressed = CriCodecsEx.CriLaylaCompress(data)
        fdst.write(compressed)
@dataclass
class _PackFile():
    stream: BinaryIO
    path: str
    offset: int   
    size : int 
    compressed : bool = False

    def get_bytes(self) -> bytes:
        self.stream.seek(self.offset)
        data = self.stream.read(self.size)
        if self.compressed:
            data = CriCodecsEx.CriLaylaDecompress(data)
        return data

    def save(self, path : str):
        with open(path, "wb") as f:
            f.write(self.get_bytes())
class _TOC():
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
                    self.tables["TOC"] = _TOC(self.stream.read(self.tables['CPK']["TocSize"][0])).table
            elif key == "ItocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["ITOC"] = _TOC(self.stream.read(self.tables['CPK']["ItocSize"][0])).table
                    if "DataL" in self.tables["ITOC"]:
                        self.tables["ITOC"]['DataL'][0] = UTF(self.tables["ITOC"]['DataL'][0]).table
                    if "DataH" in self.tables["ITOC"]:
                        self.tables["ITOC"]['DataH'][0] = UTF(self.tables["ITOC"]['DataH'][0]).table
            elif key == "HtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["HTOC"] = _TOC(self.stream.read(self.tables['CPK']["HtocSize"][0])).table
            elif key == "GtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["GTOC"] = _TOC(self.stream.read(self.tables['CPK']["GtocSize"][0])).table
                    if "AttrData" in self.tables["GTOC"]:
                        self.tables["GTOC"]['AttrData'][0] = UTF(self.tables["GTOC"]['AttrData'][0]).table
                    if "Fdata" in self.tables["GTOC"]:
                        self.tables["GTOC"]['Fdata'][0] = UTF(self.tables["GTOC"]['Fdata'][0]).table
                    if "Gdata" in self.tables["GTOC"]:
                        self.tables["GTOC"]['Gdata'][0] = UTF(self.tables["GTOC"]['Gdata'][0]).table
            elif key == "HgtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["HGTOC"] = _TOC(self.stream.read(self.tables['CPK']["HgtocSize"][0])).table
            elif key == "EtocOffset":
                if value[0]:
                    self.stream.seek(value[0], 0)
                    self.tables["ETOC"] = _TOC(self.stream.read(self.tables['CPK']["EtocSize"][0])).table
    
    @property
    def mode(self):
        TOC, ITOC, GTOC = 'TOC' in self.tables, 'ITOC' in self.tables, 'GTOC' in self.tables
        if TOC and ITOC and GTOC:
            return 3
        elif TOC and ITOC:
            return 2
        elif TOC:
            return 1
        elif ITOC:
            return 0
        raise ValueError("Unknown CPK mode.")

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
                    yield _PackFile(self.stream, os.path.join(dirname,filename), self.stream.tell(), toctable['FileSize'][i], compressed=True)
                else:
                    self.stream.seek(rel_off+toctable["FileOffset"][i], 0)
                    yield _PackFile(self.stream, os.path.join(dirname,filename), self.stream.tell(), toctable['FileSize'][i])                    
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
                        yield _PackFile(self.stream, str(i), self.stream.tell(), toctableH['FileSize'][idx], compressed=True)
                    else:
                        yield _PackFile(self.stream, str(i), self.stream.tell(), toctableH['FileSize'][idx])
                    if toctableH['FileSize'][idx] % align != 0:
                        seek_size = (align - toctableH['FileSize'][idx] % align)
                        self.stream.seek(seek_size, 1)
                elif i in toctableL['ID']:
                    idx = toctableL['ID'].index(i)
                    if toctableL['ExtractSize'][idx] > toctableL['FileSize'][idx]:
                        yield _PackFile(self.stream, str(i), self.stream.tell(), toctableL['FileSize'][idx], compressed=True)
                    else:
                        yield _PackFile(self.stream, str(i), self.stream.tell(), toctableL['FileSize'][idx])
                    if toctableL['FileSize'][idx] % align != 0:
                        seek_size = (align - toctableL['FileSize'][idx] % align)
                        self.stream.seek(seek_size, 1)
class CPKBuilder:
    """ Use this class to build semi-custom CPK archives. """
    mode: int 
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
    fileslen: int
    ITOCdata: bytearray
    TOCdata: bytearray
    CPKdata: bytearray
    ContentSize: int
    EnabledDataSize: int
    EnabledPackedSize: int
    outfile: str
    init_toc_len: int # This is a bit of a redundancy, but some CPK's need it.

    in_files : list[tuple[str, str, bool]] # (source path, dest filename, compress or not)
    os_files : list[tuple[str, bool]] # (os path, temp or not)
    files: list[tuple[str, int, int]] # (filename, file size, compressed file size).
    
    progress_cb : callable # Progress callback taking (task name, current, total)
    
    def __init__(self, mode: int = 1, Tver: str = None, encrypt: bool = False, encoding: str = "utf-8", progress_cb : callable = None) -> None:
        """Setup CPK file building

        Args:
            mode (int, optional): CPK mode. 0: ID Only (ITOC), 1: Name Only (TOC), 2: Name + ID (ITOC + TOC), 3: Name + ID + GTOC (GTOC). Defaults to 1.
            Tver (str, optional): CPK version. Defaults to None.
            encrypt (bool, optional): Enable encryption. Defaults to False.
            encoding (str, optional): Filename encoding. Defaults to "utf-8".
            progress_cb (callable, optional): Progress callback taking (task name, current, total). Defaults to None.
        """                
        self.progress_cb = progress_cb
        if not self.progress_cb:
            self.progress_cb = lambda task_name, current, total: None
        self.mode = mode
        if not Tver:
            # Some default ones I found with the matching CpkMode, hope they are good enough for all cases.
            if self.mode == 0:
                self.Tver = 'CPKMC2.18.04, DLL2.78.04'
            elif self.mode == 1:
                self.Tver = 'CPKMC2.45.00, DLL3.15.00'
            elif self.mode == 2:
                self.Tver = 'CPKMC2.49.32, DLL3.24.00'
            elif self.mode == 3:
                self.Tver = 'CPKFBSTD1.49.35, DLL3.24.00'
            else:
                raise ValueError("Unknown CpkMode.")
        else:
            self.Tver = Tver
        if self.mode not in [0, 1, 2, 3]:
            raise ValueError("Unknown CpkMode.")

        self.encrypt = encrypt
        self.encoding = encoding
        self.EnabledDataSize = 0
        self.EnabledPackedSize = 0
        self.ContentSize = 0
        self.in_files = []
        self.os_files = []

    def add_file(self, src : str, dst : str = None, compress=False):
        """Add a file to the bundle.
        
        Args:
            src (str): The source file path.
            dst (str): The destination full file name (containing directory). Can be None in ITOC Mode. Defaults to None.
            compress (bool, optional): Whether to compress the file. Defaults to False.
        
        NOTE: 
            - In ITOC-related mode, the insertion order determines the final integer ID of the files.
            - Compression can be VERY slow with high entropy files (e.g. encoded media). Use at discretion.
        """
        if not dst and self.mode != 0:
            raise ValueError("Destination filename must be specified in non-ITOC mode.")
        
        self.in_files.append((src, dst, compress))

    def _writetofile(self, header) -> None:
        with open(self.outfile, "wb") as out:
            out.write(header)
            for i, ((path, _), (filename, file_size, pack_size)) in enumerate(zip(self.os_files, self.files)):
                src = open(path, 'rb').read()
                out.write(src)
                out.write(bytes(0x800 - pack_size % 0x800))
                self.progress_cb("Write %s" % os.path.basename(filename), i + 1, len(self.files))

    def _populate_files(self, parallel : bool):
        self.files = []
        for src, dst, compress in self.in_files:
            if compress:
                tmp = NamedTemporaryFile(delete=False)
                self.os_files.append((tmp.name, True))
            else:
                self.os_files.append((src, False))
        if parallel:
            with ProcessPoolExecutor() as exec:
                futures = []
                for (src, _, _), (dst, compress) in zip(self.in_files,self.os_files):
                    if compress:
                        futures.append(exec.submit(worker_do_compression, src, dst))
                for i, fut in as_completed(futures):
                    try:
                        fut.result()
                    except:
                        pass
                    self.progress_cb("Compress %s" % os.path.basename(src), i + 1, len(futures))
        else:
            for i, ((src, _, _), (dst, compress)) in enumerate(zip(self.in_files,self.os_files)):
                    if compress:
                        worker_do_compression(src, dst)
                        self.progress_cb("Compress %s" % os.path.basename(src), i + 1, len(self.in_files))
        for (src, filename, _) , (dst, _) in zip(self.in_files,self.os_files):
            file_size = os.stat(src).st_size         
            pack_size = os.stat(dst).st_size
            self.files.append((filename, file_size, pack_size))

    def _cleanup_files(self):
        self.files = []
        for path, is_temp in self.os_files:
            if not is_temp:
                continue
            try:                
                os.unlink(path)
            except:
                pass
        self.os_files = []

    def save(self, outfile : str, parallel : bool = False):
        """Build and save the bundle into a file


        Args:
            outfile (str): The output file path.
            parallel (bool, optional): Whether to use parallel processing for file compression (if at all used). Defaults to False.

        NOTE: 
            - Temporary files may be created during the process if compression is used.
            - parallel uses multiprocessing. Make sure your main function is guarded with `if __name__ == '__main__'` clause.
        """
        assert self.in_files, "cannot save empty bundle"
        self.outfile = outfile
        self._populate_files(parallel)
        if self.encrypt:
            encflag = 0
        else:
            encflag = 0xFF
        data = None
        if self.mode == 3:
            self.TOCdata = self._generate_TOC()
            self.TOCdata = bytearray(CPKChunkHeader.pack(b'TOC ', encflag, len(self.TOCdata), 0)) + self.TOCdata
            self.TOCdata = self.TOCdata.ljust(len(self.TOCdata) + (0x800 - len(self.TOCdata) % 0x800), b'\x00')
            assert self.init_toc_len == len(self.TOCdata)
            self.GTOCdata = self._generate_GTOC()
            self.GTOCdata = bytearray(CPKChunkHeader.pack(b'GTOC', encflag, len(self.GTOCdata), 0)) + self.GTOCdata
            self.GTOCdata = self.GTOCdata.ljust(len(self.GTOCdata) + (0x800 - len(self.GTOCdata) % 0x800), b'\x00')
            self.CPKdata = self._generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.TOCdata + self.GTOCdata
        elif self.mode == 2:
            self.TOCdata = self._generate_TOC()
            self.TOCdata = bytearray(CPKChunkHeader.pack(b'TOC ', encflag, len(self.TOCdata), 0)) + self.TOCdata
            self.TOCdata = self.TOCdata.ljust(len(self.TOCdata) + (0x800 - len(self.TOCdata) % 0x800), b'\x00')
            assert self.init_toc_len == len(self.TOCdata)
            self.ITOCdata = self._generate_ITOC()
            self.ITOCdata = bytearray(CPKChunkHeader.pack(b'ITOC', encflag, len(self.ITOCdata), 0)) + self.ITOCdata
            self.ITOCdata = self.ITOCdata.ljust(len(self.ITOCdata) + (0x800 - len(self.ITOCdata) % 0x800), b'\x00')
            self.CPKdata = self._generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.TOCdata + self.ITOCdata
        elif self.mode == 1:
            self.TOCdata = self._generate_TOC()
            self.TOCdata = bytearray(CPKChunkHeader.pack(b'TOC ', encflag, len(self.TOCdata), 0)) + self.TOCdata
            self.TOCdata = self.TOCdata.ljust(len(self.TOCdata) + (0x800 - len(self.TOCdata) % 0x800), b'\x00')
            assert self.init_toc_len == len(self.TOCdata)
            self.CPKdata = self._generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.TOCdata
        elif self.mode == 0:
            self.ITOCdata = self._generate_ITOC()
            self.ITOCdata = bytearray(CPKChunkHeader.pack(b'ITOC', encflag, len(self.ITOCdata), 0)) + self.ITOCdata
            self.ITOCdata = self.ITOCdata.ljust(len(self.ITOCdata) + (0x800 - len(self.ITOCdata) % 0x800), b'\x00')
            self.CPKdata = self._generate_CPK()
            self.CPKdata = bytearray(CPKChunkHeader.pack(b'CPK ', encflag, len(self.CPKdata), 0)) + self.CPKdata
            data = self.CPKdata.ljust(len(self.CPKdata) + (0x800 - len(self.CPKdata) % 0x800) - 6, b'\x00') + bytearray(b"(c)CRI") + self.ITOCdata
        self._writetofile(data)
        self._cleanup_files()
    
    def _generate_GTOC(self) -> bytearray:
        # NOTE: Practically useless
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

    def _generate_TOC(self) -> bytearray:
        payload = []        
        temp = []        
        count = 0
        lent = 0
        switch = False
        sf = set()
        sd = set()
        for filename, store_size, full_size in self.files:
            # Dirname management.
            # Must be POSIX path
            dirname = os.path.dirname(filename)
            if dirname not in sd:
                switch = True
                lent += len(dirname) + 1
                sd.update({dirname})
            
            # Filename management.
            flname = os.path.basename(filename)
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
        for filename, store_size, full_size in self.files:
            sz = store_size
            fz = full_size
            if sz > 0xFFFFFFFF:
                raise OverflowError("4GBs is the max size of a single file that can be bundled in a CPK archive of mode 1.")
            self.EnabledDataSize += fz
            self.EnabledPackedSize += sz
            if sz % 0x800 != 0:
                self.ContentSize += sz + (0x800 - sz % 0x800)
            else:
                self.ContentSize += sz
            dirname = os.path.dirname(filename)
            payload.append(
                {
                    "DirName": (UTFTypeValues.string, dirname),
                    "FileName": (UTFTypeValues.string, os.path.basename(filename)),
                    "FileSize": (UTFTypeValues.uint, sz),
                    "ExtractSize": (UTFTypeValues.uint, fz),
                    "FileOffset": (UTFTypeValues.ullong, lent),
                    "ID": (UTFTypeValues.uint, count),
                    "UserString": (UTFTypeValues.string, "<NULL>")
                }
            )
            count += 1
            if sz % 0x800 != 0:
                lent += sz + (0x800 - sz % 0x800)
            else:
                lent += sz
        return UTFBuilder(payload, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkTocInfo").bytes()

    def _generate_ITOC(self) -> bytearray:
        if self.mode == 2:
            payload = []
            for i, (filename, store_size, full_size) in enumerate(self.files):
                payload.append(
                    {
                        "ID": (UTFTypeValues.int, i),
                        "TocIndex": (UTFTypeValues.int, i)
                    }
                )
            return UTFBuilder(payload, encrypt=self.encrypt, encoding=self.encoding, table_name="CpkExtendId").bytes()
        else:
            assert len(self.files) < 65535, "ITOC requires less than 65535 files."
            self.fileslen = len(self.files)
            datal = []
            datah = []
            for i, (filename, store_size, full_size) in enumerate(self.files):
                sz = store_size
                fz = full_size
                self.EnabledDataSize += fz
                self.EnabledPackedSize += sz
                if sz % 0x800 != 0:
                    self.ContentSize += sz + (0x800 - sz % 0x800)
                else:
                    self.ContentSize += sz
                if sz > 0xFFFF:
                    dicth = {
                        "ID": (UTFTypeValues.ushort, i),
                        "FileSize": (UTFTypeValues.uint, sz),
                        "ExtractSize": (UTFTypeValues.uint, sz)
                    }
                    datah.append(dicth)
                else:
                    dictl = {
                        "ID": (UTFTypeValues.ushort, i),
                        "FileSize": (UTFTypeValues.ushort, sz),
                        "ExtractSize": (UTFTypeValues.ushort, sz)
                    }
                    datal.append(dictl)
            datallen = len(datal)
            datahlen = len(datah)
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
        
    def _generate_CPK(self) -> bytearray:
        if self.mode == 3:
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
                    "CpkMode": (UTFTypeValues.uint, self.mode),
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
        elif self.mode == 2:
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
                    "CpkMode": (UTFTypeValues.uint, self.mode),
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
        elif self.mode == 1:
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
                    "CpkMode": (UTFTypeValues.uint, self.mode),
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
        elif self.mode == 0:
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
                    "CpkMode": (UTFTypeValues.uint, self.mode),
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
    