from typing import BinaryIO, TypeVar, Type, List

T = TypeVar("T")
from io import BytesIO, FileIO
from struct import unpack, calcsize, pack
from PyCriCodecsEx.chunk import *

class UTF:

    _dictarray: list

    magic: bytes
    table_size: int
    rows_offset: int
    string_offset: int
    data_offset: int
    num_columns: int
    row_length: int
    num_rows: int
    stream: BinaryIO
    recursive: bool
    encoding : str = 'utf-8'

    def __init__(self, stream, recursive=False):
        """Unpacks UTF table binary payload

        Args:
            stream (Union[str, bytes]): The input stream or file path to read the UTF table from.
            recursive (bool): Whether to recursively unpack nested UTF tables.
        """
        if type(stream) == str:
            self.stream = FileIO(stream)
        else:
            self.stream = BytesIO(stream)
        (
            self.magic,
            self.table_size,
            self.rows_offset,
            self.string_offset,
            self.data_offset,
            self.table_name,
            self.num_columns,
            self.row_length,
            self.num_rows,
        ) = UTFChunkHeader.unpack(self.stream.read(UTFChunkHeader.size))
        if self.magic == UTFType.UTF.value:
            self._read_rows_and_columns()
        elif self.magic == UTFType.EUTF.value:
            self.stream.seek(0)
            data = memoryview(bytearray(self.stream.read()))
            m = 0x655F
            t = 0x4115
            for i in range(len(data)):
                data[i] ^= 0xFF & m
                m = (m * t) & 0xFFFFFFFF
            self.stream = BytesIO(bytearray(data))
            (
                self.magic,
                self.table_size,
                self.rows_offset,
                self.string_offset,
                self.data_offset,
                self.table_name,
                self.num_columns,
                self.row_length,
                self.num_rows,
            ) = UTFChunkHeader.unpack(self.stream.read(UTFChunkHeader.size))
            if self.magic != UTFType.UTF.value:
                raise Exception("Decryption error.")
            self._read_rows_and_columns()
        else:
            raise ValueError("UTF chunk is not present.")
        self.recursive = recursive
        if recursive:
            def dfs(payload: list[dict]) -> None:
                for col in range(len(payload)):
                    for k, v in payload[col].items():
                        typeof, value = v
                        if typeof == UTFTypeValues.bytes:
                            # XXX: Recursive UTF tables doesn't seem to get encrypted (e.g. CPK, ACB)
                            # We can pass addition reconstruction flags alongside table names later on, but this is good enough for now
                            if value.startswith(UTFType.UTF.value) or value.startswith(
                                UTFType.EUTF.value
                            ):
                                table = UTF(value, recursive=False)
                                payload[col][k] = (table.table_name, table.dictarray)
                                dfs(table.dictarray)

            dfs(self.dictarray)

    def _read_rows_and_columns(self):
        stream = self.stream.read(self.data_offset - 0x18)
        stream = BytesIO(stream)
        types = [[], [], [], []]
        target_data = []
        target_constant = []
        target_tuple = []
        s_offsets = []
        for i in range(self.num_columns):
            flag = stream.read(1)[0]
            stflag = flag >> 4
            typeflag = flag & 0xF
            if stflag == 0x1:
                offset = int.from_bytes(stream.read(4), "big")
                s_offsets.append(offset)
                target_constant.append(offset)
                types[2].append((">" + self._stringtypes(typeflag), typeflag))
            elif stflag == 0x3:
                offset = int.from_bytes(stream.read(4), "big")
                s_offsets.append(offset)
                target_tuple.append(
                    (
                        offset,
                        unpack(
                            ">" + self._stringtypes(typeflag),
                            stream.read(calcsize(self._stringtypes(typeflag))),
                        ),
                    )
                )
                types[1].append((">" + self._stringtypes(typeflag), typeflag))
            elif stflag == 0x5:
                offset = int.from_bytes(stream.read(4), "big")
                s_offsets.append(offset)
                target_data.append(offset)
                types[0].append((">" + self._stringtypes(typeflag), typeflag))
            elif stflag == 0x7:  # Exists in old CPK's.
                # target_tuple.append((int.from_bytes(stream.read(4), "big"), int.from_bytes(stream.read(calcsize(self.stringtypes(typeflag))), "big")))
                # types[3].append((">"+self.stringtypes(typeflag), typeflag))
                raise NotImplementedError("Unsupported 0x70 storage flag.")
            else:
                raise Exception("Unknown storage flag.")

        rows = []
        for j in range(self.num_rows):
            for i in types[0]:
                rows.append(unpack(i[0], stream.read(calcsize(i[0]))))

        for i in range(4):
            for j in range(len(types[i])):
                types[i][j] = (types[i][j][0][1:], types[i][j][1])
        strings = (stream.read()).split(b"\x00")
        strings_copy = strings[:]
        self._dictarray = []
        self.encoding = "utf-8"
        for i in range(len(strings)):
            try:
                strings_copy[i] = strings[i].decode("utf-8")
            except:
                for x in ["shift-jis", "utf-16"]:
                    try:
                        strings_copy[i] = strings[i].decode(x)
                        self.encoding = x
                        # This looks sketchy, but it will always work since @UTF only supports these 3 encodings.
                        break
                    except:
                        continue
                else:
                    # Probably useless.
                    raise UnicodeDecodeError(
                        f"String of unknown encoding: {strings[i]}"
                    )
        t_t_dict = dict()
        self.table_name = strings_copy[self._finder(self.table_name, strings)]
        UTFTypeValuesList = list(UTFTypeValues)
        s_orders = [strings_copy[self._finder(i, strings)] for i in s_offsets]

        def ensure_order(d: dict) -> dict:
            return {k: d[k] for k in s_orders if k in d}

        for i in range(len(target_constant)):
            if types[2][i][1] not in [0xA, 0xB]:
                val = self._finder(target_constant[i], strings)
                t_t_dict.update(
                    {strings_copy[val]: (UTFTypeValuesList[types[2][i][1]], None)}
                )
            elif types[2][i][1] == 0xA:
                val = self._finder(target_constant[i], strings)
                t_t_dict.update({strings_copy[val]: (UTFTypeValues.string, "<NULL>")})
            else:
                # Most likely useless, since the code doesn seem to reach here.
                val = self._finder(target_constant[i], strings)
                t_t_dict.update({strings_copy[val]: (UTFTypeValues.bytes, b"")})
        for i in range(len(target_tuple)):
            if types[1][i % (len(types[1]))][1] not in [0xA, 0xB]:
                t_t_dict.update(
                    {
                        strings_copy[self._finder(target_tuple[i][0], strings)]: (
                            UTFTypeValuesList[types[1][i % len(types[1])][1]],
                            target_tuple[i][1][0],
                        )
                    }
                )
            elif types[1][i % (len(types[1]))][1] == 0xA:
                t_t_dict.update(
                    {
                        strings_copy[self._finder(target_tuple[i][0], strings)]: (
                            UTFTypeValues.string,
                            strings_copy[self._finder(target_tuple[i][1][0], strings)],
                        )
                    }
                )
            else:
                self.stream.seek(self.data_offset + target_tuple[i][1][0] + 0x8, 0)
                bin_val = self.stream.read((target_tuple[i][1][1]))
                t_t_dict.update(
                    {
                        strings_copy[self._finder(target_tuple[i][0], strings)]: (
                            UTFTypeValues.bytes,
                            bin_val,
                        )
                    }
                )
        temp_dict = dict()
        if len(rows) == 0:
            self._dictarray.append(ensure_order(t_t_dict))
        for i in range(len(rows)):
            if types[0][i % (len(types[0]))][1] not in [0xA, 0xB]:
                temp_dict.update(
                    {
                        strings_copy[
                            self._finder(target_data[i % (len(target_data))], strings)
                        ]: (
                            UTFTypeValuesList[types[0][i % (len(types[0]))][1]],
                            rows[i][0],
                        )
                    }
                )
            elif types[0][i % (len(types[0]))][1] == 0xA:
                temp_dict.update(
                    {
                        strings_copy[
                            self._finder(target_data[i % (len(target_data))], strings)
                        ]: (
                            UTFTypeValues.string,
                            strings_copy[self._finder(rows[i][0], strings)],
                        )
                    }
                )
            else:
                self.stream.seek(self.data_offset + rows[i][0] + 0x8, 0)
                bin_val = self.stream.read((rows[i][1]))
                temp_dict.update(
                    {
                        strings_copy[
                            self._finder(target_data[i % (len(target_data))], strings)
                        ]: (UTFTypeValues.bytes, bin_val)
                    }
                )
            if not (i + 1) % (len(types[0])):
                temp_dict.update(t_t_dict)
                self._dictarray.append(ensure_order(temp_dict))
                temp_dict = dict()

    def _stringtypes(self, type: int) -> str:
        types = "BbHhIiQqfdI"
        if type != 0xB:
            return types[type]
        elif type == 0xB:
            return "II"
        else:
            raise Exception("Unkown data type.")

    def _finder(self, pointer, strings) -> int:
        sum = 0
        for i in range(len(strings)):
            if sum < pointer:
                sum += len(strings[i]) + 1
                continue
            return i
        else:
            raise Exception("Failed string lookup.")

    @property
    def table(self) -> dict:
        """Returns a dictionary representation of the UTF table.

        Effectively, this retrieves a transposed version of the dictarray. Whilst discarding
        type info.

        This is mostly here for cpk.py compatibility.
        """
        keys = self._dictarray[0].keys()
        return {key: [d[key][1] for d in self._dictarray] for key in keys}

    @property
    def dictarray(self) -> list[dict]:
        """Returns a list representation of the UTF table. """
        return self._dictarray

class UTFBuilder:

    encoding: str
    dictarray: list
    strings: bytes
    table_name: str
    binary: bytes
    table: bytearray
    stflag: list
    rows_data: bytearray
    column_data: bytearray
    data_offset: int

    def __init__(
        self,
        dictarray: list[dict],
        encrypt: bool = False,
        encoding: str = "utf-8",
        table_name: str = "PyCriCodecs_table",
        ignore_recursion: bool = False,
    ) -> None:
        """Packs UTF payload back into their binary form
        
        Args:
            dictarray: A list of dictionaries representing the UTF table.
            encrypt: Whether to encrypt the table (default: False).
            encoding: The character encoding to use (default: "utf-8").
            table_name: The name of the table (default: "PyCriCodecs_table").
            ignore_recursion: Whether to ignore recursion when packing (default: False).
        """
        assert type(dictarray) == list, "dictarray must be a list of dictionaries (see UTF.dictarray)."

        # Preprocess for nested dictarray types
        def dfs(payload: list[dict], name: str) -> None:
            for dict in range(len(payload)):
                for k, v in payload[dict].items():
                    typeof_or_name, value = v
                    if type(value) == list:
                        assert type(typeof_or_name) == str, "bogus payload data"
                        payload[dict][k] = (
                            UTFTypeValues.bytes,
                            dfs(value, typeof_or_name),
                        )
            # ? Could subtables be encrypted at all?
            return UTFBuilder(
                payload, encoding=encoding, table_name=name, ignore_recursion=True
            ).bytes()

        if not ignore_recursion:
            dfs(dictarray, table_name)
        l = set([len(x) for x in dictarray])
        if len(l) != 1:
            raise ValueError("All dictionaries must be equal in length.")
        matches = [(k, v[0]) for k, v in dictarray[0].items()]
        for i in range(1, len(dictarray)):
            if matches != [(k, v[0]) for k, v in dictarray[i].items()]:
                raise ValueError(
                    "Keys and/or value types are not matching across dictionaries."
                )
        self.dictarray = dictarray
        self.encrypt = encrypt
        self.encoding = encoding
        self.table_name = table_name
        self.binary = b""
        self._get_strings()

    def _write_header(self) -> bytearray:
        self.data_offset = (
            len(self.column_data)
            + len(self.rows_data)
            + len(self.strings)
            + len(self.binary)
            + 0x18
        )
        datalen = self.data_offset
        if self.data_offset % 8 != 0:
            self.data_offset = self.data_offset + (8 - self.data_offset % 8)
        if len(self.binary) == 0:
            binary_offset = self.data_offset
        else:
            binary_offset = datalen - len(self.binary)
        header = UTFChunkHeader.pack(
            b"@UTF",  # @UTF
            self.data_offset,  # Chunk size.
            len(self.column_data) + 0x18,  # Rows offset.
            datalen - len(self.strings) - len(self.binary),  # String offset.
            binary_offset,  # Binary data offset.
            (
                0
                if self.strings.startswith(bytes(self.table_name, self.encoding))
                else self.strings.index(
                    b"\x00" + bytes(self.table_name, self.encoding) + b"\x00"
                )
                + 1
            ),  # Table name pointer.
            len(self.stflag),  # Num columns.
            sum(
                [calcsize(self._stringtypes(x[1])) for x in self.stflag if x[0] == 0x50]
            ),  # Num rows.
            len(self.dictarray),  # Rows length.
        )
        return bytearray(header)

    def _write_rows(self) -> bytearray:
        rows = bytearray()
        for dict in self.dictarray:
            for data in self.stflag:
                if data[0] == 0x50:
                    if data[1] not in [0xA, 0xB]:
                        rows += pack(">" + self._stringtypes(data[1]), dict[data[2]][1])
                    elif data[1] == 0xA:
                        if bytes(dict[data[2]][1], self.encoding) == b"":
                            idx = self.strings.index(b"\x00\x00") + 1
                            rows += pack(">" + self._stringtypes(data[1]), idx)
                        else:
                            rows += pack(
                                ">" + self._stringtypes(data[1]),
                                self.strings.index(
                                    b"\x00"
                                    + bytes(dict[data[2]][1], self.encoding)
                                    + b"\x00"
                                )
                                + 1,
                            )
                    else:
                        rows += pack(
                            ">" + self._stringtypes(data[1]),
                            self.binary.index(dict[data[2]][1]),
                            len(dict[data[2]][1]),
                        )
        return rows

    def _write_columns(self) -> bytearray:
        columns = bytearray()
        for data in self.stflag:
            columns += int.to_bytes(data[0] | data[1], 1, "big")
            if data[0] in [0x10, 0x50]:
                columns += int.to_bytes(
                    self.strings.index(
                        b"\x00" + bytes(data[2], self.encoding) + b"\x00"
                    )
                    + 1,
                    4,
                    "big",
                )
            else:
                if data[1] not in [0xA, 0xB]:
                    columns += int.to_bytes(
                        self.strings.index(
                            b"\x00" + bytes(data[2], self.encoding) + b"\x00"
                        )
                        + 1,
                        4,
                        "big",
                    ) + int.to_bytes(
                        data[3], calcsize(self._stringtypes(data[1])), "big"
                    )
                elif data[1] == 0xA:
                    columns += int.to_bytes(
                        self.strings.index(
                            b"\x00" + bytes(data[2], self.encoding) + b"\x00"
                        )
                        + 1,
                        4,
                        "big",
                    ) + (
                        b"\x00\x00\x00\x00"
                        if self.strings.startswith(
                            bytes(data[3], self.encoding) + b"\x00"
                        )
                        else (
                            int.to_bytes(
                                self.strings.index(
                                    b"\x00" + bytes(data[3], self.encoding) + b"\x00"
                                )
                                + 1,
                                4,
                                "big",
                            )
                        )
                    )
                else:
                    columns += (
                        int.to_bytes(
                            self.strings.index(
                                b"\x00" + bytes(data[2], self.encoding) + b"\x00"
                            )
                            + 1,
                            4,
                            "big",
                        )
                        + int.to_bytes(self.binary.index(data[3]), 4, "big")
                        + int.to_bytes(len(data[3]), 4, "big")
                    )
        return columns

    def _get_stflag(self):
        to_match = [(x, y) for x, y in self.dictarray[0].items()]
        UTFTypeValuesList = list(UTFTypeValues)
        self.stflag = []
        for val in to_match:
            if len(self.dictarray) != 1:
                for dict in self.dictarray:
                    if dict[val[0]][1] != val[1][1]:
                        self.stflag.append(
                            (0x50, UTFTypeValuesList.index(val[1][0]), val[0])
                        )
                        break
                else:
                    if val[1][1] == None:
                        self.stflag.append(
                            (0x10, UTFTypeValuesList.index(val[1][0]), val[0])
                        )
                    else:
                        self.stflag.append(
                            (
                                0x30,
                                UTFTypeValuesList.index(val[1][0]),
                                val[0],
                                val[1][1],
                            )
                        )
            else:
                # It seems that when there is only one dictionary, there will be no element of type 0x30 flag
                # Otherwise all of them would be either 0x30 or 0x10 flags with no length to the rows.
                if val[1][1] == None or val[1][1] == "<NULL>":
                    self.stflag.append(
                        (0x10, UTFTypeValuesList.index(val[1][0]), val[0])
                    )
                else:
                    self.stflag.append(
                        (0x50, UTFTypeValuesList.index(val[1][0]), val[0])
                    )

    def _get_strings(self):
        strings = []
        binary = b""

        for dict in self.dictarray:
            for key, value in dict.items():
                if key not in strings:
                    strings.append(key)
        for dict in self.dictarray:
            for key, value in dict.items():
                if type(value[1]) == str and value[1] not in strings:
                    strings.append(value[1])
                if (type(value[1]) == bytearray or type(value[1]) == bytes) and value[
                    1
                ] not in binary:
                    binary += value[1]
        self.binary = binary

        strings = [self.table_name] + strings

        if "<NULL>" in strings:
            strings.pop(strings.index("<NULL>"))
            strings = ["<NULL>"] + strings

        for i in range(len(strings)):
            val = strings[i].encode(self.encoding)
            if b"\x00" in val:
                raise ValueError(
                    f"Encoding of {self.encoding} for '{strings[i]}' results in string with a null byte."
                )
            else:
                strings[i] = val

        self.strings = b"\x00".join(strings) + b"\x00"

    def _stringtypes(self, type: int) -> str:
        types = "BbHhIiQqfdI"
        if type != 0xB:
            return types[type]
        elif type == 0xB:
            return "II"
        else:
            raise Exception("Unkown data type.")

    def bytes(self) -> bytearray:
        """Returns a @UTF bytearray Table from the provided payload dict."""
        self._get_stflag()
        self.column_data = self._write_columns()
        self.rows_data = self._write_rows()
        header_data = self._write_header()
        dataarray = (
            header_data + self.column_data + self.rows_data + self.strings + self.binary
        )
        if len(dataarray) % 8 != 0:
            dataarray = dataarray[:8] + dataarray[8:].ljust(
                self.data_offset, b"\x00"
            )  # Padding.
        if self.encrypt:
            dataarray = memoryview(dataarray)
            m = 0x655F
            t = 0x4115
            for i in range(len(dataarray)):
                dataarray[i] ^= 0xFF & m
                m = (m * t) & 0xFFFFFFFF
            dataarray = bytearray(dataarray)
        return dataarray

class UTFViewer:
    _payload: dict

    def __init__(self, payload):
        """Construct a non-owning read-write, deletable view of a UTF table dictarray.
        Nested classes are supported.
        Sorting (using .sort()) is done in-place and affects the original payload.

        Example:
        ```python
            class CueNameTable(UTFViewer):
                CueName : str
                CueIndex : int
            class ACBTable(UTFViewer):
                CueNameTable : List[CueNameTable]
                Awb : AWB
            src = ACB(ACB_sample)
            payload = ACBTable(src.payload)
            >>> Referencing items through Python is allowed
            name = payload.CueNameTable
            >>> Lists can be indexed
            name_str = name[0].CueName
            >>> Deleting items from lists is also allowed
            src.view.CueNameTable.pop(1)
            src.view.CueTable.pop(1)
            >>> The changes will be reflected in the original UTF payload
            
            See __new__ for the actual constructor.
        ```
        """
        assert isinstance(payload, dict), "Payload must be a dictionary."
        super().__setattr__("_payload", payload)

    def __getattr__(self, item):
        annotations = super().__getattribute__("__annotations__")
        # Nested definitions
        if item in annotations:
            sub = annotations[item]
            reduced = getattr(sub, "__args__", [None])[0]
            reduced = reduced or sub
            if issubclass(reduced, UTFViewer):
                typeof_or_name, value = self._payload[item]
                assert (
                    type(typeof_or_name) == str and type(value) == list
                ), "payload is not expanded. parse with UTF(..., recursive=True)"
                return self._view_as(value, reduced)
        payload = super().__getattribute__("_payload")
        if item not in payload:
            return super().__getattribute__(item)
        _, value = payload[item]
        return value

    def __setattr__(self, item, value):
        payload = super().__getattribute__("_payload")
        if item not in payload:
            raise AttributeError(f"{item} not in payload")
        typeof, _ = payload[item]
        payload[item] = (typeof, value)

    def __dir__(self):
        annotations = super().__getattribute__("__annotations__")
        return list(annotations.keys()) + list(super().__dir__())

    @staticmethod
    def _view_as(payload: dict, clazz: Type[T]) -> T:
        if not issubclass(clazz, UTFViewer):
            raise TypeError("class must be a subclass of UTFViewer")
        return clazz(payload)

    class ListView(list):
        _payload : List[dict]
        def __init__(self, payload: list[T]):
            self._payload = payload
            super().__init__([UTFViewer(item) for item in payload])

        def pop(self, index = -1):
            self._payload.pop(index)
            return super().pop(index)
        
        def append(self, o : "UTFViewer"):
            if len(self):
                assert type(self[0]) == type(o), "all items in the list must be of the same type."
            self._payload.append(o._payload)
            return super().append(o)
        
        def extend(self, iterable):
            for item in iterable:
                self.append(item)

        def insert(self, index, o : "UTFViewer"):
            if len(self):
                assert type(self[0]) == type(o), "all items in the list must be of the same type."            
            self._payload.insert(index, o._payload)
            return super().insert(index, o)

        def clear(self):
            self._payload.clear()
            return super().clear()

        def count(self, value):
            raise NotImplementedError("count is not supported on views")
        
        def remove(self, value):
            raise NotImplementedError("remove is not supported on views. use pop(index).")

        def sort(self, key : callable):
            p = sorted([(self[i], i) for i in range(len(self))], key=lambda x: key(x[0]))            
            self._payload[:] = [self._payload[i] for x,i in p]     
            self[:] = [x for x,i in p]            

    def __new__(cls: Type[T], payload: list | dict, **args) -> T | List[T]:
        if isinstance(payload, list):
            return UTFViewer.ListView(payload)
        return super().__new__(cls)
