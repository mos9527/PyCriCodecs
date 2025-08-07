from . import sample_file_path, temp_file_path

WAV_sample = sample_file_path("WAV/44100_5s.wav")
ACB_sample = sample_file_path("ACB/0001_01.acb")
outfile = temp_file_path("0001_01.acb")

from PyCriCodecs import *
from typing import List

src = ACB(ACB_sample)
hca = HCA(WAV_sample)
hca_bytes = hca.encode()
awb = AWBBuilder([hca_bytes], src.awb.subkey, src.awb.version, src.awb.id_intsize, src.awb.align)
src.awb = awb.build()
build = ACBBuilder(src)
open(outfile, "wb").write(build.build())
