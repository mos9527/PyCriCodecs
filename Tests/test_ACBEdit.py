from . import sample_file_path, temp_file_path

WAV_sample = sample_file_path("WAV/44100_5s.wav")
ACB_sample = sample_file_path("ACB/0001_01.acb")
outfile = temp_file_path("0001_01.acb")

from PyCriCodecs.acb import ACB, ACBBuilder
from PyCriCodecs.awb import AWBBuilder
from PyCriCodecs.hca import HCA

src = ACB(ACB_sample)
awb = AWBBuilder([HCA(WAV_sample).encode()])
# Replace AWB waveform
src.view.AwbFile = awb.build()
# Rename the cue
src.view.CueNameTable[0].CueName = "The New Cue"
# Remove the last cue
src.view.CueTable.pop()
src.view.CueNameTable.pop()
# Build the binary again
build = ACBBuilder(src)
open(outfile, "wb").write(build.build())
