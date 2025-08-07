from . import sample_file_path, temp_file_path

WAV_sample = sample_file_path("WAV/44100_5s.wav")
ACB_sample = sample_file_path("ACB/0001_01.acb")
outfile = temp_file_path("0001_01.acb")

from PyCriCodecs import ACB
from typing import List

sample = ACB(ACB_sample)
table = sample.view
pass
