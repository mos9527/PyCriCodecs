from . import sample_file_path, temp_file_path
USM_sample = sample_file_path("USM/SofdecPrime.usm")
ACB_sample = sample_file_path("ACB/0001_01.acb")
MPEG1_sample = sample_file_path('USM/MPEG1.mp4')
outfile = temp_file_path("0001_01.usm")

from PyCriCodecs.usm import USMBuilder, USM
# src = USM(USM_sample)
stream = USMBuilder(MPEG1_sample)
open(outfile, 'wb').write(stream.build())