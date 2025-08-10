from . import sample_file_path, temp_file_path
USM_sample = sample_file_path("USM/SofdecPrime.usm")
ACB_sample = sample_file_path("ACB/0001_01.acb")

import os
print(os.getpid())
input()
from PyCriCodecs.usm import USMBuilder
# src = USM(USM_sample)
open(temp_file_path("build_MPEG1.usm"), 'wb').write(USMBuilder(sample_file_path('USM/MPEG1.mp4')).build())
open(temp_file_path("build_H264.usm"), 'wb').write(USMBuilder(sample_file_path('USM/H264.h264')).build())
open(temp_file_path("build_VP9.usm"), 'wb').write(USMBuilder(sample_file_path('USM/VP9.ivf')).build())