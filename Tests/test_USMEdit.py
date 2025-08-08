from . import sample_file_path, temp_file_path
import shutil

USM_sample = sample_file_path("USM/0018.usm")
ACB_sample = sample_file_path("ACB/0001_01.acb")
outfile = temp_file_path("0001_01.acb")

from PyCriCodecs.usm import USM, USMBuilder
usm = USM(USM_sample)
pass