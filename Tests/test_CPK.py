import os
from . import sample_file_path, temp_file_path

from PyCriCodecs.cpk import CPK, CPKBuilder
cpkdir = temp_file_path('cpk')
os.makedirs(cpkdir, exist_ok=True)
cpk = CPK(temp_file_path('default.cpk'))
for f in cpk.files:
    print(f)
pass