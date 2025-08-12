import os
from . import sample_file_path, temp_file_path

from PyCriCodecs.cpk import CPK, CPKBuilder
cpkdir = temp_file_path('cpk')
cpk = CPK(temp_file_path('default.cpk'))
for f in cpk.files:
    dst = os.path.join(cpkdir, f.path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    f.save(dst)
    print('* Saved', dst)
pass