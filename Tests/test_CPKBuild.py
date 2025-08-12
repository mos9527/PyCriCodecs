import os
from . import sample_file_path, temp_file_path
from PyCriCodecsEx.cpk import CPK, CPKBuilder
from tqdm import tqdm

def test_cpk_build():
    progress = tqdm()
    def progress_callback(stage: str, current: int, total: int):
        progress.set_description(stage)
        progress.total = total
        progress.update(current - progress.n)

    cpk = CPKBuilder(progress_cb=progress_callback)
    cpkdir = temp_file_path('cpk')
    for root,_,files in os.walk(cpkdir):
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.relpath(src, cpkdir).replace('\\','/')
            print('Adding', src, 'as', dst)
            cpk.add_file(src, dst, compress=False)

    cpk.save(temp_file_path('rebuild.cpk'))
    print('Done.')

if __name__ == "__main__":
    test_cpk_build()