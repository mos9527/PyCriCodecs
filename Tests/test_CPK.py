import os
from . import sample_file_path, temp_file_path
from PyCriCodecsEx.cpk import CPK, CPKBuilder

def test_cpk_unpack():     
    # Extract CPK content
    cpkdir = temp_file_path('cpk')
    cpk = CPK(sample_file_path('CPK/default.cpk'))
    for f in cpk.files:
        dst = os.path.join(cpkdir, f.path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        f.save(dst)
        print('Saved', dst)
    print('Unpack done.')

    def progress_callback(stage: str, current: int, total: int):
        print(f"Progress [{stage}]: {current}/{total}",end='\r')
    
    # Pack files back into another CPK
    cpk = CPKBuilder(progress_cb=progress_callback)
    cpkdir = temp_file_path('cpk')
    for root,_,files in os.walk(cpkdir):
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.relpath(src, cpkdir).replace('\\','/')
            print('Adding', src, 'as', dst)
            cpk.add_file(src, dst, compress=True)

    cpk.save(temp_file_path('rebuild.cpk'))
    print('Repack done.')

if __name__ == "__main__":
    test_cpk_unpack()