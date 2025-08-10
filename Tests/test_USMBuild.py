from . import sample_file_path, temp_file_path

from PyCriCodecs.usm import USMBuilder
def pack(src : str , codec : str):
    with open(temp_file_path(f"build_{codec}.usm"), 'wb') as f:
        builder = USMBuilder(src)
        print(f'*Packing codec={codec}, instance={builder.video_stream}')
        usm = builder.build()
        print(f'Out {len(usm)} bytes')
        f.write(usm)
# Pack video stream without audio
# USM codec format is automatically selected by input file
pack(sample_file_path('USM/MPEG1.mp4'), 'MPEG1')
pack(sample_file_path('USM/H264.h264'), 'H264')
pack(sample_file_path('USM/VP9.ivf'), 'VP9')
