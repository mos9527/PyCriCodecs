from . import sample_file_path, temp_file_path

from PyCriCodecs.usm import USMBuilder
builder = USMBuilder(
    temp_file_path('mux_src_video.h264'),
    temp_file_path('mux_src_audio.wav'),
    audio_codec='hca'
)
with open(temp_file_path('rebuild_with_audio.usm'), 'wb') as f:
    f.write(builder.build())