from . import sample_file_path, temp_file_path

from PyCriCodecs.usm import USM
usm = USM(sample_file_path('.temp/rebuild_with_audio.usm'))
video = usm.get_video()
audio = usm.get_audios()
audio = audio[0] if audio else None
# Mux into MP4
import ffmpeg, os
def mux_av(video_src: str, audio_src: str, output: str, delete: bool = False):
    (        
        ffmpeg.output(
            ffmpeg.input(video_src), 
            ffmpeg.input(audio_src),
            output, 
            vcodec='copy',
            acodec='copy',
        ).overwrite_output()
    ).run()
    if delete:
        print('* Cleaning up temporary files')        
        os.unlink(video_src)
        os.unlink(audio_src)
    print(f'* Result available at: {output}')
saved_video = temp_file_path('mux_src_video1.mp4')
saved_audio = temp_file_path('mux_src_audio1.wav')
result = temp_file_path('muxed_result1.mp4')
video.save(saved_video)
audio.save(saved_audio)
mux_av(saved_video, saved_audio, result)
