from . import sample_file_path, temp_file_path

from PyCriCodecsEx.usm import USM, USMBuilder, ADXCodec, HCACodec

def test_usm_decode_and_mux():
    # Build a USM
    builder = USMBuilder(
        sample_file_path('USM/default.m1v'), # MPEG1. See USMBuilder doc
        sample_file_path('WAV/default.wav'),
        audio_codec=ADXCodec.AUDIO_CODEC
    )
    with open(temp_file_path('build.usm'), 'wb') as f:
        f.write(builder.build())
    print('Build Done.')
    # Load it back
    usm = USM(temp_file_path('build.usm'))
    audio = usm.get_audios()
    video = usm.get_video()
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
    saved_video = temp_file_path('tmp_video.mp4')
    saved_audio = temp_file_path('tmp_audio.wav')
    result = temp_file_path('muxed_result1.mp4')
    video.save(saved_video)
    audio.save(saved_audio)
    mux_av(saved_video, saved_audio, result)
    print('Remux Done.')

if __name__ == "__main__":
    test_usm_decode_and_mux()