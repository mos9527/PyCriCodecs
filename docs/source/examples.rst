Load, Extract and modify ACB files
---------------------------

.. code-block:: python

    from PyCriCodecsEx.acb import ACB, ACBBuilder, HCACodec, ADXCodec
    from PyCriCodecsEx.awb import AWBBuilder
    # Load the '.acb' file.
    src = ACB('some_cuesheet.acb')
    print(f'Loaded {src.name}')
    # cue.Waveforms indexes into this
    waveforms = src.get_waveforms() 
    for cue in src.cues:
        print(f'* {cue.CueId:<02X} - {cue.CueName} ({cue.Length:.2f}s) (references AWB IDs {",".join(map(str,cue.Waveforms))})')
        for wav in cue.Waveforms:
            outname = f"{cue.CueName}_{wav}.wav"
            # This will write the decoded WAV file to the outname path
            # Alternatively, you can access the encoded bytes through `.get_encoded()`
            # Format of which can be determined through the waveforms' type.            
            waveforms[wav].save(outname) # Key can be optionally set here
            print(f' -> {outname}')
    # Replace AWB waveform
    # Only WAVs are supported
    src.set_waveforms([HCACodec('some_audio.wav')])
    # Rename the cue
    src.view.CueNameTable[0].CueName = "The New Cue"
    # Only keep the first cue
    while len(src.view.CueTable) > 1:
        src.view.CueTable.pop(-1)
        src.view.CueNameTable.pop(-1) # Optional to pop names
    # Build the binary again
    build = ACBBuilder(src)
    open(outfile, "wb").write(build.build())
    print('Done.')

Build USM files
---------------------------
**NOTE:** FFmpeg must be installed and available in PATH for this to work.

.. code-block:: python

    from PyCriCodecsEx.usm import USM, USMBuilder, ADXCodec, HCACodec
    builder = USMBuilder()
    builder.add_video('some_video.m1v')
    # M1V -> MPEG1 Video. Limited other formats are supported
    # Refer to USMBuilder documentation for more details
    builder.add_audio(ADXCodec('some_audio.wav'))
    # Codec type determines final encoded audio payload. Either ADX or HCA.
    # Only WAV is supported. Multiple audio tracks are also supported.
    with open('build.usm', 'wb') as f:
        f.write(builder.build())
    print('Build Done.')

Load, extract then remux USM files into MP4
---------------------------
**NOTE:** FFmpeg must be installed and available in PATH for this to work.

.. code-block:: python

    usm = USM('build.usm')
    audio = usm.get_audios()
    video = usm.get_video()
    # Only choose the first audio track
    # Multiple tracks are possible - omitted here for the sake of simplicity
    audio = audio[0]
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
    saved_video = 'tmp_video.mp4'
    saved_audio = 'tmp_audio.wav'
    result = 'muxed_result.mp4'
    video.save(saved_video)
    audio.save(saved_audio)
    mux_av(saved_video, saved_audio, result)
    print('Remux Done.')
    # MP4 saved at: muxed_result.mp4

Extract CPK files
---------------------------

.. code-block:: python

    import os
    from PyCriCodecsEx.cpk import CPK
    
    # Open the CPK file
    cpk = CPK('some_archive.cpk')

    # Iterate over files and save them
    for f in cpk.files:
        dst = os.path.join('cpk_folder', f.path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        # Save the file.
        # If it's compressed, this will involve decompression - which is thread safe
        # and can be trivially parallelized through e.g. ThreadPoolExecutor or ProcessPoolExecutor
        f.save(dst)
        print(f'Saved {dst}')
    print('Unpack done.')

Pack files into a CPK
---------------------------

.. code-block:: python
    
    import os
    from PyCriCodecsEx.cpk import CPKBuilder

    def progress_callback(stage: str, current: int, total: int):
        # A simple progress callback function.
        # This is optional, and is guaranteed to be monotonus and
        # called in the calling thread of 'CPKBuilder.save'        
        print(f"Progress [{stage}]: {current}/{total}", end='\r')
    
    # You can set packing modes (ITOC, etc) here.
    # Refer to CPKBuilder documentation for more details.
    builder = CPKBuilder(progress_cb=progress_callback)
    
    # Walk through the source directory and add files
    for root, _, files in os.walk('file_directory'):
        for f in files:
            src_path = os.path.join(root, f)
            # Create a relative path for the file inside the CPK.
            dst_path = os.path.relpath(src_path, source_dir).replace('\\', '/')
            print(f'Adding {src_path} as {dst_path}')
            builder.add_file(src_path, dst_path)
    builder.save(output_cpk_path)
    print(f'\nRepack done. Saved to {output_cpk_path}')