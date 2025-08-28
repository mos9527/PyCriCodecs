from . import sample_file_path, temp_file_path
def test_acb_edit():
    WAV_sample = sample_file_path("WAV/default.wav")
    ACB_sample = sample_file_path("ACB/default.acb")
    outfile = temp_file_path("default.acb")

    from PyCriCodecsEx.acb import ACB, ACBBuilder, HCACodec, ADXCodec
    from PyCriCodecsEx.awb import AWBBuilder

    src = ACB(ACB_sample)
    print(f'Loaded {src.name}')
    waveforms = src.get_waveforms()    
    for cue in src.cues:
        print(f'* {cue.CueId:<02X} - {cue.CueName} ({cue.Length:.2f}s) (references AWB IDs {",".join(map(str,cue.Waveforms))})')
        for wav in cue.Waveforms:
            outname = temp_file_path(f"{cue.CueName}_{wav}.wav")
            waveforms[wav].save(outname)
            print(f' -> {outname}')
    # Replace AWB waveform
    print('Replacing waveform')
    src.set_waveforms([HCACodec(WAV_sample)])
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

if __name__ == "__main__":
    test_acb_edit()