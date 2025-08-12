from . import sample_file_path, temp_file_path
def test_acb_edit():
    WAV_sample = sample_file_path("WAV/default.wav")
    ACB_sample = sample_file_path("ACB/default.acb")
    outfile = temp_file_path("default.acb")

    from PyCriCodecsEx.acb import ACB, ACBBuilder
    from PyCriCodecsEx.awb import AWBBuilder
    from PyCriCodecsEx.hca import HCA

    src = ACB(ACB_sample)
    awb = AWBBuilder([HCA(WAV_sample).encode()])
    # Replace AWB waveform
    src.view.AwbFile = awb.build()
    # Rename the cue
    src.view.CueNameTable[0].CueName = "The New Cue"
    # Remove the last cue
    src.view.CueTable.pop()
    src.view.CueNameTable.pop()
    # Build the binary again
    build = ACBBuilder(src)
    open(outfile, "wb").write(build.build())
    print('Done.')

if __name__ == "__main__":
    test_acb_edit()