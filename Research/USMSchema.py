from PyCriCodecsEx.chunk import *
from PyCriCodecsEx import UTFTypeValues as T

[{'CRIUSF_DIR_STREAM': [{'avbps': (T.uint, 870219),
                         'chno': (T.ushort, 65535),
                         'datasize': (T.uint, 0),
                         'filename': (T.string,
                                      '20200817_アスノヨゾラ哨戒班_short_9sec_200727_576-324_24fps.usm'),
                         'filesize': (T.uint, 14906528),
                         'fmtver': (T.uint, 0),
                         'minbuf': (T.uint, 53824),
                         'minchk': (T.ushort, 1),
                         'stmid': (T.uint, 0)}, # Always 0
                         # First CRIUSF_DIR_STREAM block is the entire USM itself
                         # Filesize would be the size sum of all subsequent streams + headers
                        {'avbps': (T.uint, 870219),
                         'chno': (T.ushort, 0),
                         'datasize': (T.uint, 0),
                         'filename': (T.string,
                                      '20200817_アスノヨゾラ哨戒班_short_9sec_200727_576-324_24fps.mp4'),
                         'filesize': (T.uint, 14743870),
                         'fmtver': (T.uint, 0),
                         'minbuf': (T.uint, 39478),
                         'minchk': (T.ushort, 3),
                         'stmid': (T.uint, 1079199318)}]}, # @SFV or @SFA in uint32be                         
 {'VIDEO_HDRINFO': [{'alpha_type': (T.uint, 0),
                     'color_space': (T.uint, 0),
                     # Seems to always be YUV420
                     'disp_height': (T.uint, 324),
                     'disp_width': (T.uint, 576),
                     'framerate_d': (T.uint, 1000),
                     'framerate_n': (T.uint, 24000),
                    # Running (Max) framerate = framerate_n / framerate_d
                    # Do note that Sofdec does support VFR
                     'height': (T.uint, 328),
                     'ixsize': (T.uint, 39520),
                     'mat_height': (T.uint, 324),
                     'mat_width': (T.uint, 576),
                     'max_picture_size': (T.uint, 0),
                     'metadata_count': (T.uint, 1),
                     # For videos this is always 1
                     'metadata_size': (T.uint, 3200),
                     # VIDEO_SEEKINFO encoded size
                     'mpeg_codec': (T.uchar, 1),
                     # 1 - MPEG1, 5 - H264, 9 - VP9
                     'mpeg_dcprec': (T.uchar, 11),
                     # 0 - VP9, 11 - H264,MPEG1
                     'picture_type': (T.uint, 0),
                     'pre_padding': (T.uint, 0),
                     'scrn_width': (T.uint, 0),
                     'total_frames': (T.uint, 3253),
                     # Framecount
                     'width': (T.uint, 576)}]},                     
 {'VIDEO_SEEKINFO': [{'num_skip': (T.short, 0),
                    # ? Frameskip. Probably not used
                      'ofs_byte': (T.ullong, 5888),
                    # Actual starting @SFV chunk offset in file
                      'ofs_frmid': (T.int, 0),
                    # Frame number
                      'resv': (T.short, 0)},
                    # Keyframe offsets
                     ...
 ]
 # Refer to PyCriCodecsEx/usm.py for audio related info
 }
]