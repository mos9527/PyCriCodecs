from PyCriCodecsEx import *
from PyCriCodecsEx import UTFTypeValues as T

# Taken from Tests/ACB/0001_01.acb
{
    "AcbGuid": (T.bytes, b"U\x0f?4 \xbaqF\x93\xad\x1a?\xfd\xba\xec4"),    
    # Different across files
    "AcbVolume": (T.float, 1.0),
    "AcfMd5Hash": (T.bytes, b"3\x9d.{O\xe0\xc9=-\xd1N\x8cl\xb4K\r"),
    # ACF files are always external
    "AcfReferenceTable": ..., 
    # Parameter control data, omitted here
    "ActionTrackTable": (T.bytes, b""),
    "AisacControlNameTable": (T.bytes, b""),
    "AisacNameTable": (T.bytes, b""),
    "AisacTable": (T.bytes, b""),
    "AutoModulationTable": (T.bytes, b""),
    "AwbFile": (T.bytes, ...),
    # Where the AWB data is stored.
    # This could be external - in such cases this field is empty and the Name field maybe used
    # to locate an external AWB file.
    "BeatSyncInfoTable": (T.bytes, b""),
    "BlockSequenceTable": (T.bytes, b""),
    "BlockTable": (T.bytes, b""),
    "CategoryExtension": (T.uchar, 0),
    "CharacterEncodingType": (T.uchar, 0),
    "CueLimitWorkTable": (T.bytes, b""),
    "CueNameTable": [
        {"CueIndex": (T.ushort, 0), "CueName": (T.string, "0001_01")},
        ...
    ],
    # See CueTable for definitions
    # Games may use this to index into CueTable
    "CuePriorityType": (T.uchar, 0xFF),
    "CueTable": [
        {
            "AisacControlMap": (T.bytes, b""),
            "CueId": (T.uint, 0),
            "HeaderVisibility": (T.uchar, 1),
            "Length": (T.uint, 132200),
            # In milliseconds
            "NumAisacControlMaps": (T.uchar, 0),
            "NumRelatedWaveforms": (T.ushort, 1),
            "ReferenceIndex": (T.ushort, 0),
            # Indexes into CueNameTable
            "ReferenceType": (T.uchar, 3),          
            # From vgmstream
            # /* usually older games use older references but not necessarily */
            # switch(r->ReferenceType) {
            # 
            # *   case 0x01: /* Cue > Waveform (ex. PES 2015) */
            #         if (!load_acb_waveform(acb, r->ReferenceIndex))
            #             goto fail;
            #         break;
            # 
            # *   case 0x02: /* Cue > Synth > Waveform (ex. Ukiyo no Roushi) */
            #         if (!load_acb_synth(acb, r->ReferenceIndex))
            #             goto fail;
            #         break;
            # 
            # *   case 0x03: /* Cue > Sequence > Track > Command > Synth > Waveform (ex. Valkyrie Profile anatomia, Yakuza Kiwami 2) */
            # *       // Also the case for the test file itself (Project SEKAI)
            #         if (!load_acb_sequence(acb, r->ReferenceIndex))
            #             goto fail;
            #         break;
            # 
            # *   case 0x08: /* Cue > BlockSequence > Track / Block > Track > Command > Synth > Waveform (ex. Sonic Lost World, Kandagawa Jet Girls, rare) */
            #         if (!load_acb_blocksequence(acb, r->ReferenceIndex))
            #             goto fail;
            #         break;
            #     ... (other cases fails)    
            # }
            "UserData": (T.string, ""),
            "Worksize": (T.ushort, 0),
        }, ...        
    ],
    "EventTable": (T.bytes, b""),
    "FileIdentifier": (T.uint, 0),
    "GlobalAisacReferenceTable": (T.bytes, b""),
    "GraphTable": (T.bytes, b""),
    "InstrumentPluginParameterTable": (T.bytes, b""),
    "InstrumentPluginTrackTable": (T.bytes, b""),
    "LipsMorphTable": (T.bytes, b""),
    "MIDITrackTable": (T.bytes, b""),
    "Name": (T.string, "0001_01"),
    # Can be used to locate an external AWB file. See above    
    "NumCueLimit": (T.ushort, 0),
    "NumCueLimitListWorks": (T.ushort, 0),
    "NumCueLimitNodeWorks": (T.ushort, 0),
    "OutsideLinkTable": (T.bytes, b""),
    "PaddingArea": (T.bytes, b""),
    "ProjectKey": (T.bytes, b"\x17\x0e\x8dx\xd5k\x95\xb5\xae\x94TT\xa8\x9a\x9aL"),    
    "SeqCommandTable": [
        {
            "Command": (
                T.bytes,
                b"\x00A\x04\x00\x00\x00\x05\x00E\x04A\xf0"
                b"\x00\x00\x00o\x04\x00\x00'\x10",
            )
        },
        {
            "Command": (
                T.bytes,
                b"\x00A\x04\x00\x00\x00\x05\x00E\x04A\xf0"
                b"\x00\x00\x00o\x04\x00\x00#(\x00o\x04"
                b"\x00\x01\x13\x88\x00o\x04\x00"
                b"\x03\x13\x88",
            )
        },
    ],
    # TODO: Sequence commands TLV. vgmstream didn't use these
    # NOTE: TLV [u16be tag + u8 size + data]
    "SeqParameterPalletTable": (T.bytes, b""),
    "SequenceTable": [
        {
            "ActionTrackStartIndex": (T.ushort, 0xFFFF),
            "CommandIndex": (T.ushort, 0),
            "ControlWorkArea1": (T.ushort, 0),
            "ControlWorkArea2": (T.ushort, 0),
            "GlobalAisacNumRefs": (T.ushort, 0),
            "GlobalAisacStartIndex": (T.ushort, 0xFFFF),
            "InstPluginTrackStartIndex": (T.ushort, 0xFFFF),
            "LocalAisacs": (T.bytes, b""),
            "NumActionTracks": (T.ushort, 0),
            "NumInstPluginTracks": (T.ushort, 0),
            "NumTracks": (T.ushort, 1),
            "ParameterPallet": (T.ushort, 0xFFFF),
            "PlaybackRatio": (T.ushort, 100),
            "TrackIndex": (T.bytes, b"\x00\x00"),
            # Indexes into TrackTable s16be
            "TrackValues": (T.bytes, b""),
            "Type": (T.uchar, 0)
            # From vgmstream            
            # switch(r->Type) {
            #     /* types affect which item in the TrackIndex list is picked (see load_acb_synth) */
            #     case 0: /* polyphonic (TrackIndex only) */
            #     case 1: /* sequential (TrackIndex only) */
            #     case 3: /* random (TrackIndex + TrackValues = int percent) */
            #     case 4: /* random no repeat (TrackIndex + TrackValues = int percent) */
            #     ... (load track at TrackIndex regardless)
            # }
        },
        {
            "ActionTrackStartIndex": (T.ushort, 0xFFFF),
            "CommandIndex": (T.ushort, 1),
            "ControlWorkArea1": (T.ushort, 1),
            "ControlWorkArea2": (T.ushort, 1),
            "GlobalAisacNumRefs": (T.ushort, 0),
            "GlobalAisacStartIndex": (T.ushort, 0xFFFF),
            "InstPluginTrackStartIndex": (T.ushort, 0xFFFF),
            "LocalAisacs": (T.bytes, b""),
            "NumActionTracks": (T.ushort, 0),
            "NumInstPluginTracks": (T.ushort, 0),
            "NumTracks": (T.ushort, 1),
            "ParameterPallet": (T.ushort, 0xFFFF),
            "PlaybackRatio": (T.ushort, 100),
            "TrackIndex": (T.bytes, b"\x00\x01"),
            "TrackValues": (T.bytes, b""),
            "Type": (T.uchar, 0),
        },
    ],
    "Size": (T.uint, 0),
    "SoundGeneratorTable": (T.bytes, b""),
    "SoundInstruments": (T.bytes, b""),
    "SoundProgramBankKey": (T.bytes, b""),
    "StreamAwbAfs2Header": (T.bytes, b""),
    "StreamAwbHash": (
        T.bytes,
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ),
    # ? Doesn't seem to be used
    "StreamAwbTocWork": (T.bytes, b""),
    "StreamAwbTocWorkOld": (T.bytes, b""),
    "StreamAwbTocWork_Old": (T.bytes, b""),
    "StringValueTable": ...,
    # Keys in AcfReferenceTable
    "SynthCommandTable": (T.bytes, b""),
    "SynthParameterPalletTable": (T.bytes, b""),
    "SynthTable": [
        {
            "ActionTrackStartIndex": (T.ushort, 0xFFFF),
            "CommandIndex": (T.ushort, 0xFFFF),
            "ControlWorkArea1": (T.ushort, 0),
            "ControlWorkArea2": (T.ushort, 0),
            "GlobalAisacNumRefs": (T.ushort, 0),
            "GlobalAisacStartIndex": (T.ushort, 0xFFFF),
            "LocalAisacs": (T.bytes, b""),
            "NumActionTracks": (T.ushort, 0),
            "ParameterPallet": (T.ushort, 0xFFFF),
            "ReferenceItems": (T.bytes, b"\x00\x01\x00\x00"),
            # [u16be item_type + u16be item_index] indexes into one of the following
            # switch (item_type)
            #   case 0x01: /* Waveform (most common) */
            #       if (!load_acb_waveform(acb, item_index))
            #           goto fail;
            #       break;
            #   case 0x02: /* Synth, possibly random (rare, found in Sonic Lost World with ReferenceType 2) */
            #       if (!load_acb_synth(acb, item_index))
            #           goto fail;
            #       break;
            #   case 0x03: /* Sequence of Synths w/ % in Synth.TrackValues (rare, found in Sonic Lost World with ReferenceType 2) */
            #       if (!load_acb_sequence(acb, item_index))
            #           goto fail;
            #       break;
            #   ... (other cases fail)
            "TrackValues": (T.bytes, b""),
            "Type": (T.uchar, 0),
            "VoiceLimitGroupName": (T.string, ""),
        },
        {
            "ActionTrackStartIndex": (T.ushort, 0xFFFF),
            "CommandIndex": (T.ushort, 0xFFFF),
            "ControlWorkArea1": (T.ushort, 1),
            "ControlWorkArea2": (T.ushort, 1),
            "GlobalAisacNumRefs": (T.ushort, 0),
            "GlobalAisacStartIndex": (T.ushort, 0xFFFF),
            "LocalAisacs": (T.bytes, b""),
            "NumActionTracks": (T.ushort, 0),
            "ParameterPallet": (T.ushort, 0xFFFF),
            "ReferenceItems": (T.bytes, b"\x00\x01\x00\x00"),
            "TrackValues": (T.bytes, b""),
            "Type": (T.uchar, 0),
            "VoiceLimitGroupName": (T.string, ""),
        },
    ],
    "Target": (T.uchar, 0),
    "TrackCommandTable": (T.bytes, b""),
    # TLV. Seems rarely used
    "TrackEventTable": [
        # From vgmstream        
        # while (pos < max_pos) {
        #    tlv_code = read_u16be(Command_offset + pos + 0x00, sf);
        #    tlv_size = read_u8   (Command_offset + pos + 0x02, sf);
        #    pos  += 0x03;
        #    /* There are around 160 codes (some unused), with things like set volume, pan, stop, mute, and so on.
        #     * Multiple commands are linked and only "note on" seems to point so other objects, so maybe others
        #     * apply to current object (since there is "note off" without reference. */
        #    switch(tlv_code) {
        # *      case 2000: /* noteOn */
        # *      case 2003: /* noteOnWithNo plus 16b (null?) [rare, ex. PES 2014] */
        #            if (tlv_size < 0x04) {
        #                VGM_LOG("acb: TLV with unknown size\n");
        #                break;
        #            }
        # *          tlv_type = read_u16be(Command_offset + pos + 0x00, sf); /* ReferenceItem */
        # *          tlv_index = read_u16be(Command_offset + pos + 0x02, sf);
        #            /* same as Synth's ReferenceItem type? */
        #            switch(tlv_type) {
        # *              case 0x02: /* Synth (common) */
        #                    if (!load_acb_synth(acb, tlv_index))
        #                        goto fail;
        #                    break;
        # *              case 0x03: /* Sequence (common, ex. Yakuza 6, Yakuza Kiwami 2) */
        #                    if (!load_acb_sequence(acb, tlv_index))
        #                        goto fail;
        #                    break;
        #                ... (other cases fail)
        #            }
        #        ... (other TLV codes ignored)
        #       pos += tlv_size;
        #   }
        #    
        {"Command": (T.bytes, b"\x07\xd0\x04\x00\x02\x00\x00\x00\x00\x00")},
        {"Command": (T.bytes, b"\x07\xd0\x04\x00\x02\x00\x01\x00\x00\x00")},
        # In our case it's always noteOn (2000) Synth (2)
    ],
    # TLV. Can be aliased as `CommandTable`. Structures are the same    
    "TrackParameterPalletTable": (T.bytes, b""),
    "TrackTable": [
        {
            "CommandIndex": (T.ushort, 0xFFFF),
            "EventIndex": (T.ushort, 0),
            # Indexes into TrackEventTable
            "GlobalAisacNumRefs": (T.ushort, 0),
            "GlobalAisacStartIndex": (T.ushort, 0xFFFF),
            "LocalAisacs": (T.bytes, b""),
            "ParameterPallet": (T.ushort, 0xFFFF),
            "Scope": (T.uchar, 0),
            "TargetAcbName": (T.string, ""),
            "TargetId": (T.uint, 0xFFFFFFFF),
            "TargetName": (T.string, ""),
            "TargetTrackNo": (T.ushort, 0xFFFF),
            "TargetType": (T.uchar, 0),
        }, ...
    ],
    "Type": (T.uchar, 0),
    "Version": (T.uint, 20382208),
    "VersionString": (T.string, "\nACB Format/PC Ver.1.37.2 Build:\n"),
    "WaveformExtensionDataTable": (T.bytes, b""),
    # ? WAV loop points. Need samples
    "WaveformTable": [
        {
            "EncodeType": (T.uchar, 2),
            # From vgmstream
            # 00: ADX (.adx) [Gunhound EX (PSP), Persona 5 (PS3), Shin Megami Tensei V: Vengeance (PS4)]
            # 01: PCM? (.swlpcm?)
            # 02: HCA-MX? (.hca) [common]
            # 03: alt ADX?
            # 04: Wii DSP? (.wiiadpcm?)
            # 05: NDS DSP? (.dsadpcm)
            # 06: HCA-MX (.hcamx) [common]
            # 07: VAG (.vag) [Ukiyo no Roushi (Vita)]
            # 08: ATRAC3 (.at3) [Ukiyo no Shishi (PS3)]
            # 09: CWAV (.3dsadpcm) [Sonic: Lost World (3DS)]
            # 10: HEVAG (.vag) [Ukiyo no Roushi (Vita)]
            # 11: ATRAC9 (.at9) [Ukiyo no Roushi (Vita)]
            # 12: X360 XMA? (.xma2?)
            # 13: DSP (.wiiuadpcm?) [Sonic: Lost World (WiiU)]
            # 13: CWAC DSP (.wiiuadpcm?) [Mario & Sonic at the Rio 2016 Olympic Games (WiiU)]
            # 14: PS4 HEVAG?
            # 18: PS4 ATRAC9 (.at9) [13 Sentinels (PS4)]
            # 19: AAC M4A (.m4a) [Imperial SaGa Eclipse (Browser)]
            # 24: Switch Opus (.switchopus) [Super Mario RPG (Switch)]
            "ExtensionData": (T.ushort, 0xFFFF), # -1
            "LipMorphIndex": (T.ushort, 0xFFFF),
            "LoopFlag": (T.uchar, 1),
            "MemoryAwbId": (T.ushort, 0),
            # Indexes into AwbFile
            "NumChannels": (T.uchar, 2),
            "NumSamples": (T.uint, 5830020),
            # Total sample *per channel* from AWB content
            # = 132.2 * 44100 
            "SamplingRate": (T.ushort, 44100),
            "StreamAwbId": (T.ushort, 0xFFFF),
            "StreamAwbPortNo": (T.ushort, 0xFFFF),
            "Streaming": (T.uchar, 0),
        }
    ],
}
