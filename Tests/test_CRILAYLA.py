import os
from . import sample_file_path, temp_file_path
from CriCodecsEx import CriLaylaCompress, CriLaylaDecompress

def test_CRILAYLA(): 
    for _ in range(16):
        data = os.urandom(10*(1<<10))
        print('Raw size:', len(data))
        compressed = CriLaylaCompress(data)        
        print('Compressed size:', len(compressed))
        decompressed = CriLaylaDecompress(compressed)        
        print('Decompressed size:', len(decompressed))
        assert data == decompressed, "Decompressed data does not match original"
        print('Ratio:', len(compressed) / len(data))
    print('CRILAYLA Pass.')

if __name__ == "__main__":
    test_CRILAYLA()