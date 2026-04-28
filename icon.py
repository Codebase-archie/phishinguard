
import os
os.makedirs('extension/icons', exist_ok=True)

# create simple PNG icons using raw bytes
# this is a minimal 1x1 red pixel PNG, scaled by the browser
import struct, zlib

def make_png(size, color):
    def chunk(name, data):
        c = zlib.crc32(name + data) & 0xffffffff
        return struct.pack('>I', len(data)) + name + data + struct.pack('>I', c)
    
    raw = b''
    for _ in range(size):
        row = b'\x00'
        for _ in range(size):
            row += bytes(color)
        raw += row
    
    compressed = zlib.compress(raw)
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    
    data = b'\x89PNG\r\n\x1a\n'
    data += chunk(b'IHDR', ihdr)
    data += chunk(b'IDAT', compressed)
    data += chunk(b'IEND', b'')
    return data

shield_color = [59, 130, 246]  # blue
for size in [16, 48, 128]:
    with open(f'extension/icons/icon{size}.png', 'wb') as f:
        f.write(make_png(size, shield_color))
    print(f'Created icon{size}.png')
