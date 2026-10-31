import ctypes
import ctypes.util

# find_library takes the bare name of a library: no "lib" in front and no ".so" behind.
path = ctypes.util.find_library("brotlidec")
decoder = ctypes.CDLL(path)
print(decoder.BrotliDecoderVersion())
