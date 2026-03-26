try:
    import zstandard as zstd
except ImportError:
    import zstd


class ZstdFile(object):
    def __init__(self, fname, *ignore, **kw_ignore):
        self.fname = fname

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if value:
            raise value
        return True

    def read(self, **kwargs):
        with open(self.fname, "rb") as f:
            return zstd.ZstdDecompressor().decompress(f.read())

    def write(self, obj, **kwargs):
        with open(self.fname, "wb") as f:
            if isinstance(obj, str):
                obj = bytes(obj, encoding="utf8")
            f.write(zstd.ZstdCompressor().compress(obj))
