import os
import just.txt as txt
import just.json_ as json
import just.newl as newl
import just.yaml_ as yaml
import just.bytes as bytes_
import just.pickle_ as pickle
from just.path_ import remove
from just import make_path, glob, mkdir
import lxml.html

EXT_TO_MODULE = {
    "html": txt,
    "py": txt,
    "txt": txt,
    "log": txt,
    "sql": txt,
    "md": txt,
    "newl": newl,
    "json": json,
    "jsonl": json,
    "yaml": yaml,
    "yml": yaml,
    "pickle": pickle,
    "pkl": pickle,
    "bytes": bytes_,
    "png": bytes_,
    "jpg": bytes_,
    "jpeg": bytes_,
    "gif": bytes_,
}

EXT_TO_COMPRESSION = {}

try:
    import gzip

    EXT_TO_COMPRESSION.update({"gz": gzip.GzipFile, "gzip": gzip.GzipFile})
except ImportError:
    pass

try:
    import bz2

    EXT_TO_COMPRESSION.update({"bz2": bz2.BZ2File, "bzip2": bz2.BZ2File, "bzip": bz2.BZ2File})
except ImportError:
    pass

try:
    import lzma

    EXT_TO_COMPRESSION.update({"xz": lzma.open})
except ImportError:
    pass

try:
    import just.zstd_ as zstd

    EXT_TO_COMPRESSION.update({"zstd": zstd.ZstdFile, "zst": zstd.ZstdFile, "zstandard": zstd.ZstdFile})
except ImportError:
    pass

ZSTD_AVAILABLE = "zstd" in EXT_TO_COMPRESSION
ROLL_EXTENSION = "zstd" if ZSTD_AVAILABLE else "gz"


def reader(fname, no_exist, read_func_name, unknown_type, ignore_exceptions):
    fname = make_path(fname)
    if not os.path.isfile(fname) and no_exist is not None:
        return no_exist
    compression = []
    stripped_fname = fname
    for k, v in EXT_TO_COMPRESSION.items():
        if fname.endswith(k):
            compression.append(v)
            stripped_fname = stripped_fname[: -(len(k) + 1)]
    ext = stripped_fname.split(".")[-1] if "." in stripped_fname[-6:] else None
    if ext not in EXT_TO_MODULE and unknown_type == "RAISE":
        raise TypeError("just does not yet cover '{}'".format(ext))
    reader_module = EXT_TO_MODULE.get(ext, None) or EXT_TO_MODULE[unknown_type]
    read_fn = getattr(reader_module, read_func_name)
    if ignore_exceptions is not None:
        try:
            if compression:
                compression = compression[0]
                # actually returns a file handler >.<
                with compression(fname, "rb") as f:
                    return read_fn(f)
            else:
                return read_fn(fname)
        except ignore_exceptions:
            return None
    else:
        if compression:
            compression = compression[0]
            # actually returns a file handler >.<
            with compression(fname, "rb") as f:
                return read_fn(f)
        else:
            return read_fn(fname)


def read(fname, no_exist=None, unknown_type="RAISE", ignore_exceptions=None):
    if "*" in fname:
        raise ValueError(f"* cannot be in fname for normal read: {fname}")
    return reader(fname.strip(), no_exist, "read", unknown_type, ignore_exceptions)


def multi_read(star_path, no_exist=None, unknown_type="RAISE", ignore_exceptions=None, sort_reverse=False):
    for x in glob(star_path, sort_reverse=sort_reverse):
        yield x, read(x, no_exist, unknown_type, ignore_exceptions)


def multi_read_tree(star_path, no_exist=None, unknown_type="html", ignore_exceptions=None, sort_reverse=False):
    for x in glob(star_path, sort_reverse=sort_reverse):
        yield x, read_tree(x, no_exist, unknown_type, ignore_exceptions)


def writer(obj, fname, mkdir_no_exist, skip_if_exist, write_func_name, unknown_type, **kwargs):
    fname = make_path(fname)
    if skip_if_exist and os.path.isfile(fname):  # pragma: no cover
        return False
    if mkdir_no_exist:
        dname = os.path.dirname(fname)
        if dname not in set([".", "..", ""]):
            mkdir(dname)
    compression = []
    stripped_fname = fname
    for k, v in EXT_TO_COMPRESSION.items():
        if fname.endswith(k):
            compression.append(v)
            stripped_fname = stripped_fname[: -(len(k) + 1)]

    ext = stripped_fname.split(".")[-1] if "." in stripped_fname[-6:] else None
    if ext not in EXT_TO_MODULE and unknown_type == "RAISE":
        raise TypeError("just does not yet cover '{}'".format(ext))
    writer_module = EXT_TO_MODULE.get(ext, None) or EXT_TO_MODULE[unknown_type]
    write_fn = getattr(writer_module, write_func_name)
    if compression:
        # actually returns a file handler >.<
        compression = compression[0]
        with compression(fname, "wb") as f:
            return write_fn(obj, f, **kwargs)
    else:
        return write_fn(obj, fname, **kwargs)


def write(obj, fname, mkdir_no_exist=True, skip_if_exist=False, unknown_type="RAISE", **kwargs):
    return writer(obj, fname, mkdir_no_exist, skip_if_exist, "write", unknown_type, **kwargs)


# only supported for JSON Lines so far.
roll_counter = {}


def get_rolled_path(fname, roll_extension):
    it = 0
    dir_, base = os.path.split(fname)
    base, *rest = base.split(".")
    while True:
        path = f"{dir_}/{base}_{it}.{'.'.join(rest)}.{roll_extension}"
        if not os.path.exists(path):
            return path
        it += 1


def append(
    obj,
    fname,
    mkdir_no_exist=True,
    skip_if_exist=False,
    unknown_type="RAISE",
    roll=0,
    roll_extension=ROLL_EXTENSION,
):
    writer(obj, fname, mkdir_no_exist, skip_if_exist, "append", unknown_type)
    if roll:
        fname = make_path(fname)
        if fname not in roll_counter:
            roll_counter[fname] = 0
        roll_counter[fname] += 1
        if roll == roll_counter[fname]:
            data = read(fname)
            rolled_path = get_rolled_path(fname, roll_extension)
            write(data, rolled_path, unknown_type=unknown_type)
            remove(fname)
            roll_counter[fname] = 0


def multi_write(obj, fname, mkdir_no_exist=True, skip_if_exist=False):
    if not isinstance(fname, list) or not isinstance(obj, list):  # pragma: no cover
        raise NotImplementedError("Only list of fnames + list of objects supported.")
    return [write(o, fn, mkdir_no_exist, skip_if_exist) for o, fn in zip(obj, fname)]


def iread(fname, no_exist=None, unknown_type="RAISE", ignore_exceptions=None):
    return reader(fname, no_exist, "iread", unknown_type, ignore_exceptions)


def iwrite(obj, fname, mkdir_no_exist=True, skip_if_exist=False, unknown_type="RAISE"):
    return writer(obj, fname, mkdir_no_exist, skip_if_exist, "iwrite", unknown_type)


def read_tree(fname, no_exist=None, unknown_type="html", ignore_exceptions=None):
    return lxml.html.fromstring(read(fname, no_exist, unknown_type, ignore_exceptions))
