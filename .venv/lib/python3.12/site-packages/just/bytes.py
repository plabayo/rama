def read(fname):
    if not isinstance(fname, str):
        return fname.read()
    with open(fname, "rb") as f:
        return f.read()


def iread(fname):
    if not isinstance(fname, str):
        raise TypeError("Cannot iteratively read compressed file at this point.")
    with open(fname, "rb") as f:
        for char in f:
            yield char


def write(obj, fname):
    if not isinstance(fname, str):
        fname.write(obj)
    else:
        with open(fname, "wb") as f:
            f.write(obj)
