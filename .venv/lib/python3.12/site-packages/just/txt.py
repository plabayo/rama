def read(fname):
    if not isinstance(fname, str):
        return fname.read().decode()
    with open(fname) as f:
        return f.read()


def iread(fname):
    if not isinstance(fname, str):
        raise TypeError("Cannot iteratively read compressed file at this point.")
    with open(fname) as f:
        for line in f:
            yield line.rstrip("\n")


def write(obj, fname):
    if not isinstance(fname, str):
        fname.write(obj.encode())
    else:
        with open(fname, "w") as f:
            f.write(obj)


def append(obj, fname):
    if not isinstance(fname, str):
        raise TypeError("Cannot append to compression")
    with open(fname, "a+") as f:
        f.write(obj + "\n")
