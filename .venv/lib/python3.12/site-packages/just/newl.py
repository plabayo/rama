def read(fname):
    with open(fname) as f:
        return [x for x in f.read().split("\n") if x]


def iread(fname):
    with open(fname) as f:
        for line in f:
            if line:
                yield line.strip()


def write(obj, fname):
    with open(fname, "w") as f:
        f.write("\n".join(obj))
