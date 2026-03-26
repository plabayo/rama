
def read(fn):
    import dill
    with open(fn, "rb") as f:
        return dill.load(f)


def write(obj, fn):
    import dill
    with open(fn, "wb") as f:
        dill.dump(obj, f)
