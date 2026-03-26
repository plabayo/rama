def read(fn):
    import toml

    with open(fn) as f:
        return toml.load(f)


def write(obj, fn):
    import toml

    with open(fn, "w") as f:
        toml.dump(obj, f)
