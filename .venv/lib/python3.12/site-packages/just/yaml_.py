def read(fn):
    import yaml

    with open(fn) as f:
        return yaml.load(f, Loader=yaml.CLoader)


def write(obj, fn):
    import yaml

    with open(fn, "w") as f:
        yaml.dump(obj, f)
