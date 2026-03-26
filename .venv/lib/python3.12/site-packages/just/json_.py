import warnings
from just.dt import parse_dt
from collections import defaultdict
import orjson
import json

parse_knowledge = defaultdict(lambda: (0, 0))


def default(obj):
    if isinstance(obj, set):
        return list(obj)
    tp = str(type(obj))
    if ".float" in tp:
        return float(obj)
    if ".int" in tp:
        return int(obj)
    raise TypeError


def handle_str_value(path, v):
    hits, total = parse_knowledge[path]
    if total == 5:
        if hits == 5:
            return parse_dt(v)
        return v
    try:
        v = parse_dt(v)
        hits += 1
    except ValueError:
        pass
    parse_knowledge[path] = (hits, total + 1)
    return v


def try_dt(col):
    try:
        return [parse_dt(x) if isinstance(x, str) else x for x in col]
    except ValueError:
        return col


def parse_datetimes(obj, path: str = ""):
    if isinstance(obj, str):
        return handle_str_value(path, obj)
    if isinstance(obj, list):
        return [parse_datetimes(x, "." + path) for x in obj]
    if isinstance(obj, dict):
        return {k: parse_datetimes(v, path + k) for k, v in obj.items()}
    return obj


def read(fn, warn=False, parse_dt=False):
    if not isinstance(fn, str):
        return json.load(fn)
    if fn.endswith(".jsonl"):
        if warn:
            warnings.warn("Reading streaming format at once.")
        data = list(iread(fn))
        if parse_dt:
            data = parse_datetimes(data)
        return data
    with open(fn) as f:
        data = json.load(f)
        if parse_dt:
            data = parse_datetimes(data)
        return data


def append(obj, fn):
    if not isinstance(fn, str):
        raise TypeError("Cannot append to compression")
    with open(fn, "a+") as f:
        f.write(orjson.dumps(obj, default=default).decode() + "\n")


def write(obj, fn, indent=True):
    # indent 0 = false, 1 = 2 lvls
    if not isinstance(obj, bytes):
        obj = orjson.dumps(obj, option=int(indent))
    if not isinstance(fn, str):
        fn.write(obj)
    else:
        with open(fn, "w") as f:
            f.write(obj.decode())


def iread(fn):
    if not isinstance(fn, str):
        raise TypeError("Cannot iteratively read compressed file now")
    with open(fn) as f:
        for i, line in enumerate(f):
            try:
                data = orjson.loads(line)
                if parse_dt:
                    data = parse_datetimes(data)
                yield data
            except Exception as e:
                msg = "JSON-L parsing error in line number {} in the jsonl file".format(i)
                raise Exception(msg, line)


def iwrite(obj, fn):
    if not isinstance(fn, str):
        raise TypeError("Cannot iteratively write compressed")
    with open(fn, "w") as f:
        for chunk in obj:
            f.write(orjson.dumps(chunk, default=default).decode() + "\n")
