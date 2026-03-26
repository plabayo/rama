import re
from datetime import datetime

from just import glob, iread


def parse_specials(special_str):  # -> name, cast
    if not special_str:
        return "", "str"
    if "@" not in special_str:
        return special_str, ""
    return special_str.split("@")


def iso(x):
    return datetime.fromisoformat(x.replace(",", ".").replace("Z", "+00:00"))


def convert_str(format_str):
    format_str = re.sub(" +", " ", format_str)
    rr = ""
    on = False
    types = []
    tmp = ""
    lenm = len(format_str)
    captured_names = []
    for i, x in enumerate(format_str):
        if x == "}":
            on = False
            # fw = False
            name, cast = parse_specials(tmp)
            capture = bool(name)
            tp = eval(cast) if cast else str
            # if fw:
            #     pat = ".{4}"
            if i + 1 == lenm:
                pat = ".+"
            else:
                pat = f"[^{format_str[i+1]}]+"
            if capture:
                pat = f"({pat})"
                captured_names.append(name)
                types.append(tp)
            rr += pat
            tmp = ""
            len(rr)
        elif x == "{":
            on = True
        elif not on:
            rr += re.escape(x)
        else:
            tmp += x
    rr = rr.replace("\\ ", "\\ *")
    return rr, types, captured_names


NUMERIC = {int, float}


class Pattern:
    def __init__(self, format_str) -> None:
        self.format_str = format_str
        self.pattern, self.types, self.names = convert_str(format_str)
        if len(self.types) == 1:
            self.type = self.types[0]
            self.find = self.finder_one
        else:
            self.find = self.finder_multi
        self.r = re.compile(self.pattern)
        self.num_captures_vars = len([x for x in self.names if x])

    def finder_one(self, line):
        res = self.r.search(line)
        if not res:
            return None
        return self.type(res.groups()[0].strip())

    def finder_multi(self, line):
        res = self.r.search(line)
        if not res:
            return [None] * self.num_captures_vars
        return [tp(x.strip()) for name, tp, x in zip(self.names, self.types, res.groups(), strict=False) if name]

    def find_dict(self, line):
        res = self.finder_multi(line)
        if res[0] is None:
            return None
        return {
            k: v for k, v in zip(self.names, res, strict=False) if isinstance(k, int) or not k.startswith("_") and k
        }

    def stream(self, fname):
        if "*" in fname:
            return sum([[res for x in iread(fname) if (res := self.find_dict(x))] for fname in glob(fname)], [])
        return [res for x in iread(fname) if (res := self.find_dict(x))]
