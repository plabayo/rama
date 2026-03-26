from just.read_write import read


def json_extract(dc, expr):
    from jsonpath_rw import parse

    res = parse(expr).find(dc)
    if len(res) == 1:
        res = res[0].value
    else:
        res = [x.value for x in res]
    return res


def jpath(fname_or_dc, jsonpath_expression):
    if isinstance(fname_or_dc, str):
        fname_or_dc = read(fname_or_dc)
    return json_extract(fname_or_dc, jsonpath_expression)
