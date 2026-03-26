import errno
import functools
import inspect
import os
import re

import glob2

__cached_just_path = None


def glob(path, sort_reverse=False):
    res = re.findall("([$][A-Z_]+)", path)
    for x in res:
        path = path.replace(x, os.environ[x[1:]])
    path = make_path(path)
    output = glob2.glob(path)
    if sort_reverse is not None:
        output = sorted(output, reverse=sort_reverse)
    return output


def get_just_env_path():
    return os.environ.get("JUST_PATH")


def find_just_path(base=None, max_depth=5):
    if base is None:
        base = os.path.dirname(os.path.abspath(inspect.stack()[1][1]))
    for depth in range(max_depth):
        prefix = "../" * depth
        just_file = os.path.join(base, prefix, ".just")
        if os.path.isfile(just_file):
            print("just_file", os.path.abspath(os.path.dirname(just_file)))
            return os.path.abspath(os.path.dirname(just_file))
    return None


def get_likely_path():
    # try:
    # main_path = os.path.abspath(sys.modules['__main__'].__file__)
    # except AttributeError:
    main_path = os.path.realpath("__file__")
    return os.path.dirname(main_path)


def get_just_path():
    global __cached_just_path
    if __cached_just_path is not None:
        return __cached_just_path
    just_path = get_just_env_path()
    just_path = just_path if just_path is not None else find_just_path()
    just_path = just_path if just_path is not None else find_just_path(".")
    just_path = just_path if just_path is not None else get_likely_path()
    __cached_just_path = just_path
    return just_path


@functools.lru_cache(maxsize=1_000_000)
def make_path(filename):
    just_path = get_just_path()
    if not isinstance(filename, str | bytes):
        filename = filename.name.encode("utf8").decode()
    filename = filename.replace("file://", "")
    path = os.path.join(just_path, os.path.expanduser(filename))
    if path.endswith("."):
        path = path[:-1]
    return path


def exists(fname):
    return os.path.isfile(make_path(fname))


def rename(src, dest, no_exist=None) -> bool:
    src = make_path(src)
    dest = make_path(dest)
    if not dest.endswith("/"):
        *dest_folder_parts, filename = dest.split("/")
        dest_folder = "/".join(dest_folder_parts)
        if not os.path.exists(dest_folder) and "." in filename:
            os.makedirs(dest_folder)
    if not os.path.isfile(src) and no_exist is not None:
        return False
    os.rename(src, dest)
    return True


def _as_glob(dir_name, recursive):
    dir_name = make_path(dir_name)
    if "*" not in dir_name:
        if dir_name.endswith("/"):
            dir_name += "*"
        else:
            dir_name += "/*"
        if recursive:
            dir_name += "*"
    return dir_name


def ls(dir_name, recursive=False, no_dirs=False):
    dir_name = _as_glob(dir_name, recursive)
    if no_dirs:
        return [x for x in glob(dir_name) if not os.path.isdir(x)]
    else:
        return glob(dir_name)


def mkdir(path, mode=0o777) -> None:
    path = make_path(path)
    try:
        os.makedirs(path, mode)
    # Python >2.5
    except OSError as exc:  # pragma: no cover
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def remove(file_path, no_exist=False, allow_recursive=False):
    if isinstance(file_path, tuple | list):
        file_path = os.path.join(*file_path)
    if "*" in file_path:
        if not allow_recursive:
            msg = "Cannot remove wildcard unless allow_recursive=True"
            raise OSError(msg)
        paths = glob(file_path)
        for fn in sorted(paths, key=lambda x: -len(x)):
            os.remove(fn)
        return bool(paths)
    file_path = make_path(file_path)
    if os.path.isfile(file_path):
        os.remove(file_path)
        return True
    if os.path.isdir(file_path):
        if allow_recursive:
            shutil.rmtree(file_path)
            return True
        else:
            msg = "Cannot remove directory unless allow_recursive=True"
            raise OSError(msg)
    # if there is a default value, return that if no file/dir found when attempting to remove
    if no_exist is not None:
        return no_exist
    msg = f"File '{file_path}' does not exist."
    raise OSError(msg)


def most_recent(file_path):
    return max(glob(file_path), key=os.path.getctime)
