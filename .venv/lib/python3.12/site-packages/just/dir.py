import os
import errno


def mkdir(path, mode=0o777):
    path = os.path.expanduser(path)
    try:
        os.makedirs(path, mode)
    # Python >2.5
    except OSError as exc:  # pragma: no cover
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise
    return path
