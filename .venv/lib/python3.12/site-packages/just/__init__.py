""" You can kind of see this as the scope of `just` when you 'import just'
The following functions become available:
just.__project__
just.__version__
just.run
just.print_version
"""

import os
import errno
import shutil
from just.path_ import (
    ls,
    rename,
    exists,
    make_path,
    get_just_path,
    glob,
    remove,
    mkdir,
    most_recent,
)
from just.read_write import *
from just.requests_ import request, request_tree, get, get_tree, post, post_tree, save_session
from just.date import yesterday, days_back
from just.dir import mkdir
from just.log import log
from just.jpath import json_extract, jpath
from just.pattern import Pattern

# In [19]: with open("fuck.xz", "wb") as f: f.write(lzma.compress(html.encode()))

# In [20]: with lzma.open("fuck.xz") as f: hh=f.read()

__project__ = "just"
__version__ = "0.8.165"

