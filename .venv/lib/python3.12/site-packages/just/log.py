import time
import sys
import inspect
import just

START = "_".join(time.asctime().replace(":", "_").split())
NAME = sys.argv[0].rstrip(".py")
LOG_BASE = "logs"
LOG_FILE = "{}/{}_{}.jsonl".format(LOG_BASE, NAME, START)
LOG_LINK = "{}/{}.jsonl".format(LOG_BASE, NAME)


def get_file_scope():
    frame = inspect.stack()[2]
    file_name, function_name = frame[1], frame[3]
    return file_name, function_name


def log(obj, *tags):
    file_name, function_name = get_file_scope()
    data = {"tags": tags, "object": obj, "file": file_name, "function": function_name,
            "time": time.time()}
    just.append(data, LOG_FILE)
