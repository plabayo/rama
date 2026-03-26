import json
import tempfile
import time
import webbrowser


def wrap_json_into_html(x):
    return "<html><body><code style='white-space: pre-wrap;'>{}</code></body></html>".format(x)


def view_request(r):
    js = json.dumps(r.json(), indent=4)
    with tempfile.NamedTemporaryFile("w", suffix='.html', delete=False) as f:
        f.write(wrap_json_into_html(js))
        f.flush()
        webbrowser.open('file://' + f.name)
        time.sleep(1)
