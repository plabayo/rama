import tempfile
import time
import webbrowser


def view_request(r):
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(r.text)
        webbrowser.open('file://' + f.name)
        time.sleep(1)
