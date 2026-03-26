import base64
import tempfile
import time
import webbrowser


def wrap_img_into_html(content_type, x):
    return '<html><body><img src="data:{};base64,{}"</body></html>'.format(content_type, x.decode("utf8"))


def view_request(r):
    with tempfile.NamedTemporaryFile("w", suffix='.html', delete=False) as f:
        f.write(wrap_img_into_html(r.headers['Content-Type'], base64.b64encode(r.content)))
        f.flush()
        webbrowser.open('file://' + f.name)
        time.sleep(1)
