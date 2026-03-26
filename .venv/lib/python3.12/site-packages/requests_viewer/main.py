import sys
import requests
import requests_viewer.js as js
import requests_viewer.image as image

try:
    import requests_viewer.web as web
except ImportError:
    import requests_viewer.web_compat as web


def main(url=None, default=None):
    if url is None:
        url = sys.argv[1]
    r = requests.get(url)
    content_type = r.headers.get('Content-Type', default)
    if content_type is None:
        raise TypeError("Content type header not set and default=None")
    if content_type.startswith("text/html"):
        web.view_request(r)
    elif content_type.startswith("image"):
        image.view_request(r)
    elif content_type.startswith("application/json"):
        js.view_request(r)
    else:
        raise TypeError("Content type not supported: " + content_type)
