import hashlib
import os
import time
import warnings
from collections import defaultdict
from urllib.parse import urlparse

from just.path_ import exists, glob, make_path, remove
from just.read_write import read, write

session = None
PER_FOLDER = 3000
BINARY_EXTENSIONS = {"jpg", "png", "jpeg"}

caches = {}
timers = {}
sessions = {}
last_cache_fname = {}

obj_counts = defaultdict(int)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"


def get_domain(url) -> str:
    return url.split("/")[2].split("?")[0].replace("www.", "")


def delete_from_cache(url, cache_key=None, compression=".gz"):
    domain_name = get_domain(url)
    if cache_key is not None:
        fname = get_cache_file_name_str(domain_name, cache_key, compression)
        parts = fname.split()
        parts[-2] = "*"
        fname = glob("/".join(parts))[0]
    else:
        fname = last_cache_fname[domain_name]
    remove(fname)
    return fname


def update_obj_count(domain, dir_name, obj_type):
    if (domain, obj_type) not in obj_counts:
        dir_name = make_path(dir_name)
        try:
            existing_partitions = glob(make_path(dir_name) + "/*")
            if existing_partitions:
                latest_folder = max(existing_partitions)
                base = int(latest_folder.split("/")[-1]) * PER_FOLDER
                count = base + len(os.listdir(latest_folder))
            else:
                count = 0
        except FileNotFoundError:
            count = 0
        obj_counts[(domain, obj_type)] = count
    return obj_counts[(domain, obj_type)]


def get_cache_file_name(domain, request_info, compression=".gz") -> str:
    import orjson

    key = orjson.dumps(request_info)
    m = hashlib.md5()
    m.update(key)
    md5 = m.hexdigest()
    dir_name, fname = md5[:3], md5[3:]
    if not compression:
        compression = ""
    return f"~/.just_requests/{domain}/{dir_name}/{fname}.json{compression}"


def get_obj_type(cache_key):
    if isinstance(cache_key, bool):
        obj_type, fname = "", ""
    else:
        if "/" in cache_key:
            obj_type, fname = cache_key.split("/")
        else:
            obj_type, fname = "", cache_key
        if obj_type:
            obj_type = "/" + obj_type
    return obj_type, fname


def get_cache_file_name_str(domain, cache_key, compression=".gz") -> str:
    obj_type, fname = get_obj_type(cache_key)
    initial_part = f"~/.just_requests/{domain}{obj_type}"
    partition = update_obj_count(domain, initial_part, obj_type) // PER_FOLDER
    if not compression:
        compression = ""
    return f"{initial_part}/{partition}/{fname}.json{compression}"


def from_cache(url, cache_key, paths_only=False, compression=".gz"):
    domain = get_domain(url)
    obj_type, fname = get_obj_type(cache_key)
    initial_part = f"~/.just_requests/{domain}{obj_type}"
    partition = "*"
    paths = glob(f"{initial_part}/{partition}/{fname}.json{compression}")
    if paths_only:
        return paths
    return [read(x)["resp"] for x in paths]


def get_session_method(reuse_session, session_key, remote_ip, method, url):
    if reuse_session:
        domain_name, local_address = session_key
        t1 = time.time()
        expired = sessions[session_key][1] + 300 < t1 if session_key in sessions else False
        if session_key not in sessions or expired:
            import requests

            session = requests.Session()
            if local_address is not None:
                from just.source_ip import SourceAddressAdapter

                session.mount("http://", SourceAddressAdapter(local_address))
                session.mount("https://", SourceAddressAdapter(local_address))
            if remote_ip is not None:
                from just.forcedip import ForcedIPHTTPSAdapter

                session.mount(f"https://{domain_name}", ForcedIPHTTPSAdapter(dest_ip=remote_ip))
            sessions[session_key] = [session, t1]
        if expired:
            print("just.requests_", url, "old session")
        # e.g. GET or POST
        request_fn = getattr(sessions[session_key][0], method)
    else:
        import requests

        request_fn = getattr(requests, method)
    return request_fn


def is_binary_extension_url(url):
    parse_result = urlparse(url)
    for option in [parse_result.path, parse_result.query]:
        for binary in BINARY_EXTENSIONS:
            if option.endswith("." + binary):
                return binary
    return None


def _retry(
    method,
    max_retries,
    delay_base,
    raw,
    caching,
    cache_compression,
    cache_ttl,
    sleep_time,
    reuse_session,
    local_address,
    remote_ip,
    refresh_session_on_error,
    kwargs,
):
    from requests import RequestException
    from requests.utils import cookiejar_from_dict

    tries = 0
    url = kwargs["url"]
    domain_name = get_domain(url)

    use_cache, *request_info = caching

    cache_file_name = os.path.expanduser(get_cache_file_name(domain_name, request_info, cache_compression))

    if exists(cache_file_name):
        if use_cache and (not cache_ttl or time.time() < cache_ttl + os.path.getmtime(cache_file_name)):
            last_cache_fname[domain_name] = cache_file_name
            return read(cache_file_name)["resp"]
        if use_cache is None:
            use_cache = True
        remove(cache_file_name)

    if "timeout" not in kwargs:
        kwargs["timeout"] = delay_base

    cookies = kwargs.get("cookies")
    if isinstance(cookies, dict):
        kwargs["cookies"] = cookiejar_from_dict(cookies)

    session_key = (domain_name, local_address)
    request_fn = get_session_method(reuse_session, session_key, remote_ip, method, kwargs["url"])

    if sleep_time and session_key in timers:
        # 1200 - 1201 + 3
        diff = timers[session_key] - time.time() + sleep_time

        if diff > 0:
            time.sleep(diff)

    # retrying
    err = False
    r = None
    while tries < max_retries:
        try:
            r = request_fn(**kwargs)
            # update session age
            if reuse_session:
                sessions[session_key][1] = time.time()
            if r.status_code > 399:
                err = None
                if refresh_session_on_error:
                    request_fn = get_session_method(reuse_session, session_key, remote_ip, method, kwargs["url"])
            break
        except RequestException as e:
            print("just.requests_", kwargs["url"], "attempt", tries, str(e))
            if tries == max_retries:
                err = ""
                r = None
                break
            elif refresh_session_on_error:
                request_fn = get_session_method(reuse_session, session_key, remote_ip, method, kwargs["url"])
            tries += 1
            time.sleep(delay_base**tries)

    timers[session_key] = time.time()

    url.split(".")[-1]
    # result handling
    if err is None or err == "":
        text = r.text[:500] if r is not None else ""
        if len(text) == 500:
            text += "..."
        code = r.status_code if r is not None else None
        print("ERR", code, url, text)
        tmp = err
        try:
            err = r.json()
        except:
            try:
                err = r.text
            except:
                err = ""
        r = tmp
    elif raw:
        r = r.content
    elif r is None:
        pass
    elif r is not None and r.headers and "json" in (r.headers.get("Content-Type", r.headers.get("content-type")) or ""):
        r = r.json()
    elif is_binary_extension_url(url):
        r = r.content
    else:
        r = r.text
    if use_cache and r is not None:
        result = {"resp": r, "request_info": request_info, "response_ts": time.time()}
        if err:
            result["error"] = err
        write(result, cache_file_name)
        obj_type, _ = get_obj_type(use_cache)
        obj_counts[(domain_name, obj_type)] += 1

    return r


def get(
    url,
    params=None,
    max_retries=2,
    delay_base=3,
    raw=False,
    use_cache=False,
    cache_compression=".gz",
    cache_ttl=0,
    sleep_time=None,
    fname=None,
    reuse_session=True,
    local_address=None,
    remote_ip=None,
    refresh_session_on_error=False,
    user_agent=USER_AGENT,
    **kwargs,
):
    caching = (use_cache, url, params)

    kwargs["url"] = url
    if params is not None:
        kwargs["params"] = params
    if user_agent:
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        if "User-Agent" not in kwargs["headers"]:
            kwargs["headers"]["User-Agent"] = user_agent

    result = _retry(
        "get",
        max_retries,
        delay_base,
        raw,
        caching,
        cache_compression,
        cache_ttl,
        sleep_time,
        reuse_session,
        local_address,
        remote_ip,
        refresh_session_on_error,
        kwargs,
    )

    if fname is not None:
        write(result, fname)

    return result


get.from_cache = from_cache


def warn_cache() -> None:
    warnings.warn(
        "This attribute is deprecated as boolean, it still works but advised to make a str key",
        DeprecationWarning,
        stacklevel=2,
    )


def post(
    url,
    params=None,
    data=None,
    max_retries=5,
    raw=False,
    json=None,
    delay_base=3,
    use_cache=False,
    cache_compression=".gz",
    cache_ttl=0,
    sleep_time=None,
    fname=None,
    reuse_session=True,
    local_address=None,
    remote_ip=None,
    refresh_session_on_error=False,
    user_agent=USER_AGENT,
    **kwargs,
):
    if isinstance(use_cache, bool):
        warn_cache()

    caching = (use_cache, url, params, data, json)

    kwargs["url"] = url
    if params is not None:
        kwargs["params"] = params
    if data is not None:
        kwargs["data"] = data
    if json is not None:
        kwargs["json"] = json
    if user_agent:
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        if "User-Agent" not in kwargs["headers"] and "user-agent" not in kwargs["headers"]:
            kwargs["headers"]["User-Agent"] = user_agent
    result = _retry(
        "post",
        max_retries,
        delay_base,
        raw,
        caching,
        cache_compression,
        cache_ttl,
        sleep_time,
        reuse_session,
        local_address,
        remote_ip,
        refresh_session_on_error,
        kwargs,
    )

    if fname is not None:
        write(result, fname)

    return result


def request(data, **kwargs):
    data = data.copy()
    return {"get": get, "post": post}[data.pop("method")](**data, **kwargs)


def request_tree(*args, **kwargs):
    import lxml.html
    import requests_viewer

    assert requests_viewer is not None

    html = request(*args, **kwargs)
    if html is None:
        return None
    return lxml.html.fromstring(html)


post.from_cache = from_cache


def get_tree(*args, **kwargs):
    import lxml.html
    import requests_viewer

    assert requests_viewer is not None

    return lxml.html.fromstring(get(*args, **kwargs))


def post_tree(*args, **kwargs):
    import lxml.html

    return lxml.html.fromstring(post(*args, **kwargs))


def save_session(name, session) -> None:
    from requests.utils import dict_from_cookiejar

    if any("Session" in x.__name__ for x in session.__class__.__mro__):
        try:
            print("trf")
            session.transfer_driver_cookies_to_session()
        except Exception as e:
            print("ERR", e)
        session = {"headers": session.headers, "cookies": dict_from_cookiejar(session.cookies)}
    write(session, "~/.just_sessions/" + name + ".json")
