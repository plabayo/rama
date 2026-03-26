import lxml.html.diff
import lxml.html
from bs4 import UnicodeDammit
import re
import requests
import time
import webbrowser
import tempfile


def slugify(value):
    return re.sub(r'[^\w\s-]', '', re.sub(r'[-\s]+', '-', value)).strip().lower()


def view_request(r, domain=None):
    if domain is None:
        domain = extract_domain(r.url)
    view_tree(make_tree(r.content, domain))


def view_html(x):
    with tempfile.NamedTemporaryFile(mode="w", suffix='.html', delete=False) as f:
        f.write(x)
        f.flush()
        webbrowser.open('file://' + f.name)
        time.sleep(1)


def view_node(node, attach_head=False, question_contains=None):
    newstr = make_parent_line(node, attach_head, question_contains)
    view_tree(newstr)


def view_tree(node):
    view_html(lxml.html.tostring(node).decode('utf8'))


def view_diff_tree(tree1, tree2, url='', diff_method=lxml.html.diff.htmldiff):
    html1 = lxml.html.tostring(tree1).decode('utf8')
    html2 = lxml.html.tostring(tree2).decode('utf8')
    view_diff(html1, html2, tree1, tree2, url, diff_method)


def view_diff_html(html1, html2, url='', diff_method=lxml.html.diff.htmldiff):
    tree1 = lxml.html.fromstring(html1)
    tree2 = lxml.html.fromstring(html2)
    view_diff(html1, html2, tree1, tree2, url, diff_method)


def view_diff(html1, html2, tree1, tree2, url='', diff_method=lxml.html.diff.htmldiff):
    diff_html = diff_method(tree1, tree2)
    diff_tree = lxml.html.fromstring(diff_html)
    ins_counts = diff_tree.xpath('count(//ins)')
    del_counts = diff_tree.xpath('count(//del)')
    pure_diff = ''
    for y in [z for z in diff_tree.iter() if z.tag in ['ins', 'del']]:
        if y.text is not None:
            color = 'lightgreen' if 'ins' in y.tag else 'red'
            pure_diff += '<div style="background-color:{};">{}</div>'.format(color, y.text)
    print('From t1 to t2, {} insertions and {} deleted'.format(ins_counts, del_counts))
    diff = '<head><title>diff</title><base href="' + url
    diff += '" target="_blank"><style>ins{ background-color:lightgreen; } '
    diff += 'del{background-color:red;}</style></head>' + diff_html
    view_html(diff)
    view_html(html1)
    view_html(html2)
    view_html('<html><body>{}</body></html>'.format(str(pure_diff)))


def make_parent_line(node, attach_head=False, question_contains=None):
    # Add how much text context is given. e.g. 2 would mean 2 parent's text
    # nodes are also displayed
    if question_contains is not None:
        newstr = does_this_element_contain(question_contains, lxml.html.tostring(node))
    else:
        newstr = lxml.html.tostring(node)
    parent = node.getparent()
    while parent is not None:
        if attach_head and parent.tag == 'html':
            newstr = lxml.html.tostring(parent.find(
                './/head'), encoding='utf8').decode('utf8') + newstr
        tag, items = parent.tag, parent.items()
        attrs = " ".join(['{}="{}"'.format(x[0], x[1]) for x in items if len(x) == 2])
        newstr = '<{} {}>{}</{}>'.format(tag, attrs, newstr, tag)
        parent = parent.getparent()
    return newstr


def extract_domain(url):
    import tldextract
    tld = ".".join([x for x in tldextract.extract(url) if x])
    protocol = url.split('//', 1)[0]
    if protocol == 'file:':
        protocol += '///'
    else:
        protocol += '//'
    return protocol + tld


def does_this_element_contain(text='pagination', node_str=''):
    templ = '<div style="border:2px solid lightgreen">'
    templ += '<div style="background-color:lightgreen">'
    templ += 'Does this element contain <b>{}</b>?'
    templ += '</div>{}</div>'
    return templ.format(text, node_str)


def make_tree(html, domain=None):

    ud = UnicodeDammit(html, is_html=True)

    tree = lxml.html.fromstring(ud.unicode_markup)

    if domain is not None:
        tree.make_links_absolute(domain)

    for el in tree.iter():

        # remove comments
        if isinstance(el, lxml.html.HtmlComment):
            el.getparent().remove(el)
            continue

        if el.tag == 'script':
            el.getparent().remove(el)
            continue

    return tree


def get_tree(url, domain=None):
    r = requests.get(url, headers={
        'User-Agent': 'Mozilla/5.0 ;Windows NT 6.1; WOW64; Trident/7.0; rv:11.0; like Gecko'})
    if domain is None:
        domain = extract_domain(url)
    return make_tree(r.text, domain)


def get_html(url, domain=None):
    return lxml.html.tostring(get_tree(url, domain)).decode("utf8")


def get_local_tree(url, domain=None):
    if domain is None:
        domain = extract_domain(url)
    with open(url) as f:
        html = f.read()
    return make_tree(html, domain)


def normalize(s):
    return re.sub(r'\s+', lambda x: '\n' if '\n' in x.group(0) else ' ', s).strip()


def get_text_and_tail(node):
    text = node.text if node.text else ''
    tail = node.tail if node.tail else ''
    return text + ' ' + tail
