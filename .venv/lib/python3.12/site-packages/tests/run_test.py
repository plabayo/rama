""" Contains py.test tests. """

from requests_viewer.main import main
from requests_viewer.web_compat import view_request


def test_integration():
    main("https://pypi.python.org/pypi/requests_viewer")
    # from requests_viewer.web import view_diff_tree, get_tree
    # url1 = "http://xkcd.com/"
    # url2 = "http://xkcd.com/1/"
    # tree1, tree2 = get_tree(url1), get_tree(url2)
    # view_diff_tree(tree1, tree2)
