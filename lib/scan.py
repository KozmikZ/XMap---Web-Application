from lib.xmap.lib.crawl import crawl_through
from lib.xmap.lib.core import scan_url_parameter,scan_url_parameter_brute
from lib.xmap.lib.url import Url

# What needs changing in the old codebase TODO
# First:
#   Create good way to show logs on the server, have a logging class or something that is responsible with communication with the end user
# Second:
#   Tied to this communication think of ways to do -> Manual handling...

def attack_target_crawl(target_url:str,cdepth=30,sdepth=50,brute=False,verbose=False):
    attack_vectors = crawl_through(target_url,cdepth)
    analyses = {}
    if brute:
        for url in attack_vectors:
            analyses[url]=scan_url_parameter_brute(url,depth=sdepth,verbose=verbose)
    else:
        for url in attack_vectors:
            analyses[url]=scan_url_parameter(url,depth=sdepth,verbose=verbose)

def attack_target(target_url:str,p=None,sdepth=50,brute=False,verbose=False):
    ...