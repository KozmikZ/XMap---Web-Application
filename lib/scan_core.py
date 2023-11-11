from lib.xmap.lib.core import scan_url_parameter,scan_url_parameter_brute
from lib.xmap.lib.crawl import crawl_through
from lib.xmap.lib.vulnerability import Vulnerability

class ScanCore: # A single object abstraction for a given scan, since it needs to be communicating with the server as it goes
    def __init__(self) -> None:
        self.metadata = {}
        self.status = "ongoing" # An enum would help with handling this variable
        self.vulns: list[Vulnerability] = []
    def quick_scan(self,target:str):
        self.attack_target_crawl(target_url=target)
    def _attack_target_crawl(target_url:str,cdepth=30,sdepth=50,brute=False,verbose=False):
        attack_vectors = crawl_through(target_url,cdepth)
        analyses = {}
        if brute:
            for url in attack_vectors:
                analyses[url]=scan_url_parameter_brute(url,depth=sdepth,verbose=verbose)
        else:
            for url in attack_vectors:
                analyses[url]=scan_url_parameter(url,depth=sdepth,verbose=verbose)
    def deep_scan(target:str):
        ...
