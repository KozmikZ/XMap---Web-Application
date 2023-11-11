from lib.xmap.lib.core import scan_url_parameter,scan_url_parameter_brute
from lib.xmap.lib.crawl import crawl_through
from lib.xmap.lib.vulnerability import Vulnerability

# TODO possible way to communicate with the server would be by use of a server state update method and passing the server object

class ScanCore: # A single object abstraction for a given scan, since it needs to be communicating with the server as it goes
    def __init__(self,server) -> None:
        self.metadata = {}
        self.status = "ongoing" # An enum would help with handling this variable
        self.vulns: list[Vulnerability] = []
        self.server = server
    def quick_scan(self,target:str):
        self._attack_target_crawl(target_url=target)
    def _attack_target_crawl(self,target_url:str,cdepth=20,sdepth=40,brute=False):
        attack_vectors = crawl_through(target_url,cdepth)
        if brute:
            for url in attack_vectors:
                self.vulns = [*self.vulns,*scan_url_parameter_brute(url,depth=sdepth)] # a very wrong and twisted code, kind of like shooting someones balls
        else:
            for url in attack_vectors:
                self.vulns = [*self.vulns,*scan_url_parameter(url,depth=sdepth)] # a very wrong and twisted code, kind of like shooting someones balls
        return self.vulns
    def deep_scan(target:str): # a deeper scan, perhaps with manual aspects, idk right now TODO
        ...
