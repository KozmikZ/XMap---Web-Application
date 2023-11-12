from lib.xmap.lib.core import scan_url_whole,scan_url_whole_brute
from lib.xmap.lib.crawl import crawl_through
from lib.xmap.lib.vulnerability import Vulnerability
from enum import Enum


    
# TODO possible way to communicate with the server would be by use of a server state update method and passing the server object

class ScanCore: # A single object abstraction for a given scan, since it needs to be communicating with the server as it goes
    def __init__(self,server,id) -> None:
        self.metadata = {} # oop is objectively ugly and bad
        self.finished = False 
        self.vulns: list[Vulnerability] = []
        self._server = server
        self.id = id
    def quick_scan(self,target:str):
        self._attack_target_single(target_url=target)
        self.finished = True
    def _attack_target_single(self,target_url:str,sdepth=40,brute=False):
        if brute: # this code is starting to look like shit...
            self.vulns.extend(scan_url_whole_brute(target_url,depth=sdepth))
        else:
            self.vulns.extend(scan_url_whole(target_url,depth=sdepth))
    def _attack_target_crawl(self,target_url:str,cdepth=20,sdepth=40,brute=False):
        attack_vectors = crawl_through(target_url,cdepth)
        if brute:
            for url in attack_vectors:
                self.vulns.extend(scan_url_whole_brute(url,depth=sdepth))
        else:
            for url in attack_vectors:
                self.vulns.extend(scan_url_whole(url,depth=sdepth))
        return self.vulns
    def deep_scan(target:str): # a deeper scan, perhaps with manual aspects, idk right now TODO
        ...
    def to_json(self) -> dict:
        json_vulns = []
        for v in self.vulns:
            json_vulns.append(v.json())
        return {"metadata":self.metadata,"vulns":json_vulns,"finished":self.finished}

def scan_test(): # function to appeal to testing driven development because I am a loser and need to get rid of women
    test = ScanCore(None)
    test.quick_scan("http://sudo.co.il/xss/level5-2.php?p=test")
    print(test.vulns)
    for x in test.vulns:
        print(x.json())