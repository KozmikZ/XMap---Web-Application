from lib.xmap.lib.core import scan_url_whole,scan_url_whole_brute
from lib.xmap.lib.crawl import crawl_through
from lib.xmap.lib.vulnerability import Vulnerability
from datetime import datetime as dt
import functools
import json
    
# TODO possible way to communicate with the server would be by use of a server state update method and passing the server object

class ScanCore: # A single object abstraction for a given scan, since it needs to be communicating with the server as it goes
    def __init__(self,server,id) -> None:
        self.metadata = {} # oop is objectively ugly and bad
        self.scanned_targets : int= 0
        self.finished = False 
        self.vulns: list[Vulnerability] = []
        self._server = server
        self.id = id
    def get_metadata(func): # a wrapper that sets up metadata about runtime within the object
        @functools.wraps(func)
        def wrap(self,*args,**kwargs): # started, ended timestamps, then computes runtime, saves metadata in json
            started = dt.now()
            self.metadata["started"]=str(started)
            func(self,*args,**kwargs)
            ended = dt.now()
            self.metadata["ended"]=str(ended)
            self.metadata["runtime"]=str(ended-started)
            self.finished=True
        return wrap
    @get_metadata
    def quick_scan(self,target:str):
        self._attack_target_crawl(target_url=target)
    def _attack_target_single(self,target_url:str,sdepth=40,brute=False):
        if brute: # this code is starting to look like shit...
            self.vulns.extend(scan_url_whole_brute(target_url,depth=sdepth))
        else:
            self.vulns.extend(scan_url_whole(target_url,depth=sdepth))
        self.scanned_targets+=1
    def _attack_target_crawl(self,target_url:str,cdepth=20,sdepth=40,brute=False):
        attack_vectors = crawl_through(target_url,cdepth)
        if brute:
            for url in attack_vectors:
                self.vulns.extend(scan_url_whole_brute(url,depth=sdepth))
                self.scanned_targets+=1
        else:
            for url in attack_vectors:
                self.vulns.extend(scan_url_whole(url,depth=sdepth))
                self.scanned_targets+=1
        return self.vulns
    @get_metadata
    def deep_scan(self,target:str):
        self._attack_target_crawl(target,cdepth=60,sdepth=250,brute=True)
    def manual_scan(self,target:str,cdepth:int,sdepth:int,brute:bool):
        ...
    def to_json(self) -> dict:
        json_vulns: list = []
        for v in self.vulns:
            json_vulns.append(v.json())
        return {"metadata":self.metadata,"vulns":json_vulns,"finished":self.finished, "scanned_targets":self.scanned_targets}

def scan_test(): # function to appeal to testing driven development because I am a loser and need to get rid of women
    test = ScanCore(None)
    test.quick_scan("http://sudo.co.il/xss/level5-2.php?p=test")
    print(test.vulns)
    for x in test.vulns:
        print(x.json())