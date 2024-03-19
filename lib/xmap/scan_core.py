from lib.xmap.lib.core import ServerScanner
from lib.xmap.lib.crawl import crawl_through
from lib.xmap.lib.vulnerability import Vulnerability
from datetime import datetime as dt
import functools
from enum import Enum
import threading

class ScanType(Enum):
    DEEP = "DEEP"
    MANUAL = "MANUAL"
    QUICK = "QUICK"


class ScanCore: # A single object abstraction for a given scan, since it needs to be communicating with the server as it goes
    def __init__(self,server,id:int,type:ScanType,target:str,params:list=[]) -> None:
        self.params = params # parameters for a MANUAL scan
        self.metadata : dict[str,str] = {} # oop is objectively ugly and bad
        self.scanned_targets : int= 0
        self.finished = False 
        self.vulns: list[Vulnerability] = []
        self._server = server
        self.id = id
        self.type = type
        self.target = target
        self.start_scan()
        
    def start_scan(self): 
        # the first function that is always called in the initializer of every ScanCore object, that decides which scan is to be run
        if self.type == ScanType.DEEP:
            deep_job = threading.Thread(target=self._deep_scan,args=[self.target,])
            deep_job.start()
        elif self.type == ScanType.MANUAL:
            manual_job = threading.Thread(target=self._manual_scan,args=[self.target,*self.params])
            manual_job.start()
        elif self.type == ScanType.QUICK:
            quick_job = threading.Thread(target=self._quick_scan,args=[self.target,])
            quick_job.start()
    
    def get_metadata(func): 
        # a wrapper that sets up metadata about runtime within the object
        @functools.wraps(func)
        def wrap(self,*args,**kwargs): 
            # start, end timestamps, then computes runtime, saves metadata in json
            started = dt.now()
            self.metadata["started"]=str(started)
            func(self,*args,**kwargs)
            ended = dt.now()
            self.metadata["ended"]=str(ended)
            self.metadata["runtime"]=str(ended-started)
            self.finished=True
        return wrap
    
    @get_metadata
    def _quick_scan(self,target:str): 
        # a simple scan with a low crawl and scan depth
        self._attack_target_crawl(target_url=target)
    
    def _attack_target_single(self,target_url:str,sdepth=40,brute=False): 
        # the executed attack on a single target
        if brute:
            self.vulns.extend(ServerScanner.scan_url_whole_brute(target_url,depth=sdepth))
        else:
            self.vulns.extend(ServerScanner.scan_url_whole(target_url,depth=sdepth))
        self.scanned_targets+=1
    
    def _attack_target_crawl(self,target_url:str,cdepth=10,sdepth=80,brute=False): 
        # executed attack on multiple targets gathered with crawling
        attack_vectors = crawl_through(target_url,cdepth)
        if brute:
            for url in attack_vectors:
                self.vulns.extend(ServerScanner.scan_url_whole_brute(url,depth=sdepth))
                self.scanned_targets+=1
        else:
            for url in attack_vectors:
                self.vulns.extend(ServerScanner.scan_url_whole(url,depth=sdepth))
                self.scanned_targets+=1
        return self.vulns
    
    @get_metadata
    def _deep_scan(self,target:str): 
        self._attack_target_crawl(target,cdepth=60,sdepth=250,brute=True)
    
    @get_metadata
    def _manual_scan(self,target:str,cdepth:int,sdepth:int,brute:bool): 
        # a parameter defined scan
        attack_vectors = crawl_through(target,cdepth)
        for url in attack_vectors:
            if brute:
                self.vulns.extend(ServerScanner.scan_url_whole_brute(url,sdepth))
            else:
                self.vulns.extend(ServerScanner.scan_url_whole(url,sdepth))
            self.scanned_targets+=1
        return self.vulns
    
    def to_json(self) -> dict:
        # converts this scan to a json object that can then be polled for
        json_vulns: list[Vulnerability] = []
        for v in self.vulns:
            json_vulns.append(v.json())
        return {"metadata":self.metadata,"vulns":json_vulns,"finished":self.finished, "scanned_targets":self.scanned_targets, "failed":False}
