from lib.xmap.scan_core import ScanCore
from lib.xmap.scan_core import ScanType

class ServerCore: # Handling all server queries and operations
    def __init__(self) -> None:
        self.scan_cache = {} # The cache of all scans in the current session, so that the browser knows which Scan to touch based on a given id
    def quick_scan(self,target:str) -> int:
        id: int
        if len(self.scan_cache)==0: # first in hashmap?
            id = 0
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id,ScanType.quick,target)
        self.scan_cache[scan.id]=scan
        return scan.id
    # tries a deep scan on the server
    def deep_scan(self,target:str) -> int: 
        id : int
        if len(self.scan_cache)==0: # first in hashmap?
            id = 0 
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id,ScanType.deep,target)
        self.scan_cache[scan.id]=scan
        return scan.id
    # tries a manual scan on the server
    def manual_scan(self,target:str,cdepth:int,sdepth:int,brute:bool): 
        id : int
        if len(self.scan_cache)==0: # first in hashmap?
            id = 0
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id,ScanType.manual,target,[cdepth,sdepth,brute])
        self.scan_cache[scan.id]=scan
        return scan.id
    # returns the scan with this cached id
    def get_running_scan(self,id:int): 
        return self.scan_cache.get(id)