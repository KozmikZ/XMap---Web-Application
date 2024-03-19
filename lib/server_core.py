from lib.xmap.scan_core import ScanCore
from lib.xmap.scan_core import ScanType

class ServerCore: # Handling all server queries and operations
    def __init__(self) -> None:
        self.scan_cache : dict[int,ScanCore]= {} # The cache of all scans in the current session, so that the browser knows which Scan to touch based on a given id
    
    def _scan_any(self, type : ScanType,target : str, args = []) -> int:
        id: int
        if len(self.scan_cache)==0: # first in hashmap?
            id = 0
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id,type,target,args)
        self.scan_cache[scan.id]=scan
        return scan.id
    
    def quick_scan(self,target:str) -> int:
        # performs a quick scan on the server
        return self._scan_any(ScanType.QUICK,target)
    
    def deep_scan(self,target : str) -> int: 
        # performs a deep scan on the server
        return self._scan_any(ScanType.DEEP,target)
    
    def manual_scan(self,target:str,cdepth:int,sdepth:int,brute:bool) -> int: 
        # performs a custom scan on the server
        return self._scan_any(ScanType.MANUAL,target,[cdepth,sdepth,brute])
    
    def get_running_scan(self,id:int) -> ScanCore | None: 
        # returns the scan with this cached id
        return self.scan_cache.get(id)