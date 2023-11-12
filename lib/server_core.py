from lib.xmap.scan_core import ScanCore
import asyncio
import threading

class ServerCore: # Handling all server queries and operations
    def __init__(self) -> None:
        self.scan_cache = {}
    def q_scan(self,target:str):
        id: int
        if len(self.scan_cache)==0:
            id = 0
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id)
        scan_job = threading.Thread(target=scan.quick_scan,args=[target,]) # skinjob :*
        scan_job.start()
        self.scan_cache[scan.id]=scan
        return scan.id
    def get_running_scan(self,id:int): # returns the scan with this cached id
        return self.scan_cache[id]