from lib.xmap.scan_core import ScanCore
from lib.xmap.scan_core import ScanType
import asyncio
import threading

class ServerCore: # Handling all server queries and operations
    def __init__(self) -> None:
        self.scan_cache = {}
    def quick_scan(self,target:str):
        id: int
        if len(self.scan_cache)==0:
            id = 0
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id,ScanType.quick,target)
        self.scan_cache[scan.id]=scan
        return scan.id
    def deep_scan(self,target:str) -> int:
        id : int
        if len(self.scan_cache)==0:
            id = 0
        else:
            id = max(self.scan_cache.keys())+1
        scan = ScanCore(self,id,ScanType.deep,target)
        self.scan_cache[scan.id]=scan
        return scan.id
    def manual_scan(self,target:str,**args):
        ...
    def get_running_scan(self,id:int): # returns the scan with this cached id
        return self.scan_cache[id]