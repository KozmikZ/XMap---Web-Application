from lib.xmap.scan_core import ScanCore
import asyncio
class ServerCore: # Handling all server queries and operations
    def __init__(self) -> None:
        self.scan_cache = {}
    async def q_scan(self,target:str):
        scan = ScanCore(self)
        await scan.quick_scan(target)