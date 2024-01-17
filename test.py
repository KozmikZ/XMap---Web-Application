from lib.xmap.lib.core import ServerScanner


print(ServerScanner.scan_url_whole("http://sudo.co.il/xss/level0.php?email=2#"))