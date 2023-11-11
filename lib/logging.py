# server commands... HOW TO MAKE THEM WORK?
# network_issue
# 

# What we want to show to the end user
# The site and how it's being scanned
# Attacked links and possible reflections
# The summary and metadata

# There has to be a way to communicate to the end user via the server
# This way is the logger
# There need to be types of outputs the logger produces

class Logger:
    def __init__(self) -> None:
        self.main_log = []
    def log(self,msg,server_cmd:str=None):
        logged_msg = {"msg":msg,"server_cmd":server_cmd}
        self.main_log.append(logged_msg)
        