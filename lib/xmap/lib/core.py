import requests
import re
from selenium import webdriver
from lib.xmap.lib.url import Url
from lib.xmap.lib.utils import rndhead,get_url_parameters
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from lib.xmap.lib.vulnerability import Vulnerability
from lib.xmap.lib.vulnerability import VulnerabilityType
CGREEN  = '\33[32m' # terminal color pallete
CRED = '\033[91m'
CEND = '\033[0m'
OKBLUE = '\033[94m'
BOLD = '\033[1m'
MAX_TOLERANCE = 30 # tolerance of unaccepted requests
LOCATOR_STRING = "sL3a" # used to locate reflected payloads with regex
TERMINATOR_STRING ="4jQn"

"""The following are functions generally useful for both scanners"""

def pops_alert(url:str,driver:webdriver.Firefox,payload:str)->bool:
    """
    Opens a url in a webdriver and then checks if it can switch its focus to the alert box
    If there is no alert/prompt box, an exception raised and pops_alert returns False
    """
    try:
        driver.get(url)
    except:
        return False
    try: # try to check for an alert, an exception will be raised if no alert is found
        al = driver.switch_to.alert 
        al.dismiss() # to enable more browser get requests
        return True
    except: # no alert found ... testing a different method
        click_triggered = re.findall(r"(onmouseover|onclick|onfocus)",payload) # trying if it is perhaps user triggered
        if click_triggered!=None and payload[0]=="<": # if payload is trigger based and is an html element, not a direct script injection, click it!
            for el in driver.find_elements(by=By.CSS_SELECTOR,value="*"):
                try: # if no alert is present or a different sElEniUUm error occurs 
                    if el.text=="test":
                            el.click()
                            al = driver.switch_to.alert
                            al.dismiss() # to enable more browser get requests
                            return True
                except:
                    pass
        return False

def reflects(url:str,p:str)->bool: 
    # test if any parameter reflects on site:
    url : Url = Url(url)
    url.inject(p,"rXn4rT") # injecting the payload into the url
    resp = requests.get(url.__repr__(),headers={"User-Agent":rndhead()})
    reflections = re.finditer(string=str(resp.content),pattern=r"rXn4rT")# find the terminator and locator strings and whatever is in between
    return len(list(reflections))!=0
 

def setup_firefox_driver(): 
    # setting up the webdriver, so we dont have to reopen it everytime a payload is tested
    options = Options() 
    options.add_argument('--headless')
    options.add_argument("--incognito")
    try:
        geckodriver_path = "/snap/bin/geckodriver"  # specify the path to your geckodriver -> unfortunately have to do that since it cannot find it otherwise (firefox is installed with snap, selenium is not used to that)
        driver_service = Service(executable_path=geckodriver_path)
        driver = webdriver.Firefox(options=options,service=driver_service) 
    except:
        driver = webdriver.Firefox(options=options)        
    return driver

def brute_force_page(url:str,p,payloads:list[str],driver:webdriver.Firefox)->dict[VulnerabilityType,list[Vulnerability]]:
    rxss_vulns : dict[VulnerabilityType,list[Vulnerability]] = {
        VulnerabilityType.POTENTIAL:[],
        VulnerabilityType.SERIOUS:[]
        }
    for payload in payloads:
        url.inject(p,payload)
        if pops_alert(str(url),driver,payload):
            rxss_vulns[VulnerabilityType.SERIOUS].append(Vulnerability(p,str(url),payload,type=VulnerabilityType.SERIOUS))
        else:
            rxss_vulns[VulnerabilityType.POTENTIAL].append(Vulnerability(p,str(url),payload,type=VulnerabilityType.POTENTIAL))
    return rxss_vulns

class ServerScanner:
    @staticmethod
    def scan_url_parameter(url:str,p,depth:int=None)->list[Vulnerability]: 
        # returns all working rxss links for a given parameter and url
        """
        I use the payload list file to test every payloads reflection (depending on the depth, a number of payloads is tested)
        I then check for exact reflections in the site, those not tampered with by the back-end/front-end
        After I'm finished, I test every perfectly reflected payload for a popup window. If such window is detected, the software has found a vulnerability
        """

        # test if parameter reflects on site:
        if not reflects(url,p):
            return []
        url = Url(url)
        vulnerable_to_payloads : list[str]= [] # only possible reflections, not tested yet, the software needs to examine these reflections
        tolerance=0
        with open("lib/xmap/lib/payloads/payload_list.txt","r") as p_fi:
            
            payload_list = p_fi.readlines()
            if depth==None:
                depth = len(payload_list)
            else:
                ln = len(payload_list)
                if depth>ln:
                    raise BaseException("Error: brute force depth exceeded payload list length")
            
            for payload in payload_list[:depth]:
                payload = payload[:-1] # removing \n to prevent it getting injected

                url.inject(p,LOCATOR_STRING+payload+TERMINATOR_STRING) # injecting the payload into the url
                resp = requests.get(url.__repr__(),headers={"User-Agent":rndhead()})
                reflections,status = re.finditer(string=str(resp.content),pattern=r"sL3a.*?4jQn"),resp.status_code # find the terminator and locator strings and whatever is in between

                if status==200:
                    tolerance=0
                    r_list =list(reflections) # necessary to obtain match objects
                    r_count = len(r_list)
                    if r_count!=0:
                        perfect= False # perfect reflection boolean, prevents clogging the vulnerable_to_payloads list
                        for r in r_list:
                            st,en = r.span() # start and end of the reflection
                            str_reflection = str(resp.content)[st+4:en-4] # the reflection string                
                            if str_reflection==payload:
                                perfect = True
                        if perfect:
                            vulnerable_to_payloads.append(payload)
                else:
                    tolerance+=1
                    if tolerance>MAX_TOLERANCE:
                        return []

        driver = setup_firefox_driver()
        vulns = brute_force_page(url,p,vulnerable_to_payloads,driver)
        driver.quit()
        s_v = vulns[VulnerabilityType.SERIOUS]
        p_v = vulns[VulnerabilityType.POTENTIAL]
        s_v.extend(p_v)
        return s_v
    @staticmethod
    def scan_url_parameter_brute(url:str,p:str,depth:int)->list[Vulnerability]:
        # returns all the urls of type serious found by the brute scan
        if not reflects(url,p):
            return []
        
        url:Url = Url(url)
        driver = setup_firefox_driver()  
        test_payloads = open("lib/xmap/lib/payloads/payload_list.txt","r").readlines()

        rxss_vulns = brute_force_page(url,p,test_payloads[:depth],driver)
        driver.quit()
        return rxss_vulns[VulnerabilityType.SERIOUS]
    @staticmethod
    def scan_url_whole(url:str,depth:int=100) -> list[Vulnerability]: 
        # scan all parameters of a url
        params = get_url_parameters(url)
        all_xss_vulns = []
        for p in params:
            all_xss_vulns.extend(ServerScanner.scan_url_parameter(url,p,depth=depth))
        return all_xss_vulns
    @staticmethod  
    def scan_url_whole_brute(url:str,depth:int=100) -> list[Vulnerability]: # brute scan all parameters of a url
        params = get_url_parameters(url)
        all_xss_vulns: list = []
        for p in params:
            all_xss_vulns.extend(ServerScanner.scan_url_parameter_brute(str(url),p,depth=depth))
        return all_xss_vulns


class ConsoleScanner: # The console scanner has a bit of a different architecture than the Server scanner
    @staticmethod
    def scan_url_parameter(url:str,p,depth:int | None=None,manual:bool=False,verbose:bool=False,payload_list_path:str="lib/xmap/lib/payloads/payload_list.txt")->list[str]: # returns all working rxss links for a given parameter and url
        """
        I use the payload list file to test every payloads reflection (depending on the depth, a number of payloads is tested)
        I then check for exact reflections in the site, those not tampered with by the back-end/front-end
        After I'm finished, I test every perfectly reflected payload for a popup window. If such window is detected, the software has found a vulnerability
        """
        print(f"Scanning parameter {BOLD+CGREEN+p+CEND} in website: {BOLD+CGREEN+str(url)+CEND}")

        # first test if parameter reflects on site:
        if not reflects(url,p):
            return []

        url = Url(url)
        vulnerable_to_payloads = [] # only possible reflections, not tested yet, the software needs to examine these reflections
        tolerance=0
        with open(payload_list_path,"r") as p_fi:
            dbg_c = 0
            locator_string = "sL3a" # used to locate reflected payloads with regex
            terminator_string="4jQn"
            stop=False
            payload_list = p_fi.readlines()

            if depth is not None:
                depth = len(payload_list)
            else:
                ln = len(payload_list)
                if depth>ln:
                    raise BaseException("Error: brute force depth exceeded payload list length")
            for payload in payload_list[:depth]:
                if stop:
                    break
                dbg_c+=1
                payload = payload[:-1] # removing \n to prevent it getting injected
                if verbose:
                    print(f"Testing payload: {CGREEN + payload + CEND}") # verbose log

                url.inject(p,locator_string+payload+terminator_string) # injecting the payload into the url
                resp = requests.get(url.__repr__(),headers={"User-Agent":rndhead()})
                reflections,status = re.finditer(string=str(resp.content),pattern=r"sL3a.*?4jQn"),resp.status_code # find the terminator and locator strings and whatever is in between
                

                if verbose==False and dbg_c%100 == 0 :
                    print(f"Tested {CGREEN+str(dbg_c)+CEND} payloads...")
                elif verbose==True and dbg_c%10 == 0:
                    print(f"Tested {CGREEN+str(dbg_c)+CEND} payloads...")

                if status==200:
                    tolerance=0
                    r_list =list(reflections) # necessary to obtain match objects
                    r_count = len(r_list)
                    if r_count!=0:
                        perfect= False # perfect reflection boolean, prevents clogging the vulnerable_to_payloads list
                        for r in r_list:
                            st,en = r.span() # start and end of the reflection
                            str_reflection = str(resp.content)[st+4:en-4] # the reflection string
                            if str_reflection==payload:
                                if verbose:
                                    print(CGREEN+f"Found possible XSS reflection for parameter {BOLD+p}"+CEND) # verbose log
                                    print(OKBLUE+f"With payload " + CRED + payload +CEND)
                                    if manual:
                                        if input("Do you want to test payloads now?[y/n]")=="y":
                                            stop=True
                                perfect = True
                        if perfect:
                            vulnerable_to_payloads.append(payload)
                else:
                    print(CRED+f"Issue? when testing payload {payload}. Network or Security..."+CEND)
                    tolerance+=1
                    if tolerance>MAX_TOLERANCE and manual==False:
                        print("Site is most likely blocking our requests...")
                        print("Basic tests failed")
                        return [] 
                    elif tolerance>MAX_TOLERANCE and manual==True:
                        if input("Do you want to continue scanning, site looks to be blocking our requests. [y/n]")=="y":
                            tolerance=0
                        else:
                            return []     
                    
            driver = setup_firefox_driver()
            rxss_vulns: list[Vulnerability] = []

            print(f"Found {len(vulnerable_to_payloads)} reflections")
            print("Analyzing...")

            for payload in vulnerable_to_payloads:
                url.inject(p,payload)
                if pops_alert(str(url),driver,payload):
                    print(CRED+BOLD+"FOUND AND CONFIRMED XSS VULNERABILITY, PAYLOAD:"+CEND)
                    print(OKBLUE+BOLD+payload+CEND)
                    print("Link: "+CGREEN+str(url)+CEND)
                    if manual and input("Continue scanning?[y/n]")=="n":
                        return rxss_vulns
                    rxss_vulns.append(Vulnerability(p,str(url),payload,VulnerabilityType.SERIOUS))
            driver.quit()

        if len(rxss_vulns)==0:
            print("No XSS payloads confirmed")

        return rxss_vulns
    @staticmethod
    def scan_url_parameter_brute(url:str,p,depth:int,manual:bool=False,verbose:bool=False,payload_list_path:str="lib/xmap/lib/payloads/payload_list.txt")->list[str]:
        print(f"Testing THOROUGHLY for parameter {BOLD+CGREEN+p+CEND} in website: {BOLD+CGREEN+str(url)+CEND}")
        print("Warning! This method does not check for the site responses, therefore does not prevent the site from banning your IP")
        url:Url = Url(url)

        driver = setup_firefox_driver()
        rxss_vulns: list[str] = []

        test_payloads = open(payload_list_path,"r").readlines()
        payloads_tested = 0

        for payload in test_payloads[:depth]:
            payload=payload[:-1]
            payloads_tested+=1
            url.inject(p,payload)
            if verbose==True:
                print(f"Testing {CGREEN+str(url)+CEND}")
            if payloads_tested%10==0:
                print(f"Tested {CGREEN+str(payloads_tested)+CEND} payloads")
            if pops_alert(str(url),driver,payload):
                print(CRED+BOLD+"FOUND AND CONFIRMED XSS VULNERABILITY, PAYLOAD:"+CEND)
                print(OKBLUE+BOLD+payload+CEND)
                print("Link: "+CGREEN+str(url)+CEND)
                if manual and input("Continue scanning?[y/n]")=="n":
                    return rxss_vulns
                rxss_vulns.append(Vulnerability(p,str(url),payload,VulnerabilityType.SERIOUS))
        driver.quit()
        if len(rxss_vulns)==0:
            print("No XSS payloads confirmed")
        return rxss_vulns

    
        



