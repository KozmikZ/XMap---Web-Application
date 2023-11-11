import urllib3
import re
from selenium import webdriver
from lib.xmap.lib.url import Url
from lib.xmap.lib.utils import rndhead,get_url_parameters
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from lib.xmap.lib.vulnerability import Vulnerability

def pops_alert(url:str,driver:webdriver.Firefox,payload:str)->bool:
    """
    Opens a url in a webdriver and then checks if it can switch its focus to the alert box
    If there is no alert/prompt box, an exception raised and pops_alert returns False
    """
    driver.get(url)
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




def scan_url_parameter(url:str,p,depth:int=None)->list[Vulnerability]: # returns all working rxss links for a given parameter and url
    """
    I use the payload list file to test every payloads reflection (depending on the depth, a number of payloads is tested)
    I then check for exact reflections in the site, those not tampered with by the back-end/front-end
    After I'm finished, I test every perfectly reflected payload for a popup window. If such window is detected, the software has found a vulnerability
    """

    # first test if parameter reflects on site:
    url:Url = Url(url)
    url.inject(p,"rnT3xqw") # injecting the payload into the url
    resp = urllib3.request("GET",url.__repr__(),headers={"User-Agent":rndhead()})
    reflections = re.finditer(string=str(resp.data),pattern=r"rnT3xqw")
    if len(list(reflections))==0:
        return []

    
    vulnerable_to_payloads = [] # only possible reflections, not tested yet, the software needs to examine these reflections
    tolerance=0
    with open("lib/xmap/lib/payloads/payload_list.txt","r") as p_fi:
        dbg_c = 0
        locator_string = "sL3a" # used to locate reflected payloads with regex
        terminator_string="4jQn"
        stop=False
        payload_list = p_fi.readlines()

        if depth==None:
            depth = len(payload_list)
        else:
            ln = len(payload_list)
            if depth>ln:
                raise "Error: brute force depth exceeded payload list length"
        for payload in payload_list[:depth]:
            if stop:
                break
            dbg_c+=1
            payload = payload[:-1] # removing \n to prevent it getting injected

            url.inject(p,locator_string+payload+terminator_string) # injecting the payload into the url
            resp = urllib3.request("GET",url.__repr__(),headers={"User-Agent":rndhead()})
            reflections,status = re.finditer(string=str(resp.data),pattern=r"sL3a.*?4jQn"),resp.status # find the terminator and locator strings and whatever is in between
            

            if status==200:
                tolerance=0
                r_list =list(reflections) # necessary to obtain match objects
                r_count = len(r_list)
                if r_count!=0:
                    perfect= False # perfect reflection boolean, prevents clogging the vulnerable_to_payloads list
                    for r in r_list:
                        st,en = r.span() # start and end of the reflection
                        str_reflection = str(resp.data)[st+4:en-4] # the reflection string
                        if str_reflection==payload:
                            perfect = True
                    if perfect:
                        vulnerable_to_payloads.append(payload)
            else:
                tolerance+=1
                if tolerance>100:
                    return []
        options = Options() # setting up the webdriver, so we dont have to reopen it everytime the function is ran
        options.add_argument('--headless')
        options.add_argument("--incognito")
        geckodriver_path = "/snap/bin/geckodriver"  # specify the path to your geckodriver -> unfortunately have to do that since it cannot find it otherwise (firefox is installed with snap, selenium is not used to that)
        driver_service = Service(executable_path=geckodriver_path)
        driver = webdriver.Firefox(options=options,service=driver_service) 
        rxss_vulns: list[Vulnerability] = []


        for payload in vulnerable_to_payloads:
            url.inject(p,payload)
            if pops_alert(str(url),driver,payload):
                rxss_vulns.append(Vulnerability(p,str(url),payload))
        driver.quit()

    return rxss_vulns



def scan_url_parameter_brute(url:str,p:str,depth:int,manual:bool=False,verbose:bool=False)->list[str]:
    url:Url = Url(url)

    options = Options() # setting up the webdriver, so we dont have to reopen it everytime the function is ran
    options.add_argument('--headless')
    options.add_argument("--incognito")
    geckodriver_path = "/snap/bin/geckodriver"  # specify the path to your geckodriver -> unfortunately have to do that since it cannot find it otherwise (firefox is installed with snap, selenium is not used to that)
    driver_service = Service(executable_path=geckodriver_path)
    driver = webdriver.Firefox(options=options,service=driver_service) 
    rxss_vulns: list[str] = []

    test_payloads = open("lib/xmap/lib/payloads/payload_list.txt","r").readlines()
    payloads_tested = 0

    for payload in test_payloads[:depth]:
        payload=payload[:-1]
        payloads_tested+=1
        url.inject(p,payload)
        if payloads_tested%10==0:
            pass
        if pops_alert(str(url),driver,payload):
            rxss_vulns.append(Vulnerability(p,str(url),payload))
    driver.quit()
    return rxss_vulns


 
    
def scan_url_whole(url:str) -> list[Vulnerability]:
    params = get_url_parameters(url)
    total_xss_vulns = []
    for p in params:
        total_xss_vulns.append(scan_url_parameter(url,p,depth=100))
    

