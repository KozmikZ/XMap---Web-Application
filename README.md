# An open source web&console-based cross site scripting detection suite.
### *XMAP* is a reflected *XSS* detection tool that exists both in the browser, and in the terminal. 
## Command Line Interface Documentation

The most basic form of the command entered is as follows:
```bash
python3 cli.py -t "URL"
```
This command performs the most ordinary scan of a website for all URL parameters. The "t" parameter here represents "target," and for XMAP, it's the only necessary parameter in the case of a quick scan. XMAP will find the most important confirmed vulnerabilities in the fastest way and report to the user.

**Alternatively**, the tool can be run with the "b" parameter:

```bash
python3 cli.py -t "URL" -b
```
In this case, the tool performs a so-called *brute force scan* and tries every payload fully. This leads to a longer scanning time and better quality results.

In case it is necessary to scan the entire web application and its paths, the **c** parameter (crawl) must be used. With the "c" parameter, the user is automatically forced to use the -l (level) parameter or define the depth of the scan firmly. An example command is:
```bash
python3 cli.py -t "URL" -c -l 2
```

This command scans the page and its paths at level 2. This means it goes through 250 payloads and crawls up to 30 different paths.
### Additional arguments:
    -m = manual scan, during which the command line requires user input.
    -v = verbosity setting
    -p = specifying a specific parameter that XMAP should test on a specific page.
    --scan_depth, --crawl_depth = allow the user to manually set the depth of scans
    --log = path to the log file into which XMAP should write both results and the scanning process
    --payload_list = path to the file of payloads that the user wants to use for their scan. If this argument is not specified, the basic one is used.
    
## 2.2 Web Application Documentation
In the case of a web application, the user has several options for using it. The simplest way to launch the application is to download the Git repository and start it in a local web environment using the command:
```bash
flask run
```
This command is executed within the Git repository's directory. Afterward, simply navigate to the address specified by Flask to find XMAP.









