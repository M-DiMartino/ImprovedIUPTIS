
# *******************************************************************************
# Realistically Fingerprinting Social Media Webpages in HTTPS Traffic
# Hasselt University/EDM/Flanders Make.
# Paper published by ACM ICPS, ARES 2019.
# Authors: Mariano Di Martino, Peter Quax, Wim Lamotte.
# Please cite the paper if you are using this source code.
# Licensed under Apache 2.0: see LICENSE.md
# **********************************************************************


from selenium import webdriver
import os
import subprocess
import time
import json
import selenium
import socket
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.options import Options
import sys
from subprocess import check_output
import struct



if (len(sys.argv) < 2):
    print("Usage: python3 ImprovedIUPTIS_COLLECT.py <config_file>")
    exit(1)



configName = sys.argv[1]
configFile = open(configName, "r")
jsonData = configFile.read()
configParameters = json.loads(jsonData)
tempFolder = configParameters["tempFolder"]
dataset = configParameters["datasetProfiles"]
netInterface = configParameters["networkInterface"]
hostName = str.encode(configParameters["domainName"])
myIP = configParameters["ownIP"]
iterations = configParameters["iterations"]
startIteration = configParameters["startIteration"]
firefoxPath = configParameters["firefoxPath"]
prefixWebpage = configParameters["prefixWebpage"]
useHeadless = configParameters["headlessBrowser"] == "True"
numberImagesPerProfile = configParameters["numberImagesPerProfile"]
startIndexProfile = configParameters["startIndexProfile"]
useProxy = configParameters["useProxy"] == "True"
numberScrollsWebpage = configParameters["numberScrollsWebpage"]
datasetDirectory = configParameters["datasetDirectory"]
checkDomain = configParameters["checkDomain"] == "True"
maxWaitingTime = configParameters["maxWaitingTime"]
configFile.close()


rootDir = os.getcwd() + "/"
print("Own IP:" + repr(myIP))


def createExtensionZip(saveFile,folderName,ext):
    check_output(["zip", "-j", "-r", saveFile,folderName])
    check_output(["mv", saveFile,saveFile[:-3]+ext])


def getImageSizes(strURL,numberPhotos,profileName):
    allPhotosLen = []
    allPhotosTime = []
    photosFound = 0
    # Extract information from all the original images, saved by the add-on.
    urlData = open(rootDir + "URLS.txt", "r+")
    if (not urlData):
        print("Error: Can't read from URLS.txt file. Are you sure the add-on is working properly?")
        exit(1)
    rawURLData = urlData.readlines()
    urlData.close()
    allURLS = []
    allStartTime = []
    allEndTime = []
    allLens = []
    for line in rawURLData:
        splitted = line.split(' ')
        allURLS.append(splitted[0])
        allLens.append(splitted[1])
        allStartTime.append(int(float(splitted[2])*1000))
        allEndTime.append(int(float(splitted[3][:-1])*1000))

    lowestIndex = 0
    if (len(allStartTime) == 0):
        print("WARNING: No data hold.")
        return False, [], []

    while (True):
        lowestIndex = allStartTime.index(min(allStartTime))
        if (allStartTime[lowestIndex] == sys.maxsize):
            break
        allPhotosLen.append(int(allLens[lowestIndex]))
        allPhotosTime.append([allStartTime[lowestIndex] * 100, allEndTime[lowestIndex] * 100])
        allStartTime[lowestIndex] = sys.maxsize

    if (len(allPhotosLen) < numberPhotos):
        print("WARNING: Profile '" + profileName[:-1] + "' has only " + repr(len(allPhotosLen)) + " photos. Skipping...")
        return False, [], []


    return True, allPhotosLen, allPhotosTime



def getTargetedConnection(allData):
    index = 0
    # Check for client hello, then check if the SNI contains the domain that we are targetting.
    while (len(allData) > index):
        if (allData[index:index+3] == b"\x16\x03\x01"):
            tlsDataLen = struct.unpack(">H", allData[index+3:index+5])[0]
            tlsData = allData[index + 5:index+5+tlsDataLen]
            # The domain name should be somewhere in the Client Hello record. Close enough.
            foundIndex = tlsData.find(hostName)
            if (foundIndex != -1):
                print("Targeted host name found: " + str(tlsData[foundIndex:foundIndex+6]))
                return True
            else:
                return False
        index += 1
    return False



def stopTcpdump():
    # Brutally kill tcpdump.
    exitTcpdump = subprocess.Popen(["sudo", "pkill","tcpdump"])
    exitTcpdump.wait()

def getCorrespondingDump(fileDump):
    indexD = fileDump.find("-")
    return fileDump[indexD+1:] + "-" + fileDump[0:indexD]



# TShark is not conform to the JSON standard and produces duplicate keys. This function will fix this.
def join_duplicate_keys(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            if type(d[k]) == list:
                d[k].append(v)
            else:
                newlist = []
                newlist.append(d[k])
                newlist.append(v)
                d[k] = newlist
        else:
           d[k] = v
    return d

allSSLData = {}
def addToSSLData(sslid,ssllen,stream,time):
    global allSSLData
    if sslid in allSSLData:
        allSSLData[sslid]["streams"].append({"ssl_len": ssllen, "stream_id": int(stream), "time": int(float(time)*10000000)})
    else:
        allSSLData[sslid] = {"streams": [{"ssl_len": ssllen, "stream_id" : int(stream), "time": int(float(time)*10000000)}], "ssl_id": sslid}


# Extract all TLS records from the JSON output produced by tshark.
def analyzeTLSData(decData,direction):
    global sslOverhead
    sslIndex = 0
    streamID = "-1"

    #print("Analyzing TLS data in direction " + str(direction) + " ...")
    for packet in decData:
        frame = packet["_source"]["layers"]
        if ((direction == -1 and frame["tcp"]["tcp.srcport"] != "81") or (direction == 1 and frame["tcp"]["tcp.dstport"] != "81")):
            continue
        timestamp = frame["frame"]["frame.time_epoch"]
        ssl = frame["ssl"]
        if "ssl.record" in ssl and "ssl.record.content_type" in ssl["ssl.record"]:
            if (ssl["ssl.record"]["ssl.record.content_type"] != "23"):
                continue
            addToSSLData(sslIndex, int(ssl["ssl.record"]["ssl.record.length"]) - sslOverhead, streamID,timestamp)
            sslIndex += 1
        elif (type(ssl) == list):
            tIndex = 0
            while (len(ssl) > tIndex):
                # Brutally killing TCPdump might leave half TLS records open. Ignore those.
                if ("ssl.record" not in ssl[tIndex]):
                    tIndex += 1
                    continue
                if (type(ssl[tIndex]["ssl.record"]) == list):
                    t2Index = 0
                    while (len(ssl[tIndex]["ssl.record"]) > t2Index and ssl[tIndex]["ssl.record"][t2Index]["ssl.record.content_type"] == "23"):
                        addToSSLData(sslIndex,int(ssl[tIndex]["ssl.record"][t2Index]["ssl.record.length"])-sslOverhead,streamID,timestamp)
                        sslIndex += 1
                        t2Index+=1
                else:
                    if (ssl[tIndex]["ssl.record"]["ssl.record.content_type"] == "23"):
                        addToSSLData(sslIndex, int(ssl[tIndex]["ssl.record"]["ssl.record.length"])-sslOverhead,streamID,timestamp)
                        sslIndex += 1
                tIndex += 1
        elif ("ssl.record" in ssl):
            # Brutally killing TCPdump might leave half TLS records open. Ignore those.

            tIndex = 0
            try:
                # If it errors here, you probably forgot to turn of TLS 1.3. (bug fix)
                while (len(ssl["ssl.record"]) > tIndex and ssl["ssl.record"][tIndex]["ssl.record.content_type"] == "23"):
                    addToSSLData(sslIndex, int(ssl["ssl.record"][tIndex]["ssl.record.length"]) - sslOverhead,streamID,timestamp)
                    sslIndex += 1
                    tIndex += 1
            except Exception as e:
                print(e)
                print(str(ssl))
        else:
            print("Ehhhh?: " + repr(ssl))


    return allSSLData.copy()





# When this function returns, the add-on has sent a signal telling our script that all necessary images are downloaded.
def isAddonReady():
    return os.path.isfile("ready_iuptis")

def waitForReady():
    counter = 0
    # Signaling through a file.
    while (not os.path.isfile("ready_iuptis")):
        counter += 1
        if (counter > maxWaitingTime):
            print("Timeout add-on.")
            break
        time.sleep(1)

    print("Add-on is ready.")



def clearUp():
    try:
        os.remove(rootDir + "URLS.txt")
        os.remove(rootDir + "ready_iuptis")
        os.remove(rootDir + "output.pcap")
    except:
        pass

    clearProxy()
    # Remove all files in the temporary folder.
    for the_file in os.listdir(tempFolder):
        file_path = os.path.join(tempFolder, the_file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(e)


def setupBrowser(browserType):
    if (browserType == "firefox"):
        profile = webdriver.FirefoxProfile()
        # Disable any sort of caching. We perform the caching manually if necessary.
        profile.set_preference("browser.cache.disk.enable", False)
        profile.set_preference("browser.cache.memory.enable", False)
        profile.set_preference("browser.cache.offline.enable", False)
        profile.set_preference("network.http.use-cache", False)
        profile.set_preference("browser.cache.disk.smart_size.enabled", False)
        profile.set_preference("browser.cache.disk_cache_ssl", False)
        # We want to install the add-on extension without hassle.
        profile.set_preference("xpinstall.signatures.required", False)
        # We turn off 'resist fingerprinting' because it reduces the precision of the timer.
        # This is obviously only used to fingerprint and not to perform the attack.
        profile.set_preference("privacy.reduceTimerPrecision", False)
        profile.set_preference("privacy.resistFingerprinting", False)
        # Bug fix for tShark not being able to decrypt some TLS 1.3 ciphersuites.
        profile.set_preference("security.tls.version.max", 3)
        profile.set_preference("security.tls.version.min", 2)


        firefox_capabilities = webdriver.DesiredCapabilities.FIREFOX
        if (useProxy):
            profile.set_preference("network.proxy.type", 1)
            profile.set_preference("network.proxy.http", myIP)
            profile.set_preference("network.proxy.http_port", "80")
            profile.set_preference("network.proxy.ssl", myIP)
            profile.set_preference("network.proxy.ssl_port", "80")
            profile.set_preference("network.proxy.socks", myIP)
            profile.set_preference("network.proxy.socks_port", "80")
            profile.set_preference("network.proxy.backup.ssl", myIP)
            profile.set_preference("network.proxy.backup.ssl_port", "80")
            profile.set_preference("network.proxy.share_proxy_settings", True)
            firefox_capabilities = webdriver.DesiredCapabilities.FIREFOX
            firefox_capabilities['marionette'] = True
            PROXY = myIP+":81"
            firefox_capabilities['proxy'] = {
                "proxyType": "MANUAL",
                "httpProxy": PROXY,
                "ftpProxy": PROXY,
                "sslProxy": PROXY
            }

        binary = FirefoxBinary(firefoxPath)
        options = Options()
        options.headless = useHeadless
        driver = webdriver.Firefox(profile, firefox_binary=binary, options=options,capabilities=firefox_capabilities)
        driver.set_page_load_timeout(30)
        driver.install_addon(rootDir + "extension.xpi", temporary=True)
        return driver
    elif (browserType == "chrome"):
        options = webdriver.ChromeOptions()
        options.headless = False
        options.add_argument("--ssl-version-max=tls1.2")
        PROXY = myIP + ":81"
        options.add_argument("--proxy-server=" + PROXY)
        #options.add_argument("--enable-logging")
        #options.add_argument("--v=1")
        #options.add_argument("--log-path=" + rootDir + "chrome.log")
        options.add_argument("--load-extension=" + rootDir + "ExtensionChrome")
        options.add_argument("--user-data-dir=" + rootDir + "InternalChrome")
        chrome_cap = webdriver.DesiredCapabilities.CHROME
        chrome_cap['applicationCacheEnabled'] = False
        driver = webdriver.Chrome(executable_path=r"chromedriver",options=options,desired_capabilities=chrome_cap)
        return driver
    else:
        print("Error: Unknown browser type.")
        exit(1)

def collectWebpage(driverX,prefix,webpage):
    driverX.get(prefix + webpage)
    if (numberScrollsWebpage > 0):
        numberScrolls = numberScrollsWebpage
        SCROLL_PAUSE_TIME = 3.0

        # Get scroll height
        last_height = driverX.execute_script("return document.body.scrollHeight")

        while (numberScrolls > 0 and not isAddonReady()):
            numberScrolls -= 1
            # Scroll down to bottom
            driverX.execute_script("window.scrollTo(0, document.body.scrollHeight);")

            # Wait to load page
            time.sleep(SCROLL_PAUSE_TIME)

            # Calculate new scroll height and compare with last scroll height
            new_height = driverX.execute_script("return document.body.scrollHeight")
            if new_height == last_height:
                break
            last_height = new_height

def signalProxy():
    global proxySock
    while(proxySock.send(b"\x01") != 1):
        continue
    commResp = proxySock.recv(1)
    if (commResp != b"\xff"):
        print("ERROR: Unexpected response from proxy socket. Exiting ...")
        exit(0)

def clearProxy():
    global proxySock
    while (proxySock.send(b"\x02") != 1):
        continue
    commResp = proxySock.recv(1)
    if (commResp != b"\xff"):
        print("ERROR: Unexpected response from proxy socket. Exiting ...")
        exit(0)

def runNormalMode():
    print("Running normal mode ....")
    # Create the zip extension for the add-on.
    createExtensionZip(rootDir + "extension.zip", rootDir + "Extension","xpi")
    photosLen = []
    # We iterate over all profiles/queries.
    for v in range(startIndexProfile, len(allPages)):
        # Number of iterations per profile/query.
        for i in range(startIteration, iterations+startIteration):
            allRecords = []
            try:
                clearUp()
                driverX = setupBrowser("firefox")
                time.sleep(2)
                # Visit the webpage.
                print("Requesting profile '" + allPages[v][:-1] + "' ...")
                collectWebpage(driverX,prefixWebpage,allPages[v])
                # Wait until we have downloaded all necessary images (this is communicated through the add-on)
                waitForReady()
                time.sleep(4)
                driverX.quit()
                time.sleep(2)
                # Signal proxy to dump the TLS record information.
                signalProxy()
                # Get the original lengths of the images on the webpage.
                isSuccess, photosLen, photosTime = getImageSizes(hostName, numberImagesPerProfile, allPages[v])
                if (not isSuccess):
                    print("Skipping this iteration.")
                    break
            except TimeoutError as e:
                print("WARNING: Failed to load in time with message -> " + repr(e))
                stopTcpdump()
                driverX.quit()
                time.sleep(3)
                continue
            except selenium.common.exceptions.WebDriverException as e:
                print("WARNING: WebDriver threw an exception. Error: " + repr(e) + ". Skipping this one ...")
                try:
                    driverX.quit()
                except:
                    pass
                continue

            print("Iteration " + repr(i) + ": Traffic of account " + allPages[v][:-1] + "(" + repr(v) + ") is captured. Writing to file...")
            sampleData = open(rootDir + "/" + datasetDirectory + repr(v) + "_" + repr(i) + ".txt", "w+")
            strPhotosLen = repr(' '.join(str(p) for p in photosLen))

            fTls = open("tls_output.txt", "r")
            # Write out all the original photo lengths.
            sampleData.write("### " + repr(strPhotosLen) + "\n")
            # Write out each SSL record with the time when it was received, the length and whether it was received or sent.
            sampleData.write(fTls.read())
            sampleData.close()
            fTls.close()
            print("Done iteration.\n")



# Open the dataset
accounts = open(rootDir + dataset,"r")
allPages = accounts.readlines()
accounts.close()
# Make sure tcpdump is not already running.
stopTcpdump()

proxySock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
proxySock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 120)
proxySock.connect(('127.0.0.1', 82))
resp = proxySock.recv(1)
if (resp == b"\xff"):
    print("Communication socket with proxy is established.")
else:
    print("Communication socket of proxy is not ready. Exiting ...")
    exit(1)


runNormalMode()


print("END")




