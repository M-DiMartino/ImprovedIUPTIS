## Source code and dataset for publication 'Realistically Fingerprinting Social Media Webpages in HTTPS Traffic'.
Hasselt University/EDM/Flanders Make.

Paper published by ARES 2019.

Authors: Mariano Di Martino, Peter Quax, Wim Lamotte.

Please cite the paper if you are using this source code.


```
@inproceedings{DiMartino:2019:RFS:3339252.3341478,
 author = {Di Martino, Mariano and Quax, Peter and Lamotte, Wim},
 title = {Realistically Fingerprinting Social Media Webpages in HTTPS Traffic},
 booktitle = {Proceedings of the 14th International Conference on Availability, Reliability and Security},
 series = {ARES '19},
 year = {2019},
 isbn = {978-1-4503-7164-3},
 location = {Canterbury, CA, United Kingdom},
 pages = {54:1--54:10},
 articleno = {54},
 numpages = {10},
 url = {http://doi.acm.org/10.1145/3339252.3341478},
 doi = {10.1145/3339252.3341478},
 acmid = {3341478},
 publisher = {ACM},
 address = {New York, NY, USA},
 keywords = {forensics, social media, traffic analysis, webpage fingerprinting},
} 
```


## Important files
* Datasets: 5 directories with existing samples (<platform_<type>_<samplesPerProfile>,<numberOfProfiles>). Example: Twitter_Active_1sp_700p
* tcpproxy.py: Proxy which will be used in combination with Selenium to capture traffic traces and perform the HTTP/2 delaying. Port 81 is used as a proxy, while port 82 is used to communicate with other scripts.
* profilelist_<platform>.txt: List of profile names for the given platform.
* Directory 'extension': Add-on for Firefox, used to collect the actual image sizes of each profile.
* ImprovedIUPTIS_PERFORM.py: Used to run IUPTIS against existing samples.
* ImprovedIUPTIS_COLLECT.py: Used to collect new samples.
* DataCollector.json and DataCollector.py: Native messaging with 'ImprovedIUPTIS.COLLECT.py' to communicate with add-on.

## Preliminary steps to setup ImprovedIUPTIS
1. Use requirements.txt to install Python 2 and 3 libraries.
2. Download the 'geckodriver' (tested with v0.22.0) and add it to the PATH (https://www.seleniumhq.org/download/) or put it in the root directory of this package.
4. In 'DataCollector.json', set the correct location of the file 'DataCollector.py' in the variable 'path' (e.g. /home/mariano/RFWIH_Package/DataCollector.py).
5. The add-on uses native messaging to communicate with DataCollector.py. Copy DataCollector.json to the correct location (https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Manifest_location).
6. In 'DataCollector.py', set the path (variable 'rootDir') to the root directory of this package.

## Setup and run ImprovedIUPTIS against existing traces.
7. Create a JSON config file (or use the example 'ConfigInstagram_PERFORM.json'). The parameters are as followed:
   * numberOfProfiles: Number of profiles that we are going to use.
   * numberOfIterations: Number of samples per profile that we are going to use.
   * numberOfImages: Important to keep this exactly the same in all config files and in 'manifest.json'.
   * b_in: Guessed number of bytes of overhead HTTP Response header (keep it small).
   * pi_resp: Allowed range of difference for HTTP Response header (keep it large).
   * sequence: Minimum sequence/streak of image resources that have to be detected for a valid prediction (Φ in paper).
   * maxSD: Maximum standard deviation for each valid sequence (σ in paper).
   * useJenks: Do we use the Jenks Optimization method? (useGVF in paper)
   * caching: Will automatically browser-cache X% of images.
   * useImageOrder: If True, then the exact order of images will be kept (useOrder in paper).
   * datasetPath: Path to all the samples.
   * queriesPath: Path to all profile names (useful for debugging).
   * minDataSize: Minimal size (in bytes) for a valid image.
8. Example: Execute 'ImprovedIUPTIS_PERFORM.py configInstagram_PERFORM.json' to run ImpIUPTIS against existing traces of Instagram.


## Setup and run ImprovedIUPTIS for collecting new traces.
9. Create a JSON config file (or use the example 'ConfigInstagram_COLLECT.json'). The parameters are as followed:
   * networkInterface: Name of network interface that does the capturing.
   * datasetProfiles: Path to dataset of profiles for the given webplatform.
   * domainName: IUPTIS will only analyze TCP connections that have a Client_Hello with a SNI that contains this domain name.
   * sslOverhead: Overhead in number of bytes per TLS Record (for instance, HMAC headers).
   * firefoxPath: Path to the binary of Firefox (does not work with ESR).
   * prefixWebpage: Firefox will perform HTTP requests to webpages with this variable as prefix. 
   * ownIP: Capture all traffic where 'ownIP' is either the destination or source (usually local IP).
   * numberImagesPerProfile: The number of images that it has to capture per profile, before finishing.
   * maxWaitingTime: Maximum time (in seconds) that it will wait before 'numberImagesPerProfile' are captured.
   * iterations: Number of iterations/samples per profile.
   * startIndexProfile: Start at this index of the profile list ('datasetProfiles').
   * headlessBrowser: If True, then the browser will be sent to the background and thus not shown. If set to False, then the browser will be visible while capturing.
   * numberScrollsWebpage: Number of scrolls through the webpage per profile. This is necessary if images are progressively downloaded while scrolling.
   * datasetDirectory: Directory where all generated samples will be saved.
10. Tcpproxy.py will setup a proxy on port 81, which will be used to capture all TCP traffic from the Selenium Firefox browser. Port 82 will be used to communicate with ImprovedIUPTIS_COLLECT.py. The first argument of tcpproxy.py defines the number of seconds it will wait before allowing another HTTP2 request to come through. The second argument defines the domain name of the TCP connection that it will analyze (should be equal to 'domainName' in the collect config file).
Example: 'python3 tcpproxy.py 0.5 .cdninstagram.com'.
10. When tcpproxy.py is listening, the collection script 'ImprovedIUPTIS_COLLECT.py' should be executed with a config file. Example: 'ImprovedIUPTIS_COLLECT.py configInstagram_COLLECT.json' to collect new samples of Instagram profiles.


## Troubleshooting notes

* In the directory where 'geckodriver' is located, a log file 'geckodriver.log' will be generated.
* Do not execute 'ImprovedIUPTIS_COLLECT.py' with sudo, as Firefox will not accept this.
* In 'ImprovedIUPTIS_COLLECT.py', an Firefox (or Chrome) add-on/extension will be compiled and attached to Selenium which will save the actual image sizes of each profile. If necessary, you can debug the add-on in Firefox by using 'about:addons'. Error messages in the Developer Console will be generated if the add-on fails to run.

## Format of sample traces
- Each sample trace:
  * First line: Size of each image resource requested by the browser (in bytes). Number of image resources should be equal to 'numberOfImages'.
  * 0 0 0 : Defines the start of a new TCP connection
  * X Y Z : X = Timestamp of TLS Record,  Y = Length of TLS Record (minus the overhead),  Z = direction (e.g. -1 is from server to client, 1 is from client to server).
