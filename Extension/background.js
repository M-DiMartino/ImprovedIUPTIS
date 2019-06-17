//# MIT License
//#
//# Copyright (c) 2019 Mariano Di Martino
//#
//# Permission is hereby granted, free of charge, to any person obtaining a copy
//# of this software and associated documentation files (the "Software"), to deal
//# in the Software without restriction, including without limitation the rights
//# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//# copies of the Software, and to permit persons to whom the Software is
//# furnished to do so, subject to the following conditions
//#
//# The above copyright notice and this permission notice shall be included in all
//# copies or substantial portions of the Software.
//#
//# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//# SOFTWARE.
//
//# **********************************************************************************
//# Realistically Fingerprinting Social Media Webpages in HTTPS Traffic
//# Hasselt University/EDM/Flanders Make.
//# Paper published by ACM ICPS, ARES 2019.
//# Authors: Mariano Di Martino, Peter Quax, Wim Lamotte.
//# Please cite the paper if you are using this source code.
//# Licensed under: MIT License
//# *****************************************************************************************



var hostName = browser.runtime.getManifest().urlName;
var maxResponses = browser.runtime.getManifest().numberImages
var minImageSize = browser.runtime.getManifest().minImageSize

// Communication script
var port = browser.runtime.connectNative("DataCollector");
var allRequests = [];
var allResponses = [];
var totalResponses = 0;


// Message the Collector script that it is ready.
function notifyReady()
{
    port.postMessage("*READY*\n");
    console.log("IUPTIS: Notified ready.");
}


// Save all GET requests.
function logReqURL(requestDetails) {
	  console.log("Request: " + requestDetails.url);
	  if (requestDetails.method === "GET")
	  	allRequests.push([requestDetails.url,requestDetails.requestId,requestDetails.timeStamp]);
}


// If the response to the request for an image resource has been finished, then send that information to the datacollector script.
function logCompletedURL(responseDetails)
{
    var hasFound = false;
    for (var p = 0; p < allResponses.length; p++)
    {
        if (responseDetails.requestId === allResponses[p][0][1])
        {
            var reqUrl = allResponses[p][3];
            console.log("Response completed: " + reqUrl);
			hasFound = true;
			//Check if it is a targeted host domain name.
            if (reqUrl.includes(hostName) && allResponses[p][1] > minImageSize)
            {
                //Request URL, content length, timestamp of beginning response, timestamp of initial request.
                port.postMessage(reqUrl + " " + allResponses[p][1] + " " + allResponses[p][2] + " " + allResponses[p][4] + "\n");
                //port.postMessage(reqUrl + " " + allResponses[p][1] + " " + allResponses[p][2] + " " + responseDetails.timeStamp + "\n");
                totalResponses += 1;
                console.log("totalResponses = " + totalResponses);
            }
            allResponses.splice(p,1);

            // If we have reached the necessary number of responses/images, then notify the main script.
			if (totalResponses >= maxResponses)
            {
                notifyReady();
                totalResponses = -99999;
            }
			break;
        }
    }
    if (!hasFound)
        console.log("Error: something went wrong when completing response url. Can't find matching request.")

}


// Start of HTTP response for image resource.
function logRespURL(responseDetails)
{
  console.log("Response: " + responseDetails.url);
  
  currResp = [responseDetails.responseHeaders,responseDetails.requestId] ;
  var hasFound = false;
  for (var i = 0; i < allRequests.length;i++)
  {
	if (currResp[1] === allRequests[i][1])
	{

	    // Extract the HTTP header 'Content-Length'.
		contentLen = "";
		currResp[0].forEach(function(header){
					    if (header.name.toLowerCase() === "content-length") {
					      contentLen = header.value;
					    }
					  });
		if (contentLen !== "")
		{
		    console.log("Response to " + responseDetails.url + " with length " + contentLen + " has been started.");
		    allResponses.push([currResp,contentLen,responseDetails.timeStamp,allRequests[i][0],allRequests[i][2]]);
			hasFound = true;
			allRequests.splice(i,1);
			break;
		}
		else
			console.log("No content-length for response to URL " + allRequests[i][0]);
	}
  } 
  if (!hasFound)
      console.log("URL " + responseDetails.url + " is not from a GET request.") ;

}



browser.webRequest.onBeforeRequest.addListener(
logReqURL,
{urls: ["<all_urls>"]}
);

browser.webRequest.onResponseStarted.addListener(
  logRespURL,
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);

browser.webRequest.onCompleted.addListener(
  logCompletedURL,
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);





