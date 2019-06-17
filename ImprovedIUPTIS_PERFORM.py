# MIT License
#
# Copyright (c) 2019 Mariano Di Martino
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# **********************************************************************************
# Realistically Fingerprinting Social Media Webpages in HTTPS Traffic
# Hasselt University/EDM/Flanders Make.
# Paper published by ACM ICPS, ARES 2019.
# Authors: Mariano Di Martino, Peter Quax, Wim Lamotte.
# Please cite the paper if you are using this source code.
# Licensed under: MIT License
# *****************************************************************************************

import sys
import os
import math
import re
import jenkspy
import json



if (len(sys.argv) < 2):
    print("Usage: python ImprovedIUPTIS_PERFORM.py <config_file>")
    exit(1)

endProfile = -1
if (len(sys.argv) == 4):
    startProfile = int(sys.argv[2])
    endProfile = int(sys.argv[3])
else:
    startProfile = 0

configName = sys.argv[1]
configFile = open(configName, "r")
jsonData = configFile.read()
configParameters = json.loads(jsonData)
numberAccounts = configParameters["numberProfiles"]
numberIterations = configParameters["numberIterations"]
numberImages = configParameters["numberImages"]
headerGuess = configParameters["b_in"]
rangeHeaderGuess = configParameters["pi_resp"]
minSequence = configParameters["sequence"]
noiseFrameSize = configParameters["minFrame"]
maxSD = configParameters["maxSD"]
doingJenks = configParameters["useJenks"] == "True"
caching = int((configParameters["caching"]/100) * numberImages)
datasetPath = configParameters["datasetPath"]
queriesPath = configParameters["queriesPath"]
usingHTTP2 = (configParameters["usingHTTP2"] == "True")
minDataSize = configParameters["minDataSize"]
useImageOrder = (configParameters["useImageOrder"] == "True")
configFile.close()



rootDir = os.getcwd() + "/"

# Compute the standard deviation
def calcSD(arr):
    total = 0
    for g in arr:
        total += g
    mean = total / float(len(arr))
    sum = 0
    for g in arr:
        sum += pow((g - mean), 2)
    return math.sqrt(sum / float(len(arr)))


# Apply the Jenks optimization method on an array
def applyJenks(arr):
    j = jenkspy.jenks_breaks(arr, 2)
    startEl = j[0]
    stopEl = j[1]
    cacheSDA = []
    cacheSDB = []
    sdA = -1
    sdB = -1
    for p in range(0, len(arr)):
        # Split up into 2 classes.
        if (arr[p] >= startEl and arr[p] <= stopEl):
            cacheSDA.append(arr[p])
        else:
            cacheSDB.append(arr[p])

    # If one of the classes only has one element, then fallback to default standard deviation.
    if (len(cacheSDA) <= 1 or len(cacheSDB) <= 1):
        sdA = calcSD(arr)
        sdB = sdA
    else:
        sdA = calcSD(cacheSDA)
        sdB = calcSD(cacheSDB)

    return sdA,sdB


def getResp(arr):
    allConn = []
    currConn = []

    # Create a list where each element defines a TCP connection.
    for line in arr:
        tlsRec = line.replace('\n','').split(' ')
        # Each TCP connection is seperated by 0,0,0.
        if (tlsRec[0] == "0" and tlsRec[1] == "0"):
            if (currConn != []):
                allConn.append(currConn)
            currConn = []
        else:
            currConn.append(tlsRec)
    if (currConn != []):
        allConn.append(currConn)

    index = -1
    respLengths = []
    # Construct the HTTP response lengths based on the TLS records.
    for conn in allConn:
        index += 1
        inPlus = False
        totalResp = 0
        lastTime = 0
        for j in range(0,len(conn)):
            sslRecTime = int(conn[j][0])
            sslLen = int(conn[j][1])
            sslDirection = int(conn[j][2])
            if (sslDirection < 0 and not inPlus):
                if (sslLen >= noiseFrameSize or not usingHTTP2):
                    totalResp = sslLen
                    inPlus = True
                    lastTime = sslRecTime
            elif (sslDirection < 0 and inPlus):
                if (sslLen >= noiseFrameSize or not usingHTTP2):
                    totalResp += sslLen
            elif (sslDirection > 0 and inPlus):
                # Make sure we skip other small resources such as stylesheets or javascript files.
                if (totalResp > minDataSize):
                    respLengths.append([totalResp, lastTime])
                totalResp = 0
                inPlus = False
        if (totalResp > minDataSize):
            respLengths.append([totalResp, lastTime])

    resps = [item[0] for item in respLengths]

    return resps[caching:]

    # respLen = []
    # # Order the HTTP responses based on time.
    # while len(respLengths) > 0:
    #     fastestTime = -1
    #     fastestIndex = -1
    #     index = -1
    #     for resp in respLengths:
    #         index += 1
    #         if (fastestTime == -1 or fastestTime > resp[1]):
    #             fastestTime = resp[1]
    #             fastestIndex = index
    #     respLen.append(respLengths[fastestIndex][0])
    #     del respLengths[fastestIndex]
    #
    # # Use caching if wanted.
    # return respLen[caching:]


def calculateOrdered(responses,images,useJenks):
    possibleDiff = []
    isMade = False
    bestSeq = -1
    for currSequence in range(minSequence,minSequence+10):
        for i in range(0,len(responses)-minSequence):
            respSeq = responses[i:minSequence+i]
            for p in range(0,len(images)-minSequence):
                imSeq = images[p:minSequence+p]
                diffArr = []
                skipThis = False
                for q in range(len(respSeq)):
                    if (int(respSeq[q])-int(imSeq[q])-headerGuess >= rangeHeaderGuess):
                        skipThis = True
                        break
                    diffArr.append(int(respSeq[q])-int(imSeq[q])-headerGuess)
                if (skipThis):
                    continue
                # Do we apply Jenks optimization method?
                if (useJenks):
                    sdA, sdB = applyJenks(diffArr)
                else:
                    sdA = calcSD(diffArr)
                    sdB = sdA

                # Make sure the standard deviation is smaller then H_{resp} and H_{req}.
                if (sdA < maxSD and sdB < maxSD):
                    isMade = True
                    break
            if (isMade):
                break
        if (isMade):
            bestSeq = currSequence
        else:
            if (bestSeq != -1):
                isMade = True
            break
    return isMade,bestSeq


def calculateDiffs(responses,images,useJenks):
    possibleDiff = []
    # Calculate the difference of each responses with each image and take the smallest diff (if in range).
    for resp in responses:
        lowDiff = -1
        lowSecDiff = -1
        respI = int(resp)
        for imlen in images:
            imlenI = int(imlen)
            # Check if response is within range.
            if (respI - headerGuess > imlenI and (respI - headerGuess - imlenI) < rangeHeaderGuess):
                # Keep the smallest value of the difference between HTTP response body length and image length. Use that one for the sequence.
                if (respI - headerGuess - imlenI < lowDiff or lowDiff == -1):
                    lowSecDiff = lowDiff
                    lowDiff = respI - headerGuess - imlenI
                elif (respI - headerGuess - imlenI < lowSecDiff or lowSecDiff == -1):
                    lowSecDiff = respI - headerGuess - imlenI

        # The smallest difference is not always from the correct image,
        # Keep the 2 smallest diffs and choose the one who would be the closest to the previous diff.
        if (len(possibleDiff) == 0 or abs(possibleDiff[len(possibleDiff) - 1] - lowDiff) < abs(
            possibleDiff[len(possibleDiff) - 1] - lowSecDiff) or lowSecDiff == -1):
            possibleDiff.append(lowDiff)
        else:
            possibleDiff.append(lowSecDiff)

    # Iterate over all diffs
    bestSequence = -1
    for currSequence in range(minSequence,minSequence+10):
        isMade = False
        for i in range(0, len(possibleDiff) - currSequence):
            sdA = 0
            sdB = 0
            # Create a possible sequence of diffs.
            arrDiff = possibleDiff[i:currSequence + i]
            # Skip the responses not in range.
            if (-1 in arrDiff):
                continue

            # Do we apply Jenks optimization method?
            if (useJenks):
                sdA, sdB = applyJenks(arrDiff)
            else:
                sdA = calcSD(arrDiff)

            # Make sure the standard deviation is smaller then H_{resp} and H_{req}.
            if (sdA < maxSD and sdB < maxSD):
                isMade = True
                break

        if (isMade):
            bestSequence = currSequence
        else:
            if (bestSequence != -1):
                isMade = True
            break

    return isMade,bestSequence


def handleSingleQuery(responses,images,useJenks):
    # Calculate diffs for unordered sequence.
    if (useImageOrder):
        isMade,bestSeq = calculateOrdered(responses, images, useJenks)
    else:
        # Calculate for ordered sequence.
        isMade,bestSeq = calculateDiffs(responses,images,useJenks)

    return isMade,bestSeq


def loadTraces():
    allImageLen = []
    allRespLen = []
    queriesFile = open(rootDir + queriesPath)
    allQueries = queriesFile.readlines()
    queriesFile.close()

    # Load all samples
    global testje
    for accounts in range(0, numberAccounts):
        for iter in range(0, numberIterations):
            try:
                fPath = rootDir + datasetPath + repr(accounts) + "_" + repr(iter) + ".txt"
                traceData = open(fPath, "r")
            except:
                allImageLen.append([])
                allRespLen.append([])
                continue

            traceDataLines = traceData.readlines()
            traceData.close()

            # Get all the responses from this trace.
            allRespLen.append(getResp(traceDataLines[1:]))
            # Header line with all the image lengths
            headerLine = traceDataLines[0]

            imagesLen = headerLine[6:].split(' ')
            if (len(imagesLen) < numberImages):
                print("Profile " + accounts + " has not enough images.")
                allImageLen.append([])
                allRespLen.append([])
                continue
            # Bugfix last element
            imagesLen[len(imagesLen) - 1] = imagesLen[len(imagesLen) - 1][:-3]
            # for k in imagesLen:
            #     testje.append(int(k))
            allImageLen.append(imagesLen)

    return allRespLen, allImageLen, allQueries



def runNormalMode():
    # Load all the traces in the dataset folder.
    allRespLen, allImageLen, allQueries = loadTraces()
    sensPred = 0
    # For each profile and its responses.
    emptyPreds = 0
    allBestSeq = []
    for k in range(0,len(allRespLen)):
        if (len(allImageLen[k]) == 0):
            emptyPreds += 1
            allBestSeq.append(-1)
            continue
        # Check the original images of the profile to the sample TLS records from the same profile.
        isOk,bestSeq = handleSingleQuery(allRespLen[k], allImageLen[k], doingJenks)
        allBestSeq.append(bestSeq)
        if (isOk):
            print("Prediction for profile " + str(k) + " is ok!")
            sensPred += 1
        else:
            print("Incorrect prediction for profile " + str(k))

    # Defines sensitivity
    print("Sensitivity: " + str((sensPred/(len(allRespLen)-emptyPreds))*100) + " %")

    totalCorrect = 0
    emptyPreds = 0
    global endProfile
    if (endProfile == -1):
        endProfile = len(allRespLen)
    else:
        endProfile - min(len(allRespLen),endProfile)

    for k in range(startProfile,endProfile):
        if (len(allRespLen[k]) == 0):
            emptyPreds += 1
            continue
        wrongPreds = 0
        for v in range(0,len(allImageLen)):
            # We skip the own samples, already have that one.
            if v == k:
                continue
            # Check sample TLS records of this profile, with the images/fingerprints of all the other profiles.
            isWrongPred, bestSeq = handleSingleQuery(allRespLen[k], allImageLen[v], doingJenks)
            if (allBestSeq[k] > 0 and allBestSeq[k] < bestSeq and isWrongPred):
                wrongPreds += 1
            # if (isWrongPred):
            #     wrongPreds += 1
        if (wrongPreds == 0):
            totalCorrect += 1
        print("Profile " + str(k) + " has " + str(wrongPreds) + " wrong predictions.")


    print("Precision " + str((totalCorrect/(len(allRespLen)-emptyPreds))*100) + " %")




runNormalMode()

