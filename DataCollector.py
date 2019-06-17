#!/usr/bin/env python3

import sys
import json
import struct
import os

# Set root directory where we have to save "URLS.txt"
rootDir = "/home/mariano/RFWIH_Package"


def getMessage():
    rawLength = sys.stdin.buffer.read(4)
    if len(rawLength) == 0:
        sys.exit(0)
    messageLength = struct.unpack('@I', rawLength)[0]
    message = sys.stdin.buffer.read(messageLength).decode('utf-8')
    return json.loads(message)


# Send an encoded message to stdout
def sendMessage(messageContent):
    encodedContent = json.dumps(messageContent).encode('utf-8')
    encodedLength = struct.pack('@I', len(encodedContent))

    sys.stdout.buffer.write(encodedLength)
    sys.stdout.buffer.write(encodedContent)
    sys.stdout.buffer.flush()


urlData = open(rootDir + "/URLS.txt", "w+")
while True:
    receivedMessage = getMessage()
    if (receivedMessage == "*READY*\n"):
        f = open(rootDir + "/ready_iuptis", "w+")
        f.write("ready_iuptis")
        f.close()
        continue
    urlData.write(receivedMessage)
    urlData.flush()
    os.fsync(urlData)

urlData.close()
