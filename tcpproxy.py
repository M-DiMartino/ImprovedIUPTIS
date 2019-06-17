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



import os
import time
import sys
import socket
import threading
import select
import struct
from enum import Enum
from threading import Thread, Lock

allTLS = {}
mutex = Lock()

def addTLSRecord(id,tlsLen,direction,timestamp):
    sslOverhead = 24
    mutex.acquire()
    global allTLS
    if (id not in allTLS):
        allTLS[id] = []

    allTLS[id].append([tlsLen-sslOverhead,direction,timestamp])
    mutex.release()

def clearRecords():
    global allTLS
    mutex.acquire()
    allTLS = {}
    mutex.release()

# Write all TLS records to tls_output.txt
def writeRecords():
    mutex.acquire()
    try:
        os.remove("tls_output.txt")
    except:
        pass
    f = open("tls_output.txt","w")
    for sockname in allTLS:
        conn = allTLS[sockname]
        f.write("0 0 0\n")
        for rec in conn:
            f.write(str(int(rec[2]*1000000)) + " " + str(rec[0]) + " " + str(rec[1]) + "\n")
    f.close()
    mutex.release()


# Communication thread with ImprovedIUPTIS_COLLECT.py
def communicate():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 120)
    sock.bind(('127.0.0.1', 82))
    sock.listen(1)
    while True:
        client, address = sock.accept()
        client.send(b"\xff")
        print("Communication connection is accepted.")
        while (True):
            data = client.recv(1)
            if (not data):
                print("WARNING: Communication connection is closed by client.")
                exit(1)
                continue
            else:
                if (data == b"\x01"):
                    writeRecords()
                    client.send(b"\xff")
                elif (data == b"\x02"):
                    clearRecords()
                    client.send(b"\xff")
                else:
                    print("WARNING: Unknown command from client. Closing socket ...")
                    client.close()
                    exit(1)
                    break




class ThreadedServer(object):
    def __init__(self, host, port, timewait, targetDomain):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.recvSize = 4096
        #self.targetAddr = b".cdninstagram.com"
        #self.targetAddr = b"pbs.twimg.com"
        self.targetAddr = str.encode(targetDomain)
        self.isBusy = False
        self.timeWait = timewait

    def listen(self):
        self.sock.listen(40)
        # Proxy will accept TCP connections.
        while True:
            client, address = self.sock.accept()
            client.settimeout(120)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()


    def handleStream(self,client,address,outSock):
        clientData = b""
        outSockData = b""
        while 1:
            writeSockets = []
            if (clientData):
                writeSockets.append(client)
            if (outSockData):
                writeSockets.append(outSock)

            readSockets = [client, outSock]

            readable, writeable, exceptional = select.select(readSockets, writeSockets, [],0)
            for w in writeable:
                if w is client:
                    if (clientData):
                        client.send(clientData)
                        clientData = b""
                elif w is outSock:
                    if (outSockData):
                        outSock.send(outSockData)
                        outSockData = b""
            for r in readable:
                if r is client:
                    data = client.recv(self.recvSize)
                    if not data:
                        print("Client disconnected.")
                        outSock.close()
                        return True
                    outSockData += data
                elif r is outSock:
                    data = outSock.recv(self.recvSize)
                    if not data:
                        print("Server disconnected.")
                        client.close()
                        return True
                    clientData += data

    def send200Connect(self,client):
        client.send(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")

    def listenToClient(self, client, address):
        response = b""
        while True:
            isConnected = False
            data = client.recv(self.recvSize)
            if data:
                response += data
                isConnected,outHostname,outPort = self.handleHTTPConnect(response)
                if (isConnected):
                    self.send200Connect(client)
                    break
            else:
                print("Disconnected before HTTP CONNECT.")
                client.close()
                return False


        # Is this request targeted to our address?
        if (self.targetAddr in outHostname):
            # Outgoing socket.
            sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sc.connect((outHostname, int(outPort)))
            sc.setblocking(True)
            client.setblocking(True)

            self.isBusy = True
            print("Handling TARGET host: " + str(outHostname))
            val = self.handleIUPTISStream(client,address,sc)
            self.isBusy = False
            return val
        else:
            # Outgoing socket.
            sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sc.connect((outHostname, int(outPort)))
            sc.setblocking(True)
            client.setblocking(True)

            print("Host: " + str(outHostname))
            return self.handleStream(client,address,sc)


    def handleHTTPConnect(self,strConn):
        if (strConn.find(b"\r\n\r\n") == -1):
            return False, "", ""

        sIndex = strConn.find(b"\r\nHost: ")
        midIndex = strConn.find(b"\r\n",sIndex+8)
        eIndex = strConn.find(b":", sIndex+8,midIndex)
        e2Index = strConn.find(b"\r\n", eIndex+1)

        if (eIndex != -1):
            outHostname = strConn[sIndex+8:eIndex]
            outPort = strConn[eIndex+1:e2Index]
        else:
            outHostname = strConn[sIndex + 8:midIndex]
            outPort = "80"


        return True, outHostname, outPort

    def handleIUPTISStream(self,client,address,outSock):
        iupDel = IUPTISDelay(outSock.getsockname(),self.timeWait)
        while 1:

            # Run the core IUPTISDelay algorithm.
            while (iupDel.update()):
                pass

            writeSockets = []
            if (iupDel.hasDataForClient()):
                writeSockets.append(client)
            if (iupDel.hasDataForServer()):
                writeSockets.append(outSock)

            readSockets = [client, outSock]

            readable, writeable, exceptional = select.select(readSockets, writeSockets, [],0)
            for w in writeable:
                if w is client:
                    print("Sending data to client.")
                    client.send(iupDel.getDataForClient())
                elif w is outSock:
                    print("Sending data to server.")
                    outSock.send(iupDel.getDataForServer())
            for r in readable:
                if r is client:
                    data = client.recv(self.recvSize)
                    if not data:
                        print("Target client disconnected.")
                        self.isBusy = False
                        outSock.close()
                        return True
                    iupDel.sendToServer(data)
                elif r is outSock:
                    data = outSock.recv(self.recvSize)
                    if not data:
                        print("Target server disconnected.")
                        self.isBusy = False
                        client.close()
                        return True
                    iupDel.sendToClient(data)

class SERVER_STATUS(Enum):
    REQUEST_ON_ROUTE = 1
    SENDING_RESPONSE = 2
    WAITING_FOR_REQUEST = 3
    WAITING_FOR_REQUEST_FIRST = 4


class IUPTISDelay:

    def __init__(self,sockname,timeWait):
        self.dstip = sockname[0]
        self.srcport = int(sockname[1])
        self.uniqueName = self.dstip + "_" +  str(self.srcport)
        self.clientData = b""
        self.serverData = b""
        self.serverTLSQueue = []
        self.serverAllowedData = b""
        self.clientAllowedData = b""
        self.clientTLSQueue = []
        #self.WAIT_COMPLETION = 0.5
        self.WAIT_COMPLETION = timeWait
        self.lastReceivedFromServer = time.time()
        self.hasDataClient = False
        self.hasDataServer = False
        self.serverHasRequest = False
        self.serverStatus = SERVER_STATUS.WAITING_FOR_REQUEST_FIRST

    def hasDataForClient(self):
        return (len(self.clientAllowedData) > 0)

    def hasDataForServer(self):
        return (len(self.serverAllowedData) > 0)

    def sendToClient(self,data):
        #print("Received data from server.")
        self.clientData += data

    def sendToServer(self,data):
        #print("Received data from client.")
        self.serverData += data

    def getDataForClient(self):
        if (self.hasDataForClient()):
            backupData = self.clientAllowedData
            self.clientAllowedData = b""
            return backupData

    def getDataForServer(self):
        if (self.hasDataForServer()):
            backupData = self.serverAllowedData
            self.serverAllowedData = b""
            return backupData

    def update(self):
        globChanged = False

        # Handle data from client to server
        while (len(self.serverData) > 5):
            #Skip anything else then Application Data Records
            if (self.serverData[0:3] == b"\x16\x03\x01" or self.serverData[0:3] == b"\x16\x03\x03" or
                self.serverData[0:3]  == b"\x14\x03\x03" or self.serverData[0:3]  == b"\x15\x03\x03"):
                tlsLen = struct.unpack(">H", self.serverData[3:5])[0]
                # Make sure we have enough data to queue the complete TLS Record.
                if (len(self.serverData) >= tlsLen + 5):
                    self.serverTLSQueue.append([tlsLen, self.serverData[:tlsLen + 5], False])
                    self.serverData = self.serverData[tlsLen + 5:]
                    print("Queuing non-AppData for server.")
                    globChanged = True
                else:
                    break
            # Extract Application Data Records
            elif (self.serverData[0:3] == b"\x17\x03\x03"):
                tlsLen = struct.unpack(">H", self.serverData[3:5])[0]
                # Make sure we have enough data to queue the complete TLS Record.
                if (len(self.serverData) >= tlsLen + 5):
                    self.serverTLSQueue.append([tlsLen,self.serverData[:tlsLen+5], True])
                    self.serverData = self.serverData[tlsLen + 5:]
                    print("Queuing AppData for server.")
                    globChanged = True
                else:
                    break
            else:
                print("Error: Unknown TLS data from client :(. First 3 bytes: " + repr(self.serverData[0:3]))
                exit(1)


        # Handle data from server to client.
        while (len(self.clientData) > 5):
            # Skip anything else then Application Data Records
            if (self.clientData[0:3] == b"\x16\x03\x01" or self.clientData[0:3]  == b"\x16\x03\x03" or
                self.clientData[0:3]  == b"\x14\x03\x03" or self.clientData[0:3]  == b"\x15\x03\x03"):
                tlsLen = struct.unpack(">H", self.clientData[3:5])[0]
                # Make sure we have enough data to queue the complete TLS Record.
                if (len(self.clientData) >= tlsLen + 5):
                    self.clientTLSQueue.append([tlsLen, self.clientData[:tlsLen + 5], False])
                    self.clientData = self.clientData[tlsLen + 5:]
                    print("Queuing non-AppData for client.")
                    globChanged = True
                else:
                    break
            # Extract Application Data Records
            elif (self.clientData[0:3] == b"\x17\x03\x03"):
                tlsLen = struct.unpack(">H", self.clientData[3:5])[0]
                # Make sure we have enough data to queue the complete TLS Record.
                if (len(self.clientData) >= tlsLen+5):
                    self.clientTLSQueue.append([tlsLen,self.clientData[:tlsLen+5], True])
                    self.clientData = self.clientData[tlsLen + 5:]
                    print("Queuing AppData for client.")
                    globChanged = True
                else:
                    break
            else:
                print("Error: Unknown TLS data from server :(. First 3 bytes: " + repr(self.clientData[0:3]))
                exit(1)

        hasChanged = True
        while (hasChanged):
            hasChanged = False
            if (len(self.clientTLSQueue) > 0):
                hasChanged = True
                tlsData = self.clientTLSQueue[0]
                tlsLen = tlsData[0]
                tcpData = tlsData[1]
                isAppData = tlsData[2]
                self.clientAllowedData += tcpData
                if (isAppData):
                    addTLSRecord(self.uniqueName, tlsLen, -1, time.time())
                # See small TLS records as non-HTTP response data.
                if (tlsLen > 160 and isAppData):
                    if (self.serverStatus == SERVER_STATUS.REQUEST_ON_ROUTE):
                        self.serverStatus = SERVER_STATUS.SENDING_RESPONSE
                    self.lastReceivedFromServer = time.time()
                #print("Pushed data for client.")
                del self.clientTLSQueue[0]
            if (hasChanged):
                globChanged = True


        # Do we want to pass data from client to server?
        hasChanged = True
        while (hasChanged):
            hasChanged = False
            #print("SERVER_STATUS = " + repr(self.serverStatus))
            if (len(self.serverTLSQueue) > 0):
                # If we have a TLS Record that does not contain Application Data, then pass it right away.
                if (self.serverTLSQueue[0][2] == False):
                    tlsData = self.serverTLSQueue[0]
                    tcpData = tlsData[1]
                    self.serverAllowedData += tcpData
                    del self.serverTLSQueue[0]
                    hasChanged = True
                elif (self.serverStatus == SERVER_STATUS.WAITING_FOR_REQUEST_FIRST):
                    tlsData = self.serverTLSQueue[0]
                    tcpData = tlsData[1]
                    self.serverAllowedData = tcpData
                    self.serverStatus = SERVER_STATUS.WAITING_FOR_REQUEST
                    self.lastReceivedFromServer = time.time()   #MAYBE?
                    del self.serverTLSQueue[0]
                    hasChanged = True
                elif (self.serverStatus == SERVER_STATUS.WAITING_FOR_REQUEST):
                    tlsData = self.serverTLSQueue[0]
                    tcpData = tlsData[1]
                    self.serverAllowedData += tcpData
                    if (tlsData[2]):
                        addTLSRecord(self.uniqueName, tlsData[0], 1, time.time())
                    self.serverStatus = SERVER_STATUS.REQUEST_ON_ROUTE
                    del self.serverTLSQueue[0]
                    self.lastReceivedFromServer = time.time()
                    hasChanged = True
                elif (self.serverStatus == SERVER_STATUS.REQUEST_ON_ROUTE):
                    if (time.time() - self.lastReceivedFromServer >= self.WAIT_COMPLETION):
                        # Too long that we got something BIG from the server. Pass another TLS record from client to server.
                        tlsData = self.serverTLSQueue[0]
                        tcpData = tlsData[1]
                        self.serverAllowedData += tcpData
                        if (tlsData[2]):
                            addTLSRecord(self.uniqueName, tlsData[0], 1, time.time())
                        if (len(self.serverTLSQueue[0][1]) >= 40):
                            self.lastReceivedFromServer = time.time()
                        #print("Passing another TLS Record from client to server RR.")
                        del self.serverTLSQueue[0]
                        hasChanged = True
                elif (self.serverStatus == SERVER_STATUS.SENDING_RESPONSE):
                    if (time.time() - self.lastReceivedFromServer >= self.WAIT_COMPLETION): # or len(self.serverTLSQueue[0][1]) < 40):
                        # Too long that we got something BIG from the server. Pass another TLS record from client to server.
                        tlsData = self.serverTLSQueue[0]
                        tcpData = tlsData[1]
                        if (tlsData[2]):
                            addTLSRecord(self.uniqueName, tlsData[0], 1, time.time())
                        self.serverAllowedData += tcpData
                        if (len(self.serverTLSQueue[0][1]) >= 40):
                            self.lastReceivedFromServer = time.time()
                        del self.serverTLSQueue[0]
                        self.serverStatus = SERVER_STATUS.REQUEST_ON_ROUTE
                        #print("Passing another TLS Record from client to server SR.")
                        hasChanged = True
                if (hasChanged):
                    #print("Pushed data for server.")
                    globChanged = True
        return globChanged

if __name__ == "__main__":

    if (len(sys.argv) < 3):
        print("usage: python3 tcpproxy.py <time_waiting in seconds> <domain_name>")
        exit(1)

    #Running
    print("Running communication thread ... ")
    threading.Thread(target=communicate).start()
    print("Listening ...")
    ThreadedServer('', 81,float(sys.argv[1]),sys.argv[2]).listen()




