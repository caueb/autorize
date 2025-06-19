#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from burp import IHttpRequestResponse

def isStatusCodesReturned(self, messageInfo, statusCodes):
    firstHeader = self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders()[0]
    if type(statusCodes) == list:
        for statusCode in statusCodes:
            if statusCode in firstHeader:
                return True
    elif type(statusCodes) == str or type(statusCodes) == unicode:
        # single status code
        if statusCodes in firstHeader:
                return True
    return False

def makeRequest(self, messageInfo, message):
    requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
    return self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https"), message)

def makeMessage(self, messageInfo, removeOrNot, authorizeOrNot):
    requestInfo = self._helpers.analyzeRequest(messageInfo)
    headers = list(requestInfo.getHeaders())  # always copy the list
    request_line = headers[0]  # e.g., GET /path?x=1 HTTP/1.1

    if removeOrNot:
        queryFlag = self.replaceQueryParam.isSelected()
        if queryFlag:
            param = self.replaceString.getText().split("=")
            paramKey = param[0]
            paramValue = param[1]
            pattern = r"([\?&]){}=.*?(?=[\s&])".format(paramKey)
            patchedHeader = re.sub(pattern, r"\1{}={}".format(paramKey, paramValue), request_line, count=1, flags=re.DOTALL)
            headers[0] = patchedHeader
        else:
            removeHeaders = self.replaceString.getText()
            removeHeaders = [header for header in removeHeaders.split() if header.endswith(':')]

            for header in headers[:]:
                for removeHeader in removeHeaders:
                    if header.lower().startswith(removeHeader.lower()):
                        headers.remove(header)

        if authorizeOrNot:
            # Match & Replace: HEADERS
            for v in self.badProgrammerMRModel.values():
                if v["type"] == "Headers (simple string):":
                    headers = map(lambda h: h.replace(v["match"], v["replace"]), headers)
                elif v["type"] == "Headers (regex):":
                    headers = map(lambda h: re.sub(v["regexMatch"], v["replace"], h), headers)

            # Match & Replace: URL
            for v in self.badProgrammerMRModel.values():
                if "URL" in v["type"]:
                    if v["regexMatch"]:
                        request_line = re.sub(v["regexMatch"], v["replace"], request_line)
                    else:
                        request_line = request_line.replace(v["match"], v["replace"])
            headers[0] = request_line  # update the request line after modification

            # Add temporary headers from text box (unless using query param replacement)
            if not queryFlag:
                for h in self.replaceString.getText().split("\n"):
                    if h.strip() != "":
                        headers.append(h)

    msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]

    # Match & Replace: BODY
    if authorizeOrNot and msgBody is not None:
        msgBody = self._helpers.bytesToString(msgBody)
        for v in self.badProgrammerMRModel.values():
            if v["type"] == "Body (simple string):":
                msgBody = msgBody.replace(v["match"], v["replace"])
            elif v["type"] == "Body (regex):":
                msgBody = re.sub(v["regexMatch"], v["replace"], msgBody)
        msgBody = self._helpers.stringToBytes(msgBody)

    return self._helpers.buildHttpMessage(headers, msgBody)


def getResponseHeaders(self, requestResponse):
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    return self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])

def getResponseBody(self, requestResponse):
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    return self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])

def getResponseContentLength(self, response):
    return len(response) - self._helpers.analyzeResponse(response).getBodyOffset()

def get_cookie_header_from_message(self, messageInfo):
    headers = list(self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders())
    for header in headers:
        if header.strip().lower().startswith("cookie:"):
            return header
    return None

def get_authorization_header_from_message(self, messageInfo):
    headers = list(self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders())
    for header in headers:
        if header.strip().lower().startswith("authorization:"):
            return header
    return None

class IHttpRequestResponseImplementation(IHttpRequestResponse):
    def __init__(self, service, req, res):
        self._httpService = service
        self._request = req
        self._response = res
        self._comment = None
        self._highlight = None

    def getComment(self):
        return self._comment

    def getHighlight(self):
        return self._highlight

    def getHttpService(self):
        return self._httpService

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self,c):
        self._comment = c

    def setHighlight(self,h):
        self._highlight = h

    def setHttpService(self,service):
        self._httpService = service

    def setRequest(self,req):
        self._request = req

    def setResponse(self,res):
        self._response = res
