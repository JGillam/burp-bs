/*
 * Copyright (c) 2015.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.professionallyevil.burpbsh;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class HttpRequestFacade {

    private final static boolean DEBUG = false;
    private IBurpExtenderCallbacks callbacks;
    private IHttpRequestResponse msg;
    private byte[] modifiedRequest = null;
    private IRequestInfo requestInfo = null;
    private List<String> headers = null;
    private Map<String,Integer> headerIndices = new HashMap<String,Integer>(10);

    HttpRequestFacade(IBurpExtenderCallbacks callbacks, IHttpRequestResponse msg) {
        this.callbacks = callbacks;
        this.msg = msg;
    }

    public String getParam(String name){
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        IParameter param = callbacks.getHelpers().getRequestParameter(request, name);
        return param.getValue();
    }

    public void setUrlParam(String name, String value) {
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        Parameter param = new Parameter(name, value, IParameter.PARAM_URL);
        modifiedRequest = callbacks.getHelpers().updateParameter(request, param);
    }

    public void setPostParam(String name, String value) {
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        Parameter param = new Parameter(name, value, IParameter.PARAM_BODY);
        modifiedRequest = callbacks.getHelpers().updateParameter(request, param);
    }

    public String getCookie(String name){
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        IParameter param = callbacks.getHelpers().getRequestParameter(request, name);
        if(param.getType() == IParameter.PARAM_COOKIE) {
            return param.getValue();
        } else {
            return "";
        }
    }

    public void setCookie(String name, String value) {
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        Parameter param = new Parameter(name, value, IParameter.PARAM_COOKIE);
        modifiedRequest = callbacks.getHelpers().updateParameter(request, param);
        headerIndices.clear();
    }

    public void removeCookie(String name) {
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        Parameter param = new Parameter(name, "", IParameter.PARAM_COOKIE);
        modifiedRequest = callbacks.getHelpers().removeParameter(request, param);
        headerIndices.clear();
    }

    public URL getURL(){
        if(requestInfo == null){
            requestInfo = callbacks.getHelpers().analyzeRequest(msg);
        }
        return requestInfo.getUrl();
    }

    public String getMethod(){
        if(requestInfo == null){
            requestInfo = callbacks.getHelpers().analyzeRequest(msg);
        }
        return requestInfo.getMethod();
    }

    public void toggleMethod(){
        modifiedRequest = callbacks.getHelpers().toggleRequestMethod(modifiedRequest==null? msg.getRequest():modifiedRequest);
        headerIndices.clear();
    }

    public String getHeader(String name){
        initHeaders();
        //if(!name.endsWith(":")) {
        //    name = name + ":";
        //}

        if (headerIndices.containsKey(name)) {
            return headers.get(headerIndices.get(name)).substring(name.length()+2).trim();
        }else {
            return null;
        }
    }

    public void setHeader(String name, String value) {
        initHeaders();
        if (headerIndices.containsKey(name)) {  // set existing header
            int index = headerIndices.get(name);
            headers.set(index, name+": "+value);
        } else { // add new header
            headers.add(name+": "+value);
        }

        if(requestInfo == null){
            requestInfo = callbacks.getHelpers().analyzeRequest(msg);
        }
        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
       modifiedRequest =  callbacks.getHelpers().buildHttpMessage(headers, body);
    }

//    public String[] getPathParts() {
//        if(requestInfo == null) {
//            requestInfo = callbacks.getHelpers().analyzeRequest(msg);
//        }
//
//        URL url = requestInfo.getUrl();
//        return url.getPath().split("/");
//    }
//
//    public void setPathPart(int index, String value) {
//        String[] parts = getPathParts();
//        if (parts.length > index) {
//            parts[index] = value;
//        }
//
//
//        StringBuilder buf = new StringBuilder();
//        for (String part : parts) {
//            buf.append(part);
//            buf.append('/');
//        }
//        byte[] request = modifiedRequest==null? msg.getRequest():modifiedRequest;
//
//        modifiedRequest =  callbacks.getHelpers().
//
//
//    }


    byte[] getModifiedRequest(){
        return modifiedRequest;
    }

    private void debugOut(String msg) {
        if(DEBUG) {
            callbacks.printOutput(msg);
        }

    }

    private void initHeaders() {
        if(requestInfo == null){
            requestInfo = callbacks.getHelpers().analyzeRequest(msg);
        }
        if(headers == null || headers.size() == 0) {
            headers = requestInfo.getHeaders();
            headerIndices.clear();
        }

        indexHeaders();
    }

    private void indexHeaders() {
        debugOut("Checking index...");
        if(headerIndices.size() == 0) {
            for(int i=0;i<headers.size();i++) {
                String header = headers.get(i);
                debugOut("Indexing header: " + header);
                int delimit = header.indexOf(": ");
                if (delimit > 0) {
                    headerIndices.put(header.substring(0,delimit), i);
                    debugOut("Added header to index: " + header.substring(0, delimit));
                }
            }
        } else {
            debugOut("Header index > 0");
        }
    }
}
