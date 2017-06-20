/*
 * Copyright (c) 2017.
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

import burp.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpResponseFacade {
    private final static boolean DEBUG = false;
    private IBurpExtenderCallbacks callbacks;
    private IHttpRequestResponse msg;
    private byte[] modifiedResponse = null;
    private IResponseInfo responseInfo = null;
    private List<String> headers = null;
    private Map<String,Integer> headerIndices = new HashMap<String,Integer>(10);

    HttpResponseFacade(IBurpExtenderCallbacks callbacks, IHttpRequestResponse msg) {
        this.callbacks = callbacks;
        this.msg = msg;
    }

    byte[] getModifiedResponse(){
        return modifiedResponse;
    }

    private void debugOut(String msg) {
        if(DEBUG) {
            callbacks.printOutput(msg);
        }
    }

    public short getResponseCode() {
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(getCurrentResponseBytes());
        }
        return responseInfo.getStatusCode();
    }

    public void setResponseCode(int code, String statusReason) {
        try {
            byte[] responseBytes = getCurrentResponseBytes();
            int firstLF = -1;
            for (int i=0;i<50;i++) {
                if (responseBytes[i] == 13){
                    firstLF = i;
                }
            }
            if (firstLF > -1) {
                byte[] firstLineBytes = Arrays.copyOfRange(responseBytes, 0, firstLF);
                String firstLine = new String(firstLineBytes);
                String httpVersion = firstLine.substring(0, firstLine.indexOf(" "));
                String newFirstLine = httpVersion + " " + code + " " + statusReason;
                byte[] newFirstLineBytes = newFirstLine.getBytes();
                modifiedResponse = new byte[newFirstLineBytes.length + (responseBytes.length - firstLineBytes.length)];
                System.arraycopy(newFirstLineBytes, 0, modifiedResponse, 0, newFirstLineBytes.length);
                System.arraycopy(responseBytes, firstLF, modifiedResponse, newFirstLineBytes.length, responseBytes.length - firstLF);
                responseInfo = null;
            }
        }catch(Throwable t) {
            StringWriter errors = new StringWriter();
            t.printStackTrace(new PrintWriter(errors));
            callbacks.printError("Oops...");
            callbacks.printError(errors.toString());
        }
    }

    public String getHeader(String name){
        initHeaders();
        if (headerIndices.containsKey(name)) {
            return headers.get(headerIndices.get(name)).substring(name.length()+2).trim();
        }else {
            return null;
        }
    }

    private void initHeaders() {
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(getCurrentResponseBytes());
        }
        if(headers == null || headers.size() == 0) {
            headers = responseInfo.getHeaders();
            callbacks.printOutput("---start---");
            for(String header:headers) {
                callbacks.printOutput(header);
            }
            callbacks.printOutput("---end---");
            headerIndices.clear();
        }
        indexHeaders();
    }

    public void setHeader(String name, String value) {
        initHeaders();
        if(headerIndices.containsKey(name)) {
            int index = headerIndices.get(name);
            headers.set(index, name+": "+value);
        } else {
            headers.add(1, name+": "+value);
        }
        headerIndices.clear();
        updateResponseBytes();
    }

    private void updateResponseBytes(){
        StringBuilder buf = new StringBuilder();
        for(String header: headers) {
            buf.append(header);
            buf.append("\r\n");
        }
        buf.append("\r\n");
        byte[] headerBytes = buf.toString().getBytes();
        byte[] bodyBytes = getBodyBytes();
        modifiedResponse = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, modifiedResponse, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, modifiedResponse, headerBytes.length, bodyBytes.length);
    }

    private byte[] getBodyBytes() {
        byte[] responseBytes = getCurrentResponseBytes();
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);
        }
        int offset = responseInfo.getBodyOffset();
        return Arrays.copyOfRange(responseBytes, offset, responseBytes.length);
    }

    private byte[] getCurrentResponseBytes(){
        return modifiedResponse==null? msg.getResponse():modifiedResponse;
    }

    public String getCookie(String name){
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(getCurrentResponseBytes());
        }
        List<ICookie> cookies = responseInfo.getCookies();
        for (ICookie c: cookies) {
            if (name.equals(c.getName())){
                return c.getValue();
            }
        }
        return null;
    }

    public String getMimeType(){
        String statedMimeType = getStatedMimeType();
        return statedMimeType.isEmpty() ? getInferredMimeType():statedMimeType;
    }

    public String getStatedMimeType(){
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(getCurrentResponseBytes());
        }
        return responseInfo.getStatedMimeType();
    }

    public String getInferredMimeType(){
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(getCurrentResponseBytes());
        }
        return responseInfo.getInferredMimeType();
    }

    public int getBodyOffset(){
        if(responseInfo == null){
            responseInfo = callbacks.getHelpers().analyzeResponse(getCurrentResponseBytes());
        }
        return responseInfo.getBodyOffset();
    }

    public String getBody(){
        return new String(getBodyBytes());
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
