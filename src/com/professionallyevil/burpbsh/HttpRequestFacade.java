package com.professionallyevil.burpbsh;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

import java.net.URL;


public class HttpRequestFacade {

    IBurpExtenderCallbacks callbacks;
    IHttpRequestResponse msg;
    byte[] modifiedRequest = null;
    IRequestInfo requestInfo = null;

    public HttpRequestFacade(IBurpExtenderCallbacks callbacks, IHttpRequestResponse msg) {
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

    public URL getURL(){
        if(requestInfo == null){
            requestInfo = callbacks.getHelpers().analyzeRequest(msg);
        }
        return requestInfo.getUrl();
    }

    public byte[] getModifiedRequest(){
        return modifiedRequest;
    }
}
