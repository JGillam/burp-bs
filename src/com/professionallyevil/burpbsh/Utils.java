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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    IBurpExtenderCallbacks callbacks;

    public Utils(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }



    public String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public String md5(String message) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return bytesToHex(md.digest(message.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            callbacks.printError(e.getMessage());
            return "";
        }
    }

    public String increment(String value) {
        return increment(value, 1);
    }

    public String increment(String value, int step) {
        try {
            return String.valueOf(Long.parseLong(value) + step);
        }catch(RuntimeException e) {
            callbacks.printError("RuntimeError: " + e.getMessage());
            return "";
        }
    }

    public String urlDecode(String input) {
        return callbacks.getHelpers().urlDecode(input);
    }

    public void printError(String output) {
        callbacks.printError(output);
    }

    public void printOutput(String output) {
        callbacks.printOutput(output);
    }

}
