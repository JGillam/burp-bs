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

import bsh.EvalError;
import bsh.Interpreter;
import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class BshExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener {
    private JPanel mainPanel;
    private JTextArea txtScript;
    private JTextArea txtTestRequest;
    private JButton buttonTest;
    private JCheckBox enableForRequestsCheckBox;
    private JTextArea txtTestModified;
    private IHttpRequestResponse testRequest = null;
    private IBurpExtenderCallbacks callbacks;
    private Interpreter interpreter;
    private static final String VERSION = "0.2.0";

    public BshExtender() {
        buttonTest.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(testRequest!=null) {
                    try {
                        HttpRequestFacade request = new HttpRequestFacade(callbacks, testRequest);
                        interpreter.set("request", request);
                        interpreter.eval(txtScript.getText());
                        byte[] modifiedMsg = request.getModifiedRequest();
                        if(modifiedMsg == null) {
                            txtTestModified.setText("(not modified)");
                        } else {
                            txtTestModified.setText(callbacks.getHelpers().bytesToString(modifiedMsg));
                        }
                    } catch (EvalError evalError) {
                        txtTestModified.setText("*** Error in line "+evalError.getErrorLineNumber()+": "+evalError.getErrorText());
                        callbacks.printError("bsh error: " + evalError.getErrorText());
                    }
                }
            }
        });
        enableForRequestsCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateProxyFilter();
            }
        });
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)  {
        this.callbacks = callbacks;
        callbacks.setExtensionName("BS (BeanShell)");
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);
        interpreter = new Interpreter();
        try {
            interpreter.set("utils", new Utils(callbacks));
            interpreter.set("storage", new HashMap());
        } catch (EvalError evalError) {
            callbacks.printError("Error including utils for bsh scripts. "+ evalError.getErrorText());
        }
        buttonTest.setEnabled(false);

        callbacks.printOutput("Burp BeanShell extension started.  Version: " + VERSION);
        updateProxyFilter();
    }

    @Override
    public String getTabCaption() {
        return "BS";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    private void setTestRequest(IHttpRequestResponse msg) {
        this.testRequest = msg;
        txtTestRequest.setText(callbacks.getHelpers().bytesToString(msg.getRequest()));
        buttonTest.setEnabled(true);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

        if (selectedMessages != null && selectedMessages.length > 0) {
            final List<IHttpRequestResponse> requestMessages = new ArrayList<IHttpRequestResponse>();
            List<JMenuItem> menuItems = new ArrayList<JMenuItem>();

            for (IHttpRequestResponse message : selectedMessages) {
                byte[] request = message.getRequest();
                if (request != null) {
                    requestMessages.add(message);
                }
            }

            if (requestMessages.size() > 0) {
                JMenuItem mi = new JMenuItem("Test in BS");
                mi.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        setTestRequest(requestMessages.get(0));
                    }
                });
                menuItems.add(mi);
            }

            return menuItems;

        }
        return null;
    }

    private void updateProxyFilter() {
        callbacks.removeHttpListener(this);
        if (enableForRequestsCheckBox.isSelected()) {
            callbacks.printOutput("beanshell script filtering on all requests...");
            callbacks.registerHttpListener(this);
        }else {
            callbacks.printOutput("beanshell script not filtering on requests...");
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        callbacks.printOutput("Received http message from " + toolFlag);
        if(messageIsRequest && enableForRequestsCheckBox.isSelected()) {
            HttpRequestFacade request = new HttpRequestFacade(callbacks, messageInfo);
            try {
                interpreter.set("request", request);
                interpreter.eval(txtScript.getText());

                byte[] modifiedMsg = request.getModifiedRequest();
                if(modifiedMsg != null) {
                    messageInfo.setRequest(modifiedMsg);  //todo: support responses... need to fix a few blocks to do it
                    callbacks.printOutput("Message updated.");
                }

            } catch (EvalError evalError) {
                callbacks.printError(evalError.getErrorText());
            }
        }
    }
}
