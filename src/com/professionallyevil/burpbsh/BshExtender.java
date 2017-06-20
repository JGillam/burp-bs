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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
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
    private JLabel apiHelpLink;
    private JTextArea txtResponseScript;
    private JCheckBox enableForResponsesCheckBox;
    private JButton buttonResponseTest;
    private JTextArea txtTestResponseModified;
    private JTextArea txtTestResponse;
    private JLabel apiHelpLink2;
    private IHttpRequestResponse testRequest = null;
    private IHttpRequestResponse testResponse = null;
    private IBurpExtenderCallbacks callbacks;
    private Interpreter interpreter;
    private static final String VERSION = "0.3.0";

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
        buttonResponseTest.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(testResponse!=null) {
                    try {
                        HttpResponseFacade response = new HttpResponseFacade(callbacks, testResponse);
                        interpreter.set("response", response);
                        interpreter.eval(txtResponseScript.getText());
                        byte[] modifiedMsg = response.getModifiedResponse();
                        if(modifiedMsg == null) {
                            txtTestResponseModified.setText("(not modified)");
                        } else {
                            txtTestResponseModified.setText(callbacks.getHelpers().bytesToString(modifiedMsg));
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

        enableForResponsesCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateProxyFilter();
            }
        });

        apiHelpLink.addMouseListener(new MouseAdapter() {
        });

        apiHelpLink.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                executeLink("http://burpco2.com/burp-bs.html");
            }
        });

        txtScript.setTabSize(2);
        BeanScriptDocListener docListener = new BeanScriptDocListener(txtScript);
        txtScript.getDocument().addDocumentListener(docListener);

        txtResponseScript.setTabSize(2);
        BeanScriptDocListener docListener2 = new BeanScriptDocListener(txtResponseScript);
        txtResponseScript.getDocument().addDocumentListener(docListener2);
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
        buttonResponseTest.setEnabled(false);

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

    private void setTestResponse(IHttpRequestResponse msg) {
        this.testResponse = msg;
        txtTestResponse.setText(callbacks.getHelpers().bytesToString(msg.getResponse()));
        buttonResponseTest.setEnabled(true);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

        if (selectedMessages != null && selectedMessages.length > 0) {
            final List<IHttpRequestResponse> requestMessages = new ArrayList<IHttpRequestResponse>();
            final List<IHttpRequestResponse> responseMessages = new ArrayList<>();
            List<JMenuItem> menuItems = new ArrayList<JMenuItem>();

            for (IHttpRequestResponse message : selectedMessages) {
                byte[] request = message.getRequest();
                if (request != null) {
                    requestMessages.add(message);
                }

                byte[] response = message.getResponse();
                if (response != null) {
                    responseMessages.add(message);
                }
            }

            if (requestMessages.size() > 0) {
                JMenuItem mi = new JMenuItem("Test request in BS");
                mi.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        setTestRequest(requestMessages.get(0));
                    }
                });
                menuItems.add(mi);
            }

            if (responseMessages.size() > 0) {
                JMenuItem mi = new JMenuItem("Test response in BS");
                mi.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        setTestResponse(responseMessages.get(0));
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
        if (enableForRequestsCheckBox.isSelected() || enableForResponsesCheckBox.isSelected()) {
            callbacks.printOutput("beanshell script filtering on all requests...");
            callbacks.registerHttpListener(this);
        }else {
            callbacks.removeHttpListener(this);
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
        } else if(!messageIsRequest && enableForResponsesCheckBox.isSelected()) {
            HttpResponseFacade response = new HttpResponseFacade(callbacks, messageInfo);
            try {
                interpreter.set("response", response);
                interpreter.eval(txtResponseScript.getText());

                byte[] modifiedMsg = response.getModifiedResponse();
                if(modifiedMsg != null) {
                    messageInfo.setResponse(modifiedMsg);
                    callbacks.printOutput("Message updated.");
                }
            } catch (EvalError evalError) {
                callbacks.printError(evalError.getErrorText());
            }
        }
    }

    private void executeLink(String urlLink) {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            URI uri = URI.create(urlLink);
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                //e.printStackTrace();
                callbacks.printError("Link could not be followed: " + urlLink);
            }
        }
    }
}
