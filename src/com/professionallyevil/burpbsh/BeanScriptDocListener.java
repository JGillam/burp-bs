
/*
 * Copyright (c) 1995, 2008, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle or the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.professionallyevil.burpbsh;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BeanScriptDocListener implements DocumentListener {
    private enum Mode { INSERT, COMPLETION }

    private JTextArea textArea;
    private List<String> words = new ArrayList<String>();
    private static final String COMMIT_ACTION = "commit";
    private Mode mode = Mode.INSERT;

    public BeanScriptDocListener(JTextArea textArea){
        this.textArea = textArea;

        InputMap im = textArea.getInputMap();
        ActionMap am = textArea.getActionMap();
        im.put(KeyStroke.getKeyStroke("ENTER"), COMMIT_ACTION);
        am.put(COMMIT_ACTION, new CommitAction());

        words.add("hello");
        words.add("wonderer");
        words.add("world");
    }

    @Override
        public void insertUpdate(DocumentEvent ev) {
//            if (ev.getLength() != 1) {
//                return;
//            }
//
//            int pos = ev.getOffset();
//            String content = null;
//            try {
//                content = textArea.getText(0, pos + 1);
//            } catch (BadLocationException e) {
//                e.printStackTrace();
//            }
//
//            // Find where the word starts
//            int w;
//            for (w = pos; w >= 0; w--) {
//                if (! Character.isLetter(content.charAt(w))) {
//                    break;
//                }
//            }
//            if (pos - w < 1) {
//                // Too few chars
//                return;
//            }
//
//            String prefix = content.substring(w + 1).toLowerCase();
//            int n = Collections.binarySearch(words, prefix);
//            if (n < 0 && -n <= words.size()) {
//                String match = words.get(-n - 1);
//                if (match.startsWith(prefix)) {
//                    // A completion is found
//                    String completion = match.substring(pos - w);
//                    // We cannot modify Document from within notification,
//                    // so we submit a task that does the change later
//                    SwingUtilities.invokeLater(
//                            new CompletionTask(completion, pos + 1));
//                }
//            } else {
//                // Nothing found
//                mode = Mode.INSERT;
//            }
        }


    @Override
    public void removeUpdate(DocumentEvent e) {

    }

    @Override
    public void changedUpdate(DocumentEvent e) {

    }

    private class CompletionTask implements Runnable {
        String completion;
        int position;

        CompletionTask(String completion, int position) {
            this.completion = completion;
            this.position = position;
        }

        public void run() {
            textArea.insert(completion, position);
            textArea.setCaretPosition(position + completion.length());
            textArea.moveCaretPosition(position);
            mode = Mode.COMPLETION;
        }
    }

    private class CommitAction extends AbstractAction {
        public void actionPerformed(ActionEvent ev) {
            if (mode == Mode.COMPLETION) {
                int pos = textArea.getSelectionEnd();
                textArea.insert(" ", pos);
                textArea.setCaretPosition(pos + 1);
                mode = Mode.INSERT;
            } else {
                textArea.replaceSelection("\n");
            }
        }
    }

    private class TabAction extends AbstractAction {
        @Override
        public void actionPerformed(ActionEvent e) {
            int pos = textArea.getCaretPosition();
        }
    }
}
