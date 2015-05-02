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

import burp.IParameter;

public class Parameter implements IParameter {

    private String name;
    private String value;
    private byte type;

    public Parameter(String name, String value, byte type) {
        this.name = name;
        this.value = value;
        this.type = type;
    }

    @Override
    public byte getType() {
        return type;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public int getNameStart() {
        return -1;
    }

    @Override
    public int getNameEnd() {
        return -1;
    }

    @Override
    public int getValueStart() {
        return -1;
    }

    @Override
    public int getValueEnd() {
        return -1;
    }
}
