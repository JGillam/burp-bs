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
