package com.metanonia.jwtsample.service;

public interface AuthToken<T> {
    boolean validate();
    T getData();
}
