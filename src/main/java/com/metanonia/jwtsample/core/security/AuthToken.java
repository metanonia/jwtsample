package com.metanonia.jwtsample.core.security;

public interface AuthToken<T> {
    boolean validate();
    T getData();
}