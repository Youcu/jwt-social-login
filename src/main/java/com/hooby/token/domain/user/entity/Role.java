package com.hooby.token.domain.user.entity;

public enum Role {
    USER, ADMIN, MANAGER;

    @Override
    public String toString() {
        return "ROLE_" + name();
    }
}
