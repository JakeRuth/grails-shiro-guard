package com.commercehub.grails.shiro

import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.Permission

import java.util.concurrent.ConcurrentHashMap

class ConcurrentAuthorizationInfo implements AuthorizationInfo {

    protected Set<String> roles

    protected Set<String> stringPermissions

    protected Set<Permission> objectPermissions

    ConcurrentAuthorizationInfo() {
        initializeConcurrentSets()
    }

    ConcurrentAuthorizationInfo(Collection<String> roles) {
        initializeConcurrentSets()
        setRoles(roles)
    }

    private void initializeConcurrentSets() {
        // newSetFromMap creates a Set backed by a map whose properties including concurrency are preserved
        roles = Collections.newSetFromMap(new ConcurrentHashMap())
        stringPermissions = Collections.newSetFromMap(new ConcurrentHashMap())
        objectPermissions = Collections.newSetFromMap(new ConcurrentHashMap())
    }

    @Override
    Collection<String> getRoles() {
        return roles
    }

    @Override
    Collection<String> getStringPermissions() {
        return stringPermissions
    }

    @Override
    Collection<Permission> getObjectPermissions() {
        return objectPermissions
    }

    void setStringPermissions(Collection<String> stringPermissions) {
        this.stringPermissions.clear()
        this.stringPermissions.addAll(stringPermissions)
    }

    void setRoles(Collection<String> roles) {
        this.roles.clear()
        this.roles.addAll(roles)
    }

    void setObjectPermissions(Collection<Permission> objectPermissions) {
        this.objectPermissions.clear()
        this.objectPermissions.addAll(objectPermissions)
    }

    void addRole(String role) {
        roles << role
    }

    void addStringPermission(String permission) {
        stringPermissions << permission
    }

    void addObjectPermission(Permission objectPermission) {
        objectPermissions << objectPermission
    }
}
