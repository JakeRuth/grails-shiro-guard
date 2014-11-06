package com.commercehub.grails.shiro.guard;

import org.codehaus.groovy.grails.commons.AbstractInjectableGrailsClass;

import java.util.Map;

public class DefaultGrailsGuardClass extends AbstractInjectableGrailsClass implements GrailsGuardClass {

    public DefaultGrailsGuardClass(Class c) {
        super(c, GuardArtefactHandler.TYPE);
    }

    public boolean hasPermission(String actionName, Map<String, String> params) {
        return false;
    }

    public String buildPermissionString(String actionName, Map<String, String> params) {
        return "";
    }

}
