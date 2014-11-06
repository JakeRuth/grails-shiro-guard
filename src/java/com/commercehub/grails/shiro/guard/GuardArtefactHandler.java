package com.commercehub.grails.shiro.guard;

import org.codehaus.groovy.grails.commons.ArtefactHandlerAdapter;

public class GuardArtefactHandler extends ArtefactHandlerAdapter {
    public static final String TYPE = "Guard";

    public GuardArtefactHandler() {
        super(TYPE, GrailsGuardClass.class, DefaultGrailsGuardClass.class, null);
    }

    public boolean isArtefactClass(Class clazz) {
        return clazz != null && clazz.getName().endsWith(TYPE);
    }
}