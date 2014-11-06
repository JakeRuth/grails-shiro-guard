package com.commercehub.grails.shiro.guard;

import java.util.Map;

public interface GrailsGuardClass {

    /*
     * this method will optionally check and incoming params to determine whether or not the
     * current user should be given access to a page
     */
    boolean hasPermission(String actionName, Map<String, String> params);

    /*
     * this method builds out the permission shiro string
     */
    String buildPermissionString(String actionName, Map<String, String> params);

}
