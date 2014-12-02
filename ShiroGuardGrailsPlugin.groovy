import com.commercehub.grails.shiro.ConcurrentAuthorizationInfo
import com.commercehub.grails.shiro.guard.GuardArtefactHandler
import grails.util.Holders
import org.apache.shiro.SecurityUtils
import org.apache.shiro.realm.AuthorizingRealm
import org.codehaus.groovy.grails.plugins.web.filters.FilterConfig

class ShiroGuardGrailsPlugin {

    def version = "0.0.3"

    def grailsVersion = "2.2.4 > *"

    def pluginExcludes = [
            "grails-app/views/error.gsp"
    ]

    def title = "Grails Shiro Guard Plugin"
    def author = "Jake Ruth"
    def authorEmail = "jruth@commercehub.com"
    def description = 'This plugin is built on top of shiro.  ' +
            'It provides a grails guard artifact that is used to guard access to your controllers using shiro permission strings.'

    def documentation = 'http://commercehub-oss.github.io/grails-shiro-guard/'
    def issueManagement = [ url: 'https://github.com/commercehub-oss/grails-shiro-guard/issues' ]
    def scm = [ url: 'https://github.com/commercehub-oss/grails-shiro-guard' ]
    def license = 'APACHE'
    def organization = [ name: "CommerceHub", url: "http://www.commercehub.com/" ]

    def artefacts = [ GuardArtefactHandler ]

    def watchedResources = [
            "file:./grails-app/guards/**/*Guard.groovy"
    ]

    def doWithApplicationContext = { ctx ->
        application.getArtefacts(GuardArtefactHandler.TYPE).each { guardClass ->
            def guardBeans = beans {
                "${guardClass.propertyName}"(guardClass.clazz) { bean ->
                    bean.autowire = "byName"
                }
            }

            ctx.registerBeanDefinition("${guardClass.propertyName}", guardBeans.getBeanDefinition("${guardClass.propertyName}"))
        }
    }

    def doWithDynamicMethods = { ctx ->
        // Add a 'guardedAccessControl' method to FilterConfig (so that it's available from Grails filters).
        def mc = FilterConfig.metaClass

        mc.guardedAccessControl << { -> return guardedAccessControlMethod(delegate) }
        mc.guardedAccessControl << { Map args -> return guardedAccessControlMethod(delegate, args) }
        mc.guardedAccessControl << { Closure c -> return guardedAccessControlMethod(delegate, [:], c) }
        mc.guardedAccessControl << { Map args, Closure c -> return guardedAccessControlMethod(delegate, args, c) }
    }

    boolean guardedAccessControlMethod(filter, Map args = [:], Closure c = null) {
        if (guardedAccessControl(filter)) {
            return true
        } else {
            // Default to original Shiro Access control:
            // (1) - when the request to a controller did not have a guard class
            // (2) - a controller was guarded and the user was not allowed access (url hacker's get caught here)
            return filter.accessControl(args, c)
        }
    }

    boolean guardedAccessControl(def filter) {
        def params = filter.params
        String controllerName = filter.controllerName
        String actionName = filter.actionName
        String packageName = getPackageNameForController(controllerName)

        String guardArtefactIdentifier = getGuardArtefactIdentifier(packageName, controllerName)
        def guardArtefact = getGuardArtefact(guardArtefactIdentifier)

        if (guardArtefact && isUserAuthenticated()) {
            try {
                def guardBean = Holders.applicationContext.getBean(controllerName + GuardArtefactHandler.TYPE)
                String permissionString = guardBean.buildPermissionString(actionName, params)

                if (currentUserHasPermission(permissionString)) {
                    return true
                } else {
                    boolean isUserPermitted = guardBean.hasPermission(actionName, params)

                    if (isUserPermitted) {
                        addPermissionStringForCurrentSession(permissionString)
                    }
                    return isUserPermitted
                }
            } catch (IllegalArgumentException ex) {
                return false
            }
        }
        return false
    }

    public void addPermissionStringForCurrentSession(String permission) {
        def shiroSecurityManager = Holders.applicationContext.getBean('shiroSecurityManager')
        def authorizingRealm = shiroSecurityManager.authorizer as AuthorizingRealm
        def uniqueShiroAttributesForCurrentUser = SecurityUtils.subject.principals
        def currentPermissions = authorizingRealm.authorizationCache.get( uniqueShiroAttributesForCurrentUser) as ConcurrentAuthorizationInfo

        currentPermissions.addStringPermission(permission)
    }

    private def getGuardArtefact(String guardArtefactIdentifier) {
        def grailsApplication = Holders.applicationContext.getBean('grailsApplication')

        return grailsApplication.getArtefact(GuardArtefactHandler.TYPE, guardArtefactIdentifier)
    }

    private boolean isUserAuthenticated() {
        def grailsApplication = Holders.applicationContext.getBean('grailsApplication')
        def subject = SecurityUtils.subject
        boolean isUserLoggedIn = subject?.principal != null
        boolean authcRequired = true

        if (grailsApplication.config.security.shiro.authc.required instanceof Boolean) {
            authcRequired = grailsApplication.config.security.shiro.authc.required
        }

        return isUserLoggedIn || (!authcRequired && subject.authenticated)
    }

    private boolean currentUserHasPermission(String permission) {
        return SecurityUtils.subject.isPermitted(permission)
    }

    private String getPackageNameForController(String controllerName) {
        def grailsApplication = Holders.applicationContext.getBean('grailsApplication')

        def controller = grailsApplication.controllerClasses.find { controller ->
            return controller.name.equalsIgnoreCase(controllerName)
        }

        return controller.packageName
    }

    private getGuardArtefactIdentifier(String packageName, String controllerName) {
        String identifier

        if (packageName.size()) {
            identifier = "${packageName}.${controllerName.capitalize()}" + GuardArtefactHandler.TYPE
        } else {
            identifier = controllerName.capitalize() + GuardArtefactHandler.TYPE
        }
        return identifier
    }

}
