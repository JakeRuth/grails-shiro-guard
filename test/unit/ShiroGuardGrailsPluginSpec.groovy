import com.commercehub.grails.shiro.ConcurrentAuthorizationInfo
import com.commercehub.grails.shiro.guard.GuardArtefactHandler
import grails.util.Holders
import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.cache.Cache
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.subject.SimplePrincipalMap
import org.apache.shiro.web.mgt.DefaultWebSecurityManager
import org.codehaus.groovy.grails.commons.DefaultGrailsApplication
import org.springframework.context.support.GenericApplicationContext
import org.apache.shiro.subject.Subject
import spock.lang.Specification

class ShiroGuardGrailsPluginSpec extends Specification {

    def "deny access to non-guarded controllers"() {
        given:
            def defaultGrailsApplication = new DefaultGrailsApplicationHelper()
            defaultGrailsApplication.initDefaultArtefactHandlers()
            defaultGrailsApplication.addArtefact("Controller", TestController)

            def applicationContext = Mock(GenericApplicationContext)
            applicationContext.getBean("grailsApplication") >> defaultGrailsApplication

            GroovyMock(Holders, global: true)
            Holders.getApplicationContext() >> applicationContext

            def grailsShiroGuardPlugin = getShiroGuardGrailsPluginInstance()

        expect:
            !grailsShiroGuardPlugin.guardedAccessControl([controllerName: "Test"])
    }

    @SuppressWarnings("GroovyPointlessBoolean")
    def "if the controller is guarded, see if they already have the permission, if not ask the guard if they should"() {
        given:
            def guardArtefactType = "Guard"
            def samplePermissionString = "sample:permission:string"

            def testBean = new TestBean(hasPermission: shouldHavePermission)

            def defaultGrailsApplication = new DefaultGrailsApplicationHelper()
            defaultGrailsApplication.initDefaultArtefactHandlers()
            defaultGrailsApplication.addArtefact("Controller", TestController)

            def guardArtefactHandler =  new GuardArtefactHandler()
            defaultGrailsApplication.registerArtefactHandler(guardArtefactHandler)
            defaultGrailsApplication.addArtefact(guardArtefactType, TestGuard)

            def principalCollection = new SimplePrincipalMap()
            principalCollection.put('samplePrinciple', new Object())

            def authorizationInfo = new ConcurrentAuthorizationInfo()
            authorizationInfo.setStringPermissions(['1', '2', '3'] as Set<String>)

            def subject = Mock(Subject)
            subject.getPrincipal() >> principalCollection
            subject.getPrincipals() >> principalCollection
            subject.isPermitted(samplePermissionString) >> alreadyHasPermission

            def cache = new FakeShiroCache(
                    principalCollection: principalCollection, authorizationInfo: authorizationInfo)

            def fakeAuthorizingRealm = new FakeAuthorizingRealm(cache: cache)

            def shiroSecurityManager = Mock(DefaultWebSecurityManager)
            shiroSecurityManager.getAuthorizer() >> fakeAuthorizingRealm

            def applicationContext = Mock(GenericApplicationContext)
            applicationContext.getBean("testGuard") >> testBean
            applicationContext.getBean("grailsApplication") >> defaultGrailsApplication
            applicationContext.getBean("shiroSecurityManager") >> shiroSecurityManager

            GroovyMock(Holders, global: true)
            Holders.getApplicationContext() >> applicationContext

            GroovyMock(SecurityUtils, global: true)
            SecurityUtils.getSubject() >> subject

            def grailsShiroGuardPlugin = getShiroGuardGrailsPluginInstance()

        expect:
            grailsShiroGuardPlugin.guardedAccessControl([controllerName: "test"]) == shouldHavePermission

        where:
            alreadyHasPermission || shouldHavePermission
            true                 || true
            false                || true
            false                || false
    }

    def "ensure that dynamically added permissions in Shiro's cached session are actually added"() {
        given:
            def principalCollection = new SimplePrincipalMap()

            def subject = Mock(Subject)
            subject.getPrincipals() >> principalCollection

            GroovyMock(SecurityUtils, global: true)
            SecurityUtils.getSubject() >> subject

            def authorizationInfo = new ConcurrentAuthorizationInfo()
            authorizationInfo.setStringPermissions(['1', '2', '3'] as Set<String>)

            def cache = new FakeShiroCache(
                    principalCollection: principalCollection, authorizationInfo: authorizationInfo)

            def fakeAuthorizingRealm = new FakeAuthorizingRealm(cache: cache)

            def shiroSecurityManager = Mock(DefaultWebSecurityManager)
            shiroSecurityManager.getAuthorizer() >> fakeAuthorizingRealm

            def applicationContext = Mock(GenericApplicationContext)
            applicationContext.getBean("shiroSecurityManager") >> shiroSecurityManager

            GroovyMock(Holders, global: true)
            Holders.getApplicationContext() >> applicationContext

            def grailsShiroGuardPlugin = getShiroGuardGrailsPluginInstance()

        when:
            grailsShiroGuardPlugin.addPermissionStringForCurrentSession(permStringToAdd)

        then:
            fakeAuthorizingRealm.getAuthorizationCache()
                    .get(principalCollection)
                    .stringPermissions
                    .containsAll(permStringToAdd)

        where:
            permStringToAdd | _
            '4'             | _
            '7'             | _
            ''              | _
    }

    private getShiroGuardGrailsPluginInstance() {
        def gcl = new GroovyClassLoader()
        def shiroGuardPluginDir = new File('.')
        gcl.addClasspath(shiroGuardPluginDir.canonicalPath)
        def grailsShiroGuardPluginClass = gcl.loadClass('ShiroGuardGrailsPlugin')
        return grailsShiroGuardPluginClass.newInstance()
    }

}

class FakeShiroCache implements Cache {

    PrincipalCollection principalCollection
    ConcurrentAuthorizationInfo authorizationInfo

    @Override
    Object get(Object o) {
        if (o == principalCollection) {
            return authorizationInfo
        } else {
            throw new RuntimeException("Received unexpected collection")
        }
    }

    @Override
    Object put(Object o, Object o2) {
        return null
    }

    @Override
    Object remove(Object o) {
        return null
    }

    @Override
    void clear() {
    }

    @Override
    int size() {
        return 0
    }

    @Override
    Set keys() {
        return null
    }

    @Override
    Collection values() {
        return null
    }

}

class FakeAuthorizingRealm extends AuthorizingRealm {

    FakeShiroCache cache

    FakeAuthorizingRealm() {
        this.cache = cache
    }

    FakeShiroCache getAuthorizationCache() {
        return cache
    }

    AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) {
        return null
    }

    AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null
    }

}

class TestController {
}

class TestGuard {
}

class TestBean {

    boolean hasPermission

    @SuppressWarnings("GroovyUnusedDeclaration")
    String buildPermissionString(String actionName, Map<String, String> params) {
        return "sample:permission:string"
    }

    @SuppressWarnings("GroovyUnusedDeclaration")
    boolean hasPermission(String actionName, Map<String, String> params) {
        return hasPermission ?: false
    }

}

class DefaultGrailsApplicationHelper extends DefaultGrailsApplication {

    void initDefaultArtefactHandlers() {
        super.initArtefactHandlers()
    }

}
