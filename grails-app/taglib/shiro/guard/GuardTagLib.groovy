package shiro.guard

import com.commercehub.grails.shiro.guard.GuardArtefactHandler
import grails.util.Holders
import org.apache.shiro.SecurityUtils

class GuardTagLib {

    static namespace = "guard"

    /**
     * @attr action REQUIRED
     * @attr id REQUIRED
     */
    def hasPermission = { attrs, body ->
        String controller = attrs?.controller ?: controllerName
        String action = attrs.action
        String id = attrs.id

        def guardBean = Holders.applicationContext.getBean(controller + GuardArtefactHandler.TYPE)
        String permissionString = guardBean.buildPermissionString(action, [id: id])

        if (SecurityUtils.subject.isPermitted(permissionString)) {
            out << body()
        }
        else if (guardBean.hasPermission(action, [id: id])) {
            out << body()
        }
    }

}
