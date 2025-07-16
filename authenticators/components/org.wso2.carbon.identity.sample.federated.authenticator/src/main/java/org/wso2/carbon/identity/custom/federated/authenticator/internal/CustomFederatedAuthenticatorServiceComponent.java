package org.wso2.carbon.identity.custom.federated.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.custom.federated.authenticator.CustomFederatedAuthenticator;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;

@Component(
        name = "custom.federated.authenticator",
        immediate = true
)
public class CustomFederatedAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(CustomFederatedAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            CustomFederatedAuthenticator customFederatedAuthenticator = new CustomFederatedAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customFederatedAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("Custom Federated Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating custom federated authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Custom federated Authenticator bundle is deactivated");
        }
    }
}
