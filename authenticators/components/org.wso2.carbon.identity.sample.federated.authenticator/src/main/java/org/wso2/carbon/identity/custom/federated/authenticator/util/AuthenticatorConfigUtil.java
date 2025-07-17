package org.wso2.carbon.identity.custom.federated.authenticator.util;

import org.wso2.carbon.identity.application.common.model.Property;

/**
 * Utility class for creating authenticator configuration properties
 */
public class AuthenticatorConfigUtil {

    /**
     * Creates a configuration property with the given parameters
     * 
     * @param name The property name
     * @param displayName The display name for the property
     * @param description The description of the property
     * @param required Whether the property is required
     * @param displayOrder The display order in the UI
     * @return The created Property object
     */
    public static Property createProperty(String name, String displayName, String description, 
                                        boolean required, int displayOrder) {
        Property property = new Property();
        property.setName(name);
        property.setDisplayName(displayName);
        property.setDescription(description);
        property.setRequired(required);
        property.setDisplayOrder(displayOrder);
        return property;
    }

    /**
     * Creates a confidential property (for sensitive data like passwords)
     * 
     * @param name The property name
     * @param displayName The display name for the property
     * @param description The description of the property
     * @param required Whether the property is required
     * @param displayOrder The display order in the UI
     * @return The created Property object with confidential flag set
     */
    public static Property createConfidentialProperty(String name, String displayName, String description, 
                                                    boolean required, int displayOrder) {
        Property property = createProperty(name, displayName, description, required, displayOrder);
        property.setConfidential(true);
        return property;
    }
}
