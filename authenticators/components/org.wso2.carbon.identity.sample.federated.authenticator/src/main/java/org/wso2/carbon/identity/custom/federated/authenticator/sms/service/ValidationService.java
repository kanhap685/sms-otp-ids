package org.wso2.carbon.identity.custom.federated.authenticator.sms.service;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.util.Map;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Service class for validation operations
 * Handles user validation, mobile number validation, and input validation
 */
public class ValidationService {

    private static final Log log = LogFactory.getLog(ValidationService.class);

    /**
     * Validates if a user exists in the system
     * For federated authenticator, we assume user exists since they come from external IdP
     * 
     * @param username Username to validate
     * @param tenantDomain Tenant domain
     * @return True if user exists
     */
    public boolean validateUserExists(String username, String tenantDomain) {
        if (StringUtils.isBlank(username)) {
            return false;
        }
        
        // For federated authenticator, we assume user exists since they come from external IdP
        if (log.isDebugEnabled()) {
            log.debug("Validating user existence for: " + username + " in tenant: " + tenantDomain + " (federated - assumed exists)");
        }
        
        return true;
    }

    /**
     * Validates mobile number format
     * 
     * @param mobileNumber Mobile number to validate
     * @return ValidationResult containing validation status and message
     */
    public ValidationResult validateMobileNumber(String mobileNumber) {
        if (StringUtils.isBlank(mobileNumber)) {
            return new ValidationResult(false, "Mobile number is required");
        }
        
        // Remove all non-digit characters for validation
        String cleanNumber = mobileNumber.replaceAll("\\D", "");
        
        // Check if it's a valid Thai mobile number
        if (cleanNumber.length() < 9 || cleanNumber.length() > 10) {
            return new ValidationResult(false, "Invalid mobile number format");
        }
        
        // Thai mobile numbers start with 06, 08, or 09
        if (cleanNumber.length() == 10 && !cleanNumber.startsWith("06") && 
            !cleanNumber.startsWith("08") && !cleanNumber.startsWith("09")) {
            return new ValidationResult(false, "Invalid Thai mobile number format");
        }
        
        return new ValidationResult(true, "Valid mobile number");
    }

    /**
     * Validates OTP input format
     * 
     * @param otpCode OTP code to validate
     * @param expectedLength Expected OTP length
     * @return ValidationResult containing validation status and message
     */
    public ValidationResult validateOTPFormat(String otpCode, int expectedLength) {
        if (StringUtils.isBlank(otpCode)) {
            return new ValidationResult(false, "OTP code is required");
        }
        
        String cleanOtp = otpCode.trim();
        
        // Check length
        if (cleanOtp.length() != expectedLength) {
            return new ValidationResult(false, 
                "OTP code must be exactly " + expectedLength + " digits");
        }
        
        // Check if it contains only digits
        if (!cleanOtp.matches("\\d+")) {
            return new ValidationResult(false, "OTP code must contain only numbers");
        }
        
        return new ValidationResult(true, "Valid OTP format");
    }

    /**
     * Validates authentication context
     * 
     * @param context Authentication context to validate
     * @return ValidationResult containing validation status and message
     */
    public ValidationResult validateAuthenticationContext(AuthenticationContext context) {
        if (context == null) {
            return new ValidationResult(false, "Authentication context is null");
        }
        
        if (StringUtils.isBlank(context.getTenantDomain())) {
            return new ValidationResult(false, "Tenant domain is missing");
        }
        
        if (StringUtils.isBlank(context.getContextIdentifier())) {
            return new ValidationResult(false, "Context identifier is missing");
        }
        
        return new ValidationResult(true, "Valid authentication context");
    }

    /**
     * Validates HTTP request parameters
     * 
     * @param request HTTP request to validate
     * @return ValidationResult containing validation status and message
     */
    public ValidationResult validateRequest(HttpServletRequest request) {
        if (request == null) {
            return new ValidationResult(false, "HTTP request is null");
        }
        
        String sessionDataKey = request.getParameter("sessionDataKey");
        if (StringUtils.isBlank(sessionDataKey)) {
            return new ValidationResult(false, "Session data key is missing");
        }
        
        return new ValidationResult(true, "Valid request");
    }

    /**
     * Validates if SMS OTP is mandatory for the user
     * 
     * @param context Authentication context
     * @param username Username to check
     * @return True if SMS OTP is mandatory
     */
    public boolean isSMSOTPMandatory(AuthenticationContext context, String username) {
        try {
            // Check if SMS OTP is globally mandatory
            if (SMSOTPUtils.isSMSOTPMandatory(context)) {
                return true;
            }
            
            // Check if user has disabled SMS OTP (if user control is enabled)
            if (StringUtils.isNotBlank(username)) {
                boolean isUserControlEnabled = SMSOTPUtils.isSMSOTPEnableOrDisableByUser(context);
                if (isUserControlEnabled) {
                    return !SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context);
                }
            }
            
            return false;
            
        } catch (Exception e) {
            log.warn("Error checking SMS OTP mandatory status for user: " + username, e);
            // Default to mandatory if we can't determine the status
            return true;
        }
    }

    /**
     * Validates tenant domain format
     * 
     * @param tenantDomain Tenant domain to validate
     * @return ValidationResult containing validation status and message
     */
    public ValidationResult validateTenantDomain(String tenantDomain) {
        if (StringUtils.isBlank(tenantDomain)) {
            return new ValidationResult(false, "Tenant domain is required");
        }
        
        // Basic tenant domain validation
        if (!tenantDomain.matches("^[a-zA-Z0-9.-]+$")) {
            return new ValidationResult(false, "Invalid tenant domain format");
        }
        
        return new ValidationResult(true, "Valid tenant domain");
    }

    /**
     * Extracts and validates username from different sources
     * 
     * @param context Authentication context
     * @return ExtractedUserInfo containing username and validation status
     */
    public ExtractedUserInfo extractAndValidateUsername(AuthenticationContext context) {
        String username = null;
        
        // Try to get username from previous authentication step
        if (context.getSequenceConfig() != null && context.getSequenceConfig().getStepMap() != null) {
            for (Map.Entry<Integer, StepConfig> entry : context.getSequenceConfig().getStepMap().entrySet()) {
                if (entry.getKey() < context.getCurrentStep() && 
                    entry.getValue().getAuthenticatedUser() != null) {
                    username = entry.getValue().getAuthenticatedUser().getUserName();
                    break;
                }
            }
        }
        
        // If not found, try context properties
        if (StringUtils.isBlank(username)) {
            Object contextUsername = context.getProperty("USER_NAME");
            if (contextUsername != null) {
                username = String.valueOf(contextUsername);
            }
        }
        
        // Validate the extracted username
        if (StringUtils.isBlank(username)) {
            return new ExtractedUserInfo(null, false, "Username not found in context");
        }
        
        // Get tenant-aware username
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        
        return new ExtractedUserInfo(tenantAwareUsername, true, "Username successfully extracted");
    }

    /**
     * Result class for validation operations
     */
    public static class ValidationResult {
        private boolean valid;
        private String message;
        
        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public String getMessage() {
            return message;
        }
        
        @Override
        public String toString() {
            return "ValidationResult{" +
                    "valid=" + valid +
                    ", message='" + message + '\'' +
                    '}';
        }
    }

    /**
     * Result class for username extraction
     */
    public static class ExtractedUserInfo {
        private String username;
        private boolean valid;
        private String message;
        
        public ExtractedUserInfo(String username, boolean valid, String message) {
            this.username = username;
            this.valid = valid;
            this.message = message;
        }
        
        public String getUsername() {
            return username;
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public String getMessage() {
            return message;
        }
        
        @Override
        public String toString() {
            return "ExtractedUserInfo{" +
                    "username='" + username + '\'' +
                    ", valid=" + valid +
                    ", message='" + message + '\'' +
                    '}';
        }
    }
}
