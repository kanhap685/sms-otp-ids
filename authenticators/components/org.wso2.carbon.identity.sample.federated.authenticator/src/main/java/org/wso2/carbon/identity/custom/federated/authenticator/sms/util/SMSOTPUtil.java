package org.wso2.carbon.identity.custom.federated.authenticator.sms.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Improved utility class for SMS OTP operations
 * Provides cleaner, more organized helper methods
 */
public class SMSOTPUtil {

    private static final Log log = LogFactory.getLog(SMSOTPUtil.class);

    /**
     * Extracts mobile number from various sources
     * 
     * @param request HTTP request
     * @param username Username
     * @return Mobile number or null if not found
     */
    public static String extractMobileNumber(HttpServletRequest request, String username) {
        // First try to get from user profile
        if (StringUtils.isNotEmpty(username)) {
            try {
                String mobileFromProfile = SMSOTPUtils.getMobileNumberForUsername(username);
                if (StringUtils.isNotEmpty(mobileFromProfile)) {
                    return mobileFromProfile;
                }
            } catch (Exception e) {
                log.debug("Could not get mobile number from user profile: " + e.getMessage());
            }
        }
        
        // Then try to get from request parameters
        return request.getParameter(SMSOTPConstants.MOBILE_NUMBER);
    }

    /**
     * Formats mobile number for Thai format
     * 
     * @param mobileNumber Original mobile number
     * @return Formatted mobile number
     */
    public static String formatMobileNumber(String mobileNumber) {
        if (StringUtils.isEmpty(mobileNumber)) {
            return mobileNumber;
        }
        
        // Remove all non-digit characters
        String cleanNumber = mobileNumber.replaceAll("\\D", "");
        
        // For Thai mobile numbers, ensure proper format
        if (cleanNumber.length() == 10 && cleanNumber.startsWith("0")) {
            // Remove leading 0 and add country code for international format
            return "66" + cleanNumber.substring(1);
        }
        
        return cleanNumber;
    }

    /**
     * Masks sensitive values in content
     * 
     * @param content Content to mask
     * @param valuesToMask Values that should be masked
     * @return Masked content
     */
    public static String maskSensitiveValues(String content, String[] valuesToMask) {
        if (StringUtils.isEmpty(content) || valuesToMask == null || valuesToMask.length == 0) {
            return content;
        }
        
        String maskedContent = content;
        for (String value : valuesToMask) {
            if (StringUtils.isNotEmpty(value)) {
                maskedContent = maskedContent.replace(value, "***");
            }
        }
        
        return maskedContent;
    }

    /**
     * Builds error information from context
     * 
     * @param context Authentication context
     * @return Error information map
     */
    public static Map<String, String> buildErrorInfo(AuthenticationContext context) {
        Map<String, String> errorInfo = new HashMap<>();
        
        if (context != null) {
            Object errorCode = context.getProperty(SMSOTPConstants.ERROR_CODE);
            if (errorCode != null) {
                errorInfo.put("errorCode", errorCode.toString());
            }
            
            Object errorMessage = context.getProperty(SMSOTPConstants.ERROR_INFO);
            if (errorMessage != null) {
                errorInfo.put("errorMessage", errorMessage.toString());
            }
            
            Object codeMismatch = context.getProperty(SMSOTPConstants.CODE_MISMATCH);
            if (codeMismatch != null) {
                errorInfo.put("codeMismatch", codeMismatch.toString());
            }
            
            Object tokenExpired = context.getProperty(SMSOTPConstants.TOKEN_EXPIRED);
            if (tokenExpired != null) {
                errorInfo.put("tokenExpired", tokenExpired.toString());
            }
        }
        
        return errorInfo;
    }

    /**
     * Gets tenant-aware username
     * 
     * @param username Full username
     * @return Tenant-aware username
     */
    public static String getTenantAwareUsername(String username) {
        if (StringUtils.isEmpty(username)) {
            return username;
        }
        
        return MultitenantUtils.getTenantAwareUsername(username);
    }

    /**
     * Gets tenant domain from username
     * 
     * @param username Full username
     * @return Tenant domain
     */
    public static String getTenantDomain(String username) {
        if (StringUtils.isEmpty(username)) {
            return null;
        }
        
        return MultitenantUtils.getTenantDomain(username);
    }

    /**
     * Checks if SMS OTP is enabled for the user
     * 
     * @param context Authentication context
     * @param username Username to check
     * @return True if SMS OTP is enabled
     */
    public static boolean isSMSOTPEnabled(AuthenticationContext context, String username) {
        try {
            // Check if globally mandatory
            if (SMSOTPUtils.isSMSOTPMandatory(context)) {
                return true;
            }
            
            // Check user-specific setting
            if (StringUtils.isNotEmpty(username)) {
                boolean isUserControlEnabled = SMSOTPUtils.isSMSOTPEnableOrDisableByUser(context);
                if (isUserControlEnabled) {
                    return !SMSOTPUtils.isSMSOTPDisableForLocalUser(username, context);
                }
            }
            
            return false;
            
        } catch (Exception e) {
            log.warn("Error checking SMS OTP enabled status for user: " + username, e);
            return true; // Default to enabled if we can't determine
        }
    }

    /**
     * Builds URL with query parameters
     * 
     * @param baseUrl Base URL
     * @param queryParams Query parameters
     * @param authenticatorName Authenticator name
     * @return Complete URL
     */
    public static String buildURL(String baseUrl, String queryParams, String authenticatorName) {
        if (StringUtils.isEmpty(baseUrl)) {
            return null;
        }
        
        StringBuilder url = new StringBuilder(baseUrl);
        
        // Add query parameters
        if (StringUtils.isNotEmpty(queryParams)) {
            url.append(baseUrl.contains("?") ? "&" : "?");
            url.append(queryParams);
        }
        
        // Add authenticator parameter
        if (StringUtils.isNotEmpty(authenticatorName)) {
            url.append(url.toString().contains("?") ? "&" : "?");
            url.append("authenticator=").append(authenticatorName);
        }
        
        return url.toString();
    }

    /**
     * Validates OTP format
     * 
     * @param otpCode OTP code to validate
     * @param expectedLength Expected length
     * @return True if valid format
     */
    public static boolean isValidOTPFormat(String otpCode, int expectedLength) {
        if (StringUtils.isEmpty(otpCode)) {
            return false;
        }
        
        String cleanOtp = otpCode.trim();
        
        // Check length
        if (cleanOtp.length() != expectedLength) {
            return false;
        }
        
        // Check if contains only digits
        return cleanOtp.matches("\\d+");
    }

    /**
     * Gets the default OTP length
     * 
     * @return Default OTP length (4 digits)
     */
    public static int getDefaultOTPLength() {
        return 4;
    }

    /**
     * Gets the default OTP validity period in minutes
     * 
     * @return Default validity period (5 minutes)
     */
    public static int getDefaultOTPValidityMinutes() {
        return 5;
    }

    /**
     * Checks if mobile number update is allowed
     * 
     * @param context Authentication context
     * @return True if mobile number update is allowed
     */
    public static boolean isMobileNumberUpdateAllowed(AuthenticationContext context) {
        return SMSOTPUtils.isEnableMobileNoUpdate(context);
    }

    /**
     * Sanitizes error messages for display
     * 
     * @param errorMessage Original error message
     * @return Sanitized error message
     */
    public static String sanitizeErrorMessage(String errorMessage) {
        if (StringUtils.isEmpty(errorMessage)) {
            return "An error occurred during authentication";
        }
        
        // Remove any sensitive information patterns
        String sanitized = errorMessage.replaceAll("password|token|secret|key", "***");
        
        // Ensure the message is not too long
        if (sanitized.length() > 200) {
            sanitized = sanitized.substring(0, 200) + "...";
        }
        
        return sanitized;
    }

    /**
     * Checks if request is a resend request
     * 
     * @param request HTTP request
     * @return True if it's a resend request
     */
    public static boolean isResendRequest(HttpServletRequest request) {
        String resend = request.getParameter(SMSOTPConstants.RESEND);
        return StringUtils.isNotEmpty(resend);
    }

    /**
     * Gets configuration value with fallback
     * 
     * @param context Authentication context
     * @param configName Configuration name
     * @param defaultValue Default value if not found
     * @return Configuration value or default
     */
    public static String getConfigurationWithDefault(AuthenticationContext context, String configName, String defaultValue) {
        try {
            String value = SMSOTPUtils.getConfiguration(context, configName);
            return StringUtils.isNotEmpty(value) ? value : defaultValue;
        } catch (Exception e) {
            log.debug("Error getting configuration " + configName + ", using default: " + defaultValue);
            return defaultValue;
        }
    }

    /**
     * Logs debug information about the authentication context
     * 
     * @param context Authentication context
     * @param stage Current stage description
     */
    public static void logDebugInfo(AuthenticationContext context, String stage) {
        if (log.isDebugEnabled() && context != null) {
            log.debug("SMS OTP Authentication - " + stage + ":");
            log.debug("  Context ID: " + context.getContextIdentifier());
            log.debug("  Tenant Domain: " + context.getTenantDomain());
            log.debug("  Current Step: " + context.getCurrentStep());
            log.debug("  Is Retrying: " + context.isRetrying());
        }
    }
}
