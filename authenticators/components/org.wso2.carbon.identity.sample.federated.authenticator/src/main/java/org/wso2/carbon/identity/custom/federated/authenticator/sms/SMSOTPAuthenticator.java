package org.wso2.carbon.identity.custom.federated.authenticator.sms;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.custom.federated.authenticator.CustomFederatedAuthenticator;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.model.SMSResponse;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.OTPService;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.SMSService;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.ValidationService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Refactored SMS OTP Authenticator with better structure and cleaner functions
 * 
 * This class handles SMS OTP authentication with improved:
 * - Separation of concerns using service classes
 * - Better error handling and validation
 * - Cleaner method structure
 * - Improved readability and maintainability
 */
public class SMSOTPAuthenticator implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SMSOTPAuthenticator.class);

    // Service instances
    private final OTPService otpService;
    private final SMSService smsService;
    private final ValidationService validationService;

    /**
     * Constructor with dependency injection
     */
    public SMSOTPAuthenticator() {
        this.otpService = new OTPService();
        this.smsService = new SMSService();
        this.validationService = new ValidationService();
    }

    /**
     * Checks if this authenticator can handle the current request
     * 
     * @param request HTTP request
     * @return true if can handle, false otherwise
     */
    public boolean canHandle(HttpServletRequest request) {
        return hasOTPParameter(request) || 
               hasResendParameter(request) || 
               hasMobileNumberParameter(request);
    }

    /**
     * Returns the friendly name of this authenticator
     */
    public String getFriendlyName() {
        return "SMSOTP-IDS";
    }

    /**
     * Returns the name of this authenticator
     */
    public String getName() {
        return "SMSOTP-IDS";
    }

    /**
     * Returns the claim dialect URI
     */
    public String getClaimDialectURI() {
        return SMSOTPConstants.OIDC_DIALECT;
    }

    /**
     * Returns configuration properties for this authenticator
     */
    public List<Property> getConfigurationProperties() {
        List<Property> properties = new ArrayList<>();
        
        properties.add(createProperty(SMSOTPConstants.SMS_URL, "SMS URL", 
                "Enter client SMS URL value. Use $ctx.num for phone number and $ctx.msg for message", true, 0));
        
        properties.add(createProperty(SMSOTPConstants.HTTP_METHOD, "HTTP Method", 
                "Enter the HTTP Method used by the SMS API", true, 1));
        
        properties.add(createProperty(SMSOTPConstants.HEADERS, "HTTP Headers", 
                "Enter headers separated by comma. Use $ctx.num and $ctx.msg for placeholders", false, 2));
        
        properties.add(createProperty(SMSOTPConstants.PAYLOAD, "HTTP Payload", 
                "Enter HTTP Payload for SMS API. Use $ctx.num and $ctx.msg for placeholders", false, 3));
        
        properties.add(createProperty(SMSOTPConstants.HTTP_RESPONSE, "HTTP Response Code", 
                "Enter expected HTTP response code for successful SMS", false, 4));
        
        properties.add(createProperty(SMSOTPConstants.SHOW_ERROR_INFO, "Show Detailed Error Information", 
                "Enter \"true\" if detailed error information from SMS provider needs to be displayed in the UI", false, 5));
        
        properties.add(createProperty(SMSOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO, "Mask values in Error Info", 
                "Enter comma separated Values to be masked by * in the detailed error messages", false, 6));
        
        return properties;
    }

    /**
     * Initiates the authentication request
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param context Authentication context
     * @throws AuthenticationFailedException if authentication fails
     */
    public void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationContext context) throws AuthenticationFailedException {
        try {
            handleSMSOTPAuthentication(request, response, context);
        } catch (Exception e) {
            log.error("Error processing authentication request", e);
            throw new AuthenticationFailedException("Error processing authentication request", e);
        }
    }

    /**
     * Main SMS OTP authentication handler
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param context Authentication context
     * @throws AuthenticationFailedException if authentication fails
     */
    public void handleSMSOTPAuthentication(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws AuthenticationFailedException {
        
        // Clean up any existing session data to prevent conflicts
        cleanupSessionData(context);
        
        // Validate context
        ValidationService.ValidationResult contextValidation = validationService.validateAuthenticationContext(context);
        if (!contextValidation.isValid()) {
            throw new AuthenticationFailedException(contextValidation.getMessage());
        }

        String queryParams = buildQueryParams(context);
        
        try {
            // Extract and validate user information
            getAuthenticatedUser(context); // Ensure authenticated user is available
            String username = extractUsername(context);
            String tenantDomain = context.getTenantDomain();
            
            // Validate user exists
            if (!validationService.validateUserExists(username, tenantDomain)) {
                redirectToErrorPage(response, context, queryParams, "User not found in the system");
                return;
            }
            
            // Get and validate mobile number
            String mobileNumber = getUserMobileNumber(request, response, context, username, tenantDomain, queryParams);
            if (StringUtils.isEmpty(mobileNumber)) {
                // getMobileNumber handles redirection if needed
                return;
            }
            
            // Proceed with SMS OTP sending
            sendSMSOTP(response, context, mobileNumber, queryParams, username);
            
        } catch (Exception e) {
            log.error("Error in SMS OTP authentication: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "Authentication failed: " + e.getMessage());
        }
    }

    /**
     * Processes the authentication response (OTP validation)
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param context Authentication context
     * @throws AuthenticationFailedException if authentication fails
     */
    public void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationContext context) throws AuthenticationFailedException {
        
        if (log.isDebugEnabled()) {
            log.debug("Processing SMS OTP authentication response");
        }

        // Add synchronization to prevent concurrent session conflicts
        synchronized (this) {
            try {
                processOTPValidation(request, response, context);
            } catch (Exception e) {
                if (e.getMessage() != null && e.getMessage().contains("Unique index or primary key violation")) {
                    log.warn("Session conflict detected, retrying after cleanup: " + e.getMessage());
                    // Clean up and retry once
                    cleanupSessionData(context);
                    try {
                        Thread.sleep(100); // Brief delay
                        processOTPValidation(request, response, context);
                    } catch (Exception retryE) {
                        log.error("Retry failed after session cleanup: " + retryE.getMessage(), retryE);
                        throw new AuthenticationFailedException("Authentication failed due to session conflict", retryE);
                    }
                } else {
                    throw e;
                }
            }
        }
    }

    /**
     * Internal OTP validation processing
     */
    private void processOTPValidation(HttpServletRequest request, HttpServletResponse response,
                                    AuthenticationContext context) throws AuthenticationFailedException {

        String queryParams = buildQueryParams(context);
        
        // Extract OTP from request
        String userOTP = extractOTPFromRequest(request);
        String storedOTP = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
        
        // Enhanced logging for debugging
        log.info("SMS OTP Validation Debug:");
        log.info("  - User OTP from request: '" + userOTP + "'");
        log.info("  - Stored OTP in context: '" + storedOTP + "'");
        log.info("  - User OTP length: " + (userOTP != null ? userOTP.length() : "null"));
        log.info("  - Stored OTP length: " + (storedOTP != null ? storedOTP.length() : "null"));
        
        // Get authenticated user
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        if (authenticatedUser == null) {
            log.error("SMS OTP Validation Error: AuthenticatedUser is null in context");
            redirectToErrorPage(response, context, queryParams, "Authentication session expired. Please try again.");
            return;
        }
        
        // Validate OTP
        Long sentTime = (Long) context.getProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME);
        Long validityPeriod = (Long) context.getProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME);
        
        log.info("SMS OTP Context Properties:");
        log.info("  - Sent Time: " + sentTime);
        log.info("  - Validity Period: " + validityPeriod);
        
        OTPService.OTPValidationResult validationResult = otpService.validateOTP(userOTP, storedOTP, sentTime, validityPeriod);
        
        log.info("SMS OTP Validation Result:");
        log.info("  - Is Valid: " + validationResult.isValid());
        log.info("  - Message: " + validationResult.getMessage());
        
        if (!validationResult.isValid()) {
            log.warn("SMS OTP Validation Failed: " + validationResult.getMessage());
            redirectToErrorPage(response, context, queryParams, validationResult.getMessage());
            return;
        }
        
        // OTP validation successful
        log.info("SMS OTP Validation Successful for user: " + authenticatedUser.getUserName());
        handleSuccessfulAuthentication(context, authenticatedUser);
    }

    /**
     * Gets the context identifier from request
     */
    public String getContextIdentifier(HttpServletRequest request) {
        // Check OAuth2 state parameter
        String state = request.getParameter(SMSOTPConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 0) {
                return stateElements[0];
            }
        }
        
        // Check session data key
        String sessionDataKey = request.getParameter("sessionDataKey");
        if (StringUtils.isNotBlank(sessionDataKey)) {
            return sessionDataKey;
        }
        
        return null;
    }

    // ===== PRIVATE HELPER METHODS =====

    /**
     * Checks if request has OTP parameter
     */
    private boolean hasOTPParameter(HttpServletRequest request) {
        return StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.CODE)) ||
               StringUtils.isNotEmpty(request.getParameter("OTPcode"));
    }

    /**
     * Checks if request has resend parameter
     */
    private boolean hasResendParameter(HttpServletRequest request) {
        String resend = request.getParameter(SMSOTPConstants.RESEND);
        return StringUtils.isNotEmpty(resend);
    }

    /**
     * Checks if request has mobile number parameter
     */
    private boolean hasMobileNumberParameter(HttpServletRequest request) {
        return StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.MOBILE_NUMBER));
    }

    /**
     * Creates a property for configuration
     */
    private Property createProperty(String name, String displayName, String description, boolean required, int order) {
        Property property = new Property();
        property.setName(name);
        property.setDisplayName(displayName);
        property.setDescription(description);
        property.setRequired(required);
        property.setDisplayOrder(order);
        return property;
    }

    /**
     * Builds query parameters for redirects
     */
    private String buildQueryParams(AuthenticationContext context) {
        return FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(),
                context.getCallerSessionKey(),
                context.getContextIdentifier());
    }

    /**
     * Gets authenticated user from context
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        
        if (authenticatedUser == null && context.getSequenceConfig() != null) {
            Map<Integer, org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig> stepMap = 
                    context.getSequenceConfig().getStepMap();
            
            if (stepMap != null) {
                for (Map.Entry<Integer, org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig> entry : 
                     stepMap.entrySet()) {
                    if (entry.getKey() < context.getCurrentStep() && entry.getValue().getAuthenticatedUser() != null) {
                        authenticatedUser = entry.getValue().getAuthenticatedUser();
                        context.setProperty(SMSOTPConstants.AUTHENTICATED_USER, authenticatedUser);
                        break;
                    }
                }
            }
        }
        
        return authenticatedUser;
    }

    /**
     * Extracts username from context
     */
    private String extractUsername(AuthenticationContext context) throws AuthenticationFailedException {
        ValidationService.ExtractedUserInfo userInfo = validationService.extractAndValidateUsername(context);
        
        if (!userInfo.isValid()) {
            throw new AuthenticationFailedException(userInfo.getMessage());
        }
        
        return userInfo.getUsername();
    }

    /**
     * Gets user mobile number
     */
    private String getUserMobileNumber(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context, String username, String tenantDomain,
                                     String queryParams) throws AuthenticationFailedException {
        
        try {
            String mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
            
            if (StringUtils.isEmpty(mobileNumber)) {
                // Check if mobile number is provided in request
                String requestMobileNumber = request.getParameter(SMSOTPConstants.MOBILE_NUMBER);
                if (requestMobileNumber != null) {
                    // Update user's mobile number
                    updateUserMobileNumber(context, request, username, tenantDomain);
                    mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
                } else {
                    // Redirect to mobile number request page
                    redirectToMobileNumberRequestPage(response, context, queryParams);
                    return null;
                }
            }
            
            // Validate mobile number format
            ValidationService.ValidationResult mobileValidation = validationService.validateMobileNumber(mobileNumber);
            if (!mobileValidation.isValid()) {
                redirectToErrorPage(response, context, queryParams, mobileValidation.getMessage());
                return null;
            }
            
            return mobileNumber;
            
        } catch (Exception e) {
            log.error("Error getting mobile number for user: " + username, e);
            throw new AuthenticationFailedException("Error getting mobile number");
        }
    }

    /**
     * Sends SMS OTP to user
     */
    private void sendSMSOTP(HttpServletResponse response, AuthenticationContext context, String mobileNumber,
                           String queryParams, String username) throws AuthenticationFailedException {
        
        try {
            // Create SMS configuration first to get payload information
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            SMSService.SMSConfig smsConfig = new SMSService.SMSConfig(
                    authenticatorProperties.get(SMSOTPConstants.SMS_URL),
                    authenticatorProperties.get(SMSOTPConstants.HTTP_METHOD),
                    authenticatorProperties.get(SMSOTPConstants.HEADERS),
                    authenticatorProperties.get(SMSOTPConstants.PAYLOAD),
                    authenticatorProperties.get(SMSOTPConstants.HTTP_RESPONSE)
            );
            
            // Store SMS payload in context so OTP service can read the otpDigit configuration
            if (StringUtils.isNotEmpty(smsConfig.getPayload())) {
                context.setProperty("SMS_PAYLOAD_CONFIG", smsConfig.getPayload());
                log.info("Set SMS payload in context for OTP generation: " + smsConfig.getPayload());
            }
            
            // Generate OTP (now it can read otpDigit from the payload)
            String otpCode = otpService.generateOTP(context);
            
            // Send SMS
            SMSResponse smsResponse = smsService.sendOTP(context, mobileNumber, otpCode, smsConfig);
            
            if (smsResponse.isSuccess()) {
                // Store OTP information in context
                // Use the generated otpCode instead of actualOtpSent from response to avoid parsing issues
                String actualOtpSent = smsResponse.getActualOtpSent();
                if (actualOtpSent != null && !actualOtpSent.isEmpty()) {
                    // Clean up actualOtpSent - remove any non-numeric characters
                    actualOtpSent = actualOtpSent.replaceAll("[^0-9]", "");
                    if (actualOtpSent.isEmpty()) {
                        actualOtpSent = otpCode; // Fallback to generated OTP
                    }
                } else {
                    actualOtpSent = otpCode; // Use generated OTP if response OTP is empty
                }
                otpService.storeOTPInContext(context, otpCode, actualOtpSent);
                
                // SMS payload already set in context before OTP generation
                // No need to set again here
                
                // Redirect to OTP input page
                redirectToOTPPage(response, context, queryParams, username);
                
            } else {
                // SMS sending failed
                String errorMessage = "Failed to send SMS OTP: " + smsResponse.getMessage();
                context.setProperty(SMSOTPConstants.ERROR_CODE, errorMessage);
                redirectToErrorPage(response, context, queryParams, errorMessage);
            }
            
        } catch (IOException e) {
            log.error("Error sending SMS OTP: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "Error sending SMS. Please try again.");
        }
    }

    /**
     * Updates user's mobile number
     */
    private void updateUserMobileNumber(AuthenticationContext context, HttpServletRequest request,
                                      String username, String tenantDomain) throws AuthenticationFailedException {
        
        if (username != null && !context.isRetrying()) {
            if (log.isDebugEnabled()) {
                log.debug("Updating mobile number for user: " + username);
            }
            
            try {
                Map<String, String> attributes = new java.util.HashMap<>();
                attributes.put(SMSOTPConstants.MOBILE_CLAIM, request.getParameter(SMSOTPConstants.MOBILE_NUMBER));
                SMSOTPUtils.updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes, tenantDomain);
                
            } catch (Exception e) {
                log.error("Error updating mobile number for user: " + username, e);
                throw new AuthenticationFailedException("Error updating mobile number");
            }
        }
    }

    /**
     * Extracts OTP from request
     */
    private String extractOTPFromRequest(HttpServletRequest request) {
        String userToken = request.getParameter(SMSOTPConstants.CODE);
        if (StringUtils.isEmpty(userToken)) {
            userToken = request.getParameter("OTPcode");
        }
        return userToken;
    }

    /**
     * Handles successful authentication
     */
    private void handleSuccessfulAuthentication(AuthenticationContext context, AuthenticatedUser authenticatedUser) {
        if (log.isDebugEnabled()) {
            log.debug("SMS OTP authentication successful for user: " + authenticatedUser.getUserName());
        }
        
        context.setSubject(authenticatedUser);
    }

    /**
     * Redirects to OTP input page
     */
    private void redirectToOTPPage(HttpServletResponse response, AuthenticationContext context,
                                 String queryParams, String username) throws AuthenticationFailedException {
        
        try {
            String loginPage = CustomFederatedAuthenticator.getLoginPage(context);
            String url = CustomFederatedAuthenticator.getURL(loginPage, queryParams, getName());
            
            // Add screen value if available
            if (StringUtils.isNotEmpty(username)) {
                try {
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);
                    String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                    UserRealm userRealm = (UserRealm) SMSOTPUtils.getUserRealm(tenantDomain);
                    
                    if (userRealm != null) {
                        String screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
                        if (screenValue != null) {
                            url = url + SMSOTPConstants.SCREEN_VALUE + screenValue;
                        }
                    }
                } catch (Exception e) {
                    log.warn("Error getting screen value for user: " + username, e);
                }
            }
            
            response.sendRedirect(url);
            
        } catch (IOException e) {
            log.error("Error redirecting to OTP page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error redirecting to OTP page");
        }
    }

    /**
     * Redirects to mobile number request page
     */
    private void redirectToMobileNumberRequestPage(HttpServletResponse response, AuthenticationContext context,
                                                 String queryParams) throws AuthenticationFailedException {
        
        try {
            String mobileNumberRequestPage = SMSOTPUtils.getMobileNumberRequestPage(context);
            if (StringUtils.isNotEmpty(mobileNumberRequestPage)) {
                String url = CustomFederatedAuthenticator.getURL(mobileNumberRequestPage, queryParams, getName());
                response.sendRedirect(url);
            } else {
                redirectToErrorPage(response, context, queryParams, 
                        "Mobile number not found. Please contact administrator.");
            }
            
        } catch (IOException e) {
            log.error("Error redirecting to mobile number request page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error redirecting to mobile number request page");
        }
    }

    /**
     * Redirects to error page
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
                                   String queryParams, String errorMessage) throws AuthenticationFailedException {
        
        try {
            String errorPage = CustomFederatedAuthenticator.getErrorPage(context);
            String url = CustomFederatedAuthenticator.getURL(errorPage, queryParams, getName());
            
            // Add error message to URL
            if (StringUtils.isNotEmpty(errorMessage)) {
                url = url + "&authFailure=true&authFailureMsg=" + java.net.URLEncoder.encode(errorMessage, "UTF-8");
            }
            
            response.sendRedirect(url);
            
        } catch (IOException e) {
            log.error("Error redirecting to error page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error redirecting to error page");
        }
    }

    /**
     * Gets screen attribute for user
     */
    private String getScreenAttribute(AuthenticationContext context, UserRealm userRealm, String username)
            throws UserStoreException, AuthenticationFailedException {
        
        String screenUserAttributeParam = SMSOTPUtils.getScreenUserAttribute(context);
        if (screenUserAttributeParam != null) {
            String screenUserAttributeValue = userRealm.getUserStoreManager()
                    .getUserClaimValue(username, screenUserAttributeParam, null);
            
            if (screenUserAttributeValue != null) {
                int noOfDigits = 0;
                if (SMSOTPUtils.getNoOfDigits(context) != null) {
                    noOfDigits = Integer.parseInt(SMSOTPUtils.getNoOfDigits(context));
                }
                return CustomFederatedAuthenticator.getMaskedValue(context, screenUserAttributeValue, noOfDigits);
            }
        }
        
        return null;
    }

    /**
     * Cleans up existing session data to prevent constraint violations
     * 
     * @param context Authentication context
     */
    private void cleanupSessionData(AuthenticationContext context) {
        try {
            if (context != null) {
                // Remove any existing OTP-related properties that might cause conflicts
                String[] propertiesToClean = {
                    SMSOTPConstants.OTP_TOKEN,
                    SMSOTPConstants.SENT_OTP_TOKEN_TIME,
                    SMSOTPConstants.TOKEN_VALIDITY_TIME,
                    "CLIENT_OTP_VALIDATION",
                    "SMS_PAYLOAD_CONFIG",
                    "screenValue",
                    "MASKED_EMAIL",
                    "OTP_TYPE"
                };
                
                for (String property : propertiesToClean) {
                    if (context.getProperty(property) != null) {
                        context.removeProperty(property);
                        if (log.isDebugEnabled()) {
                            log.debug("Cleaned up session property: " + property);
                        }
                    }
                }
                
                // Add a small delay to ensure any pending session operations complete
                Thread.sleep(50);
                
                if (log.isDebugEnabled()) {
                    log.debug("Session cleanup completed for context: " + context.getContextIdentifier());
                }
            }
        } catch (Exception e) {
            // Log but don't fail the authentication process due to cleanup issues
            log.warn("Warning during session cleanup: " + e.getMessage());
        }
    }
}
