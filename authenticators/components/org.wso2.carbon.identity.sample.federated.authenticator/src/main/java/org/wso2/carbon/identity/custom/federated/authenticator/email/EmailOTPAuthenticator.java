package org.wso2.carbon.identity.custom.federated.authenticator.email;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.custom.federated.authenticator.email.service.EmailService;
import org.wso2.carbon.identity.custom.federated.authenticator.email.service.EmailService.EmailConfig;
import org.wso2.carbon.identity.custom.federated.authenticator.email.service.EmailService.EmailResponse;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.OTPService;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.OTPService.OTPValidationResult;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.ValidationService;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.ValidationService.ValidationResult;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;
import org.wso2.carbon.identity.custom.federated.authenticator.CustomFederatedAuthenticator;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

/**
 * Email OTP Authenticator for handling email-based OTP authentication
 * 
 * This class handles Email OTP authentication with:
 * - Email sending and OTP generation
 * - OTP validation
 * - Error handling and redirection
 */
public class EmailOTPAuthenticator implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(EmailOTPAuthenticator.class);

    // Service instances
    private final OTPService otpService = new OTPService();
    private final EmailService emailService = new EmailService();
    private final ValidationService validationService = new ValidationService();

    /**
     * Handles Email OTP authentication request
     */
    public void handleEmailOTPAuthentication(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException {
        
        // Clean up any existing session data to prevent conflicts
        cleanupSessionData(context);
        
        if (log.isDebugEnabled()) {
            log.debug("Starting Email OTP authentication for session: " + context.getContextIdentifier());
        }

        try {
            String username = extractUsername(context);
            String tenantDomain = context.getTenantDomain();
            String queryParams = request.getQueryString();

            // Create and store AuthenticatedUser in context for validation
            AuthenticatedUser authenticatedUser = null;
            if (context.getSequenceConfig() != null && 
                context.getSequenceConfig().getAuthenticatedUser() != null) {
                authenticatedUser = context.getSequenceConfig().getAuthenticatedUser();
            } else if (context.getLastAuthenticatedUser() != null) {
                authenticatedUser = context.getLastAuthenticatedUser();
            } else {
                // Create new AuthenticatedUser if not found
                authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
                authenticatedUser.setTenantDomain(tenantDomain);
            }
            
            // Store authenticated user in context for later validation
            context.setProperty(SMSOTPConstants.AUTHENTICATED_USER, authenticatedUser);
            log.info("Set AuthenticatedUser in context for EMAIL OTP: " + authenticatedUser.getUserName());

            // Get user email address
            String emailAddress = getUserEmailAddress(request, response, context, username, tenantDomain, queryParams);
            if (emailAddress == null) {
                return; // Error already handled in getUserEmailAddress
            }

            // Send Email OTP
            sendEmailOTP(response, context, emailAddress, queryParams, username);

        } catch (Exception e) {
            log.error("Error in Email OTP authentication: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Email OTP authentication failed", e);
        }
    }

    /**
     * Processes Email OTP authentication response
     */
    public void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationContext context) throws AuthenticationFailedException {
        
        if (log.isDebugEnabled()) {
            log.debug("Processing Email OTP response for session: " + context.getContextIdentifier());
        }

        try {
            String userToken = request.getParameter(SMSOTPConstants.CODE);
            
            // Check if we have user input
            if (StringUtils.isEmpty(userToken)) {
                String errorMessage = "Please enter the OTP code sent to your email.";
                handleOTPValidationFailure(response, context, errorMessage);
                return;
            }

            // Get stored OTP information from context
            String contextToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
            String actualOtpSent = (String) context.getProperty("CLIENT_OTP_VALIDATION");
            Long sentTime = (Long) context.getProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME);
            Long validityPeriod = (Long) context.getProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME);
            
            log.info("Email OTP Validation Debug:");
            log.info("  - User OTP from request: '" + userToken + "'");
            log.info("  - Stored OTP in context: '" + contextToken + "'");
            log.info("  - Actual OTP sent: '" + actualOtpSent + "'");
            log.info("  - User OTP length: " + (userToken != null ? userToken.length() : "null"));
            log.info("  - Stored OTP length: " + (contextToken != null ? contextToken.length() : "null"));
            
            // Get authenticated user
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
            if (authenticatedUser == null) {
                log.error("Email OTP Validation Error: AuthenticatedUser is null in context");
                String errorMessage = "Authentication session expired. Please try again.";
                handleOTPValidationFailure(response, context, errorMessage);
                return;
            }
            
            // Validate OTP using OTPService
            OTPValidationResult validationResult = otpService.validateOTP(userToken, contextToken, sentTime, validityPeriod);
            
            log.info("Email OTP Validation Result:");
            log.info("  - Is Valid: " + validationResult.isValid());
            log.info("  - Message: " + validationResult.getMessage());
            
            if (!validationResult.isValid()) {
                log.warn("Email OTP Validation Failed: " + validationResult.getMessage());
                handleOTPValidationFailure(response, context, validationResult.getMessage());
                return;
            }

            // OTP validation successful
            log.info("Email OTP Validation Successful for user: " + authenticatedUser.getUserName());
            
            // Set authenticated user as subject
            context.setSubject(authenticatedUser);
            
            if (log.isDebugEnabled()) {
                log.debug("Email OTP authentication completed successfully for session: " + context.getContextIdentifier());
            }

        } catch (Exception e) {
            log.error("Error processing Email OTP response: " + e.getMessage(), e);
            String errorMessage = "Technical error occurred during Email OTP verification. Please try again.";
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Extracts username from authentication context
     */
    private String extractUsername(AuthenticationContext context) throws AuthenticationFailedException {
        String username = null;
        
        // Try to get username from authenticated user
        if (context.getSequenceConfig() != null && 
            context.getSequenceConfig().getAuthenticatedUser() != null) {
            username = context.getSequenceConfig().getAuthenticatedUser().getUserName();
        }
        
        // Try to get from last authenticated user
        if (StringUtils.isEmpty(username) && context.getLastAuthenticatedUser() != null) {
            username = context.getLastAuthenticatedUser().getUserName();
        }
        
        if (StringUtils.isEmpty(username)) {
            throw new AuthenticationFailedException("Cannot find the username from authentication context");
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Extracted username: " + username);
        }
        
        return username;
    }

    /**
     * Gets user email address
     */
    private String getUserEmailAddress(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context, String username, String tenantDomain,
                                     String queryParams) throws AuthenticationFailedException {
        
        try {
            UserRealm userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            String emailAddress = null;
            
            if (userRealm != null) {
                try {
                    // Get email from user store
                    emailAddress = userRealm.getUserStoreManager()
                        .getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), 
                                         "http://wso2.org/claims/emailaddress", null);
                } catch (UserStoreException e) {
                    log.error("Error getting email address for user: " + username, e);
                }
            }
            
            if (StringUtils.isEmpty(emailAddress)) {
                String errorMessage = "Email address not found for user: " + username + 
                                    ". Please contact your administrator to update your email address in your profile.";
                redirectToErrorPage(response, context, queryParams, errorMessage);
                return null;
            }
            
            // Validate email format
            ValidationResult emailValidation = validationService.validateEmailAddress(emailAddress);
            if (!emailValidation.isValid()) {
                String errorMessage = "Invalid email address format: " + emailValidation.getMessage() + 
                                    ". Please contact your administrator to correct your email address.";
                redirectToErrorPage(response, context, queryParams, errorMessage);
                return null;
            }
            
            return emailAddress;
            
        } catch (Exception e) {
            log.error("Error getting email address for user: " + username, e);
            throw new AuthenticationFailedException("Error getting email address");
        }
    }

    /**
     * Sends Email OTP to user
     */
    private void sendEmailOTP(HttpServletResponse response, AuthenticationContext context, String emailAddress,
                            String queryParams, String username) throws AuthenticationFailedException {
        
        try {
            // Create Email configuration first to get payload information
            java.util.Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            EmailConfig emailConfig = new EmailConfig(
                    authenticatorProperties.get("EMAIL_URL"),
                    authenticatorProperties.get("EMAIL_HTTP_METHOD"),
                    authenticatorProperties.get("EMAIL_HEADERS"),
                    authenticatorProperties.get("EMAIL_PAYLOAD"),
                    authenticatorProperties.get("EMAIL_HTTP_RESPONSE")
            );
            
            // Store Email payload in context so OTP service can read the otpDigit configuration
            if (emailConfig.getPayload() != null && !emailConfig.getPayload().trim().isEmpty()) {
                context.setProperty("EMAIL_PAYLOAD_CONFIG", emailConfig.getPayload());
                log.info("Set EMAIL payload in context for OTP generation: " + emailConfig.getPayload());
            }
            
            // Generate OTP (now it can read otpDigit from the payload)
            String otpCode = otpService.generateOTP(context);
            
            // Send Email
            EmailResponse emailResponse = emailService.sendOTP(context, emailAddress, otpCode, emailConfig);
            
            if (emailResponse.isSuccess()) {
                // Store OTP information in context
                String actualOtpSent = emailResponse.getActualOtpSent();
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
                
                // Store Email payload for JSP (use same property name as SMS for compatibility)
                if (StringUtils.isNotEmpty(emailConfig.getPayload())) {
                    context.setProperty("SMS_PAYLOAD_CONFIG", emailConfig.getPayload()); // Use SMS property for compatibility
                    context.setProperty("EMAIL_PAYLOAD_CONFIG", emailConfig.getPayload()); // Keep EMAIL property as well
                }
                
                // Mark this as EMAIL OTP for context
                context.setProperty("OTP_TYPE", "EMAIL");
                
                // Store additional context properties that JSP might need
                context.setProperty("SCREEN_VALUE", maskEmailAddress(emailAddress));
                context.setProperty("MOBILE_NUMBER", emailAddress); // Store actual email for reference
                context.setProperty("OTP_CHANNEL", "EMAIL"); // Indicate this is email channel
                
                // Store email configuration for potential resend operations
                context.setProperty("EMAIL_URL", emailConfig.getUrl());
                context.setProperty("EMAIL_METHOD", emailConfig.getHttpMethod());
                context.setProperty("EMAIL_HEADERS", emailConfig.getHeaders());
                context.setProperty("EMAIL_PAYLOAD", emailConfig.getPayload());
                context.setProperty("EMAIL_HTTP_RESPONSE", emailConfig.getExpectedResponse());
                
                // Redirect to OTP input page
                redirectToOTPPage(response, context, queryParams, username, emailAddress);
                
            } else {
                // Email sending failed
                String errorMessage = "Failed to send Email OTP: " + emailResponse.getMessage() + 
                                    ". Please check your email configuration or try again later.";
                context.setProperty(SMSOTPConstants.ERROR_CODE, errorMessage);
                redirectToErrorPage(response, context, queryParams, errorMessage);
            }
            
        } catch (IOException e) {
            log.error("Error sending Email OTP: " + e.getMessage(), e);
            String errorMessage = "Unable to send Email OTP due to technical issues. Please try again later or contact support.";
            redirectToErrorPage(response, context, queryParams, errorMessage);
        }
    }

    /**
     * Handles OTP validation failure
     */
    private void handleOTPValidationFailure(HttpServletResponse response, AuthenticationContext context, 
                                          String errorMessage) throws AuthenticationFailedException {
        
        try {
            context.setProperty(SMSOTPConstants.ERROR_CODE, errorMessage);
            
            // Set additional error context for EMAIL OTP
            context.setProperty("AUTH_FAILURE_MSG", errorMessage);
            context.setProperty("ERROR_TYPE", "EMAIL_OTP_VALIDATION");
            context.setProperty("OTP_CHANNEL", "EMAIL");
            
            String errorPage = CustomFederatedAuthenticator.getErrorPage(context);
            String queryString = context.getContextIdIncludedQueryParams();
            String url = CustomFederatedAuthenticator.getURL(errorPage, queryString, "CustomFederatedAuthenticator");
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + url);
            }
            
            response.sendRedirect(url);
            
        } catch (IOException e) {
            log.error("Error redirecting to error page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error redirecting to error page", e);
        }
    }

    /**
     * Redirects to OTP input page
     */
    private void redirectToOTPPage(HttpServletResponse response, AuthenticationContext context, 
                                 String queryParams, String username, String emailAddress) 
                                 throws AuthenticationFailedException {
        
        try {
            String loginPage = CustomFederatedAuthenticator.getLoginPage(context);
            // Use context query params to ensure proper authentication context handling
            String contextQueryParams = context.getContextIdIncludedQueryParams();
            String url = CustomFederatedAuthenticator.getURL(loginPage, contextQueryParams, "CustomFederatedAuthenticator");
            
            // Add screen value if available (use email instead of mobile for EMAIL OTP)
            if (StringUtils.isNotEmpty(username)) {
                try {
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);
                    UserRealm userRealm = (UserRealm) SMSOTPUtils.getUserRealm(tenantDomain);
                    
                    if (userRealm != null) {
                        // For EMAIL OTP, use the masked email as screen value
                        String screenValue = maskEmailAddress(emailAddress);
                        if (screenValue != null) {
                            url = url + SMSOTPConstants.SCREEN_VALUE + screenValue;
                        }
                    }
                } catch (Exception e) {
                    log.warn("Error getting screen value for user: " + username, e);
                }
            }
            
            // Add email address to context for display (use same properties as SMS for compatibility)
            context.setProperty("MASKED_EMAIL", maskEmailAddress(emailAddress));
            context.setProperty("screenValue", maskEmailAddress(emailAddress)); // For JSP compatibility
            context.setProperty("SCREEN_VALUE", maskEmailAddress(emailAddress)); // Alternative property name
            
            // Set additional properties for EMAIL OTP display
            context.setProperty("OTP_TYPE_DISPLAY", "EMAIL"); // For UI display purposes
            context.setProperty("CONTACT_METHOD", "email address"); // Human readable contact method
            context.setProperty("MASKED_CONTACT", maskEmailAddress(emailAddress)); // Masked contact info
            
            // For compatibility with existing SMS JSP logic
            context.setProperty("MOBILE_NUMBER_MASKED", maskEmailAddress(emailAddress));
            context.setProperty("CONTACT_VALUE", emailAddress); // Full contact value (for internal use)
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to SMS OTP page: " + url + " for EMAIL OTP");
            }
            
            response.sendRedirect(url);
            
        } catch (IOException e) {
            log.error("Error redirecting to OTP page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error redirecting to OTP page", e);
        }
    }

    /**
     * Redirects to error page
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
                                   String queryParams, String errorMessage) throws AuthenticationFailedException {
        
        try {
            context.setProperty(SMSOTPConstants.ERROR_CODE, errorMessage);
            String errorPage = CustomFederatedAuthenticator.getErrorPage(context);
            // Use context query params to ensure proper authentication context handling
            String contextQueryParams = context.getContextIdIncludedQueryParams();
            String url = CustomFederatedAuthenticator.getURL(errorPage, contextQueryParams, "CustomFederatedAuthenticator");
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + url + " with error: " + errorMessage);
            }
            
            response.sendRedirect(url);
            
        } catch (IOException e) {
            log.error("Error redirecting to error page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error redirecting to error page", e);
        }
    }

    /**
     * Masks email address for display (e.g., j***@example.com)
     */
    private String maskEmailAddress(String email) {
        if (StringUtils.isEmpty(email) || !email.contains("@")) {
            return email;
        }
        
        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];
        
        if (localPart.length() <= 2) {
            return email; // Don't mask very short local parts
        }
        
        String maskedLocal = localPart.charAt(0) + "***";
        return maskedLocal + "@" + domain;
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
                    "EMAIL_PAYLOAD_CONFIG",
                    "SMS_PAYLOAD_CONFIG",
                    "screenValue",
                    "MASKED_EMAIL",
                    "OTP_TYPE"
                };
                
                for (String property : propertiesToClean) {
                    if (context.getProperty(property) != null) {
                        context.removeProperty(property);
                        if (log.isDebugEnabled()) {
                            log.debug("Cleaned up email session property: " + property);
                        }
                    }
                }
                
                // Add a small delay to ensure any pending session operations complete
                Thread.sleep(50);
                
                if (log.isDebugEnabled()) {
                    log.debug("Email session cleanup completed for context: " + context.getContextIdentifier());
                }
            }
        } catch (Exception e) {
            // Log but don't fail the authentication process due to cleanup issues
            log.warn("Warning during email session cleanup: " + e.getMessage());
        }
    }
}
