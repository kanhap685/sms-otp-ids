package org.wso2.carbon.identity.custom.federated.authenticator.email;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.custom.federated.authenticator.email.service.EmailService;
import org.wso2.carbon.identity.custom.federated.authenticator.email.service.EmailService.EmailConfig;
import org.wso2.carbon.identity.custom.federated.authenticator.email.service.EmailService.EmailResponse;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.OTPService;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.OTPService.OTPValidationResult;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.ValidationService;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.service.ValidationService.ValidationResult;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

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
        
        if (log.isDebugEnabled()) {
            log.debug("Starting Email OTP authentication for session: " + context.getContextIdentifier());
        }

        try {
            String username = extractUsername(context);
            String tenantDomain = context.getTenantDomain();
            String queryParams = request.getQueryString();

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
            
            // Validate user input
            ValidationResult inputValidation = validationService.validateOTPFormat(userToken, 4);
            if (!inputValidation.isValid()) {
                handleOTPValidationFailure(response, context, inputValidation.getMessage());
                return;
            }

            // Get stored OTP from context
            String contextToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
            Long sentTime = (Long) context.getProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME);
            
            // Validate OTP
            OTPValidationResult otpValidation = otpService.validateOTP(
                userToken, contextToken, sentTime, 5L // 5 minutes validity
            );

            if (otpValidation.isValid()) {
                if (log.isDebugEnabled()) {
                    log.debug("Email OTP validation successful for session: " + context.getContextIdentifier());
                }
                context.setSubject(context.getSequenceConfig().getAuthenticatedUser());
            } else {
                handleOTPValidationFailure(response, context, otpValidation.getMessage());
            }

        } catch (Exception e) {
            log.error("Error processing Email OTP response: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Error processing Email OTP response", e);
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
                                    ". Please contact administrator to update your email address.";
                redirectToErrorPage(response, context, queryParams, errorMessage);
                return null;
            }
            
            // Validate email format
            ValidationResult emailValidation = validationService.validateEmailAddress(emailAddress);
            if (!emailValidation.isValid()) {
                redirectToErrorPage(response, context, queryParams, emailValidation.getMessage());
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
            // Generate OTP
            String otpCode = otpService.generateOTP(context);
            
            // Create Email configuration
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            EmailConfig emailConfig = new EmailConfig(
                    authenticatorProperties.get("EMAIL_URL"),
                    authenticatorProperties.get("EMAIL_HTTP_METHOD"),
                    authenticatorProperties.get("EMAIL_HEADERS"),
                    authenticatorProperties.get("EMAIL_PAYLOAD"),
                    authenticatorProperties.get("EMAIL_HTTP_RESPONSE")
            );
            
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
                
                // Store Email payload for JSP
                if (StringUtils.isNotEmpty(emailConfig.getPayload())) {
                    context.setProperty("EMAIL_PAYLOAD_CONFIG", emailConfig.getPayload());
                }
                
                // Redirect to OTP input page
                redirectToOTPPage(response, context, queryParams, username, emailAddress);
                
            } else {
                // Email sending failed
                String errorMessage = "Failed to send Email OTP: " + emailResponse.getMessage();
                context.setProperty(SMSOTPConstants.ERROR_CODE, errorMessage);
                redirectToErrorPage(response, context, queryParams, errorMessage);
            }
            
        } catch (IOException e) {
            log.error("Error sending Email OTP: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "Error sending Email. Please try again.");
        }
    }

    /**
     * Handles OTP validation failure
     */
    private void handleOTPValidationFailure(HttpServletResponse response, AuthenticationContext context, 
                                          String errorMessage) throws AuthenticationFailedException {
        
        try {
            context.setProperty(SMSOTPConstants.ERROR_CODE, errorMessage);
            String errorPageUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace("authenticationendpoint/login.do", "authenticationendpoint/emailOtpError.jsp");
            
            String queryString = context.getContextIdIncludedQueryParams();
            if (StringUtils.isNotBlank(queryString)) {
                errorPageUrl += "?" + queryString;
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + errorPageUrl);
            }
            
            response.sendRedirect(errorPageUrl);
            
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
            String otpPageUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace("authenticationendpoint/login.do", "authenticationendpoint/emailOtp.jsp");
            
            String queryString = context.getContextIdIncludedQueryParams();
            if (StringUtils.isNotBlank(queryString)) {
                otpPageUrl += "?" + queryString;
            }
            
            // Add email address to context for display
            context.setProperty("MASKED_EMAIL", maskEmailAddress(emailAddress));
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to Email OTP page: " + otpPageUrl);
            }
            
            response.sendRedirect(otpPageUrl);
            
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
            String errorPageUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace("authenticationendpoint/login.do", "authenticationendpoint/emailOtpError.jsp");
            
            String queryString = context.getContextIdIncludedQueryParams();
            if (StringUtils.isNotBlank(queryString)) {
                errorPageUrl += "?" + queryString;
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + errorPageUrl + " with error: " + errorMessage);
            }
            
            response.sendRedirect(errorPageUrl);
            
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
}
