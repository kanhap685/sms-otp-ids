package org.wso2.carbon.identity.custom.federated.authenticator.sms.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.OneTimePassword;

/**
 * Service class for OTP operations
 * Handles OTP generation, validation, and token management
 */
public class OTPService {

    private static final Log log = LogFactory.getLog(OTPService.class);

    /**
     * Generates a new OTP token
     * 
     * @param context Authentication context
     * @return Generated OTP token
     */
    public String generateOTP(AuthenticationContext context) {
        // Always use 4-digit OTP as per requirement
        int tokenLength = 4;
        boolean isAlphanumeric = SMSOTPUtils.isEnableAlphanumericToken(context);
        
        if (log.isDebugEnabled()) {
            log.debug("Generating OTP with length: " + tokenLength + ", alphanumeric: " + isAlphanumeric);
        }
        
        try {
            OneTimePassword otpGenerator = new OneTimePassword();
            String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
            
            String otpToken = otpGenerator.generateToken(
                secret, 
                String.valueOf(SMSOTPConstants.NUMBER_BASE), 
                tokenLength, 
                isAlphanumeric
            );
            
            if (log.isDebugEnabled()) {
                log.debug("Successfully generated OTP token with length: " + otpToken.length());
            }
            
            return otpToken;
            
        } catch (Exception e) {
            log.error("Error generating OTP token: " + e.getMessage(), e);
            // Return a fallback OTP in case of error
            return generateFallbackOTP(tokenLength);
        }
    }

    /**
     * Validates the provided OTP against the stored token
     * 
     * @param userToken OTP provided by user
     * @param contextToken OTP stored in context
     * @param sentTime Time when OTP was sent
     * @param validityPeriod Validity period in minutes
     * @return OTP validation result
     */
    public OTPValidationResult validateOTP(String userToken, String contextToken, 
                                         Long sentTime, Long validityPeriod) {
        
        if (log.isDebugEnabled()) {
            log.debug("Validating OTP - User token length: " + 
                     (userToken != null ? userToken.length() : "null") +
                     ", Context token length: " + 
                     (contextToken != null ? contextToken.length() : "null"));
        }
        
        // Check if tokens are provided
        if (userToken == null || userToken.trim().isEmpty()) {
            return new OTPValidationResult(false, "Please enter the OTP code.");
        }
        
        if (contextToken == null || contextToken.trim().isEmpty()) {
            return new OTPValidationResult(false, "OTP session expired. Please try again.");
        }
        
        // Normalize tokens
        userToken = userToken.trim();
        contextToken = contextToken.trim();
        
        // Check token match
        if (!userToken.equals(contextToken)) {
            if (log.isDebugEnabled()) {
                log.debug("OTP token mismatch. User: '" + userToken + "', Context: '" + contextToken + "'");
            }
            return new OTPValidationResult(false, 
                "Invalid OTP code. Please enter the complete " + contextToken.length() + "-digit OTP sent to your mobile.");
        }
        
        // Check token expiry
        if (sentTime != null && validityPeriod != null) {
            long currentTime = System.currentTimeMillis();
            long elapsedTime = currentTime - sentTime;
            long validityInMillis = validityPeriod * 60 * 1000; // Convert minutes to milliseconds
            
            if (elapsedTime > validityInMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("OTP token expired. Elapsed time: " + elapsedTime + 
                             "ms, Validity period: " + validityInMillis + "ms");
                }
                return new OTPValidationResult(false, "OTP has expired. Please request a new code.");
            }
        }
        
        return new OTPValidationResult(true, "OTP validation successful");
    }

    /**
     * Stores OTP information in authentication context
     * 
     * @param context Authentication context
     * @param otpToken Generated OTP token
     * @param actualOtpSent Actual OTP sent via SMS
     */
    public void storeOTPInContext(AuthenticationContext context, String otpToken, String actualOtpSent) {
        log.debug("~~~~~~~~~~~~~~ actualOtpSent: " + actualOtpSent + "~~~~~~~~~~~~~~");
        if (context == null) {
            log.error("Authentication context is null, cannot store OTP information");
            return;
        }
        
        // Store the generated OTP token for validation
        context.setProperty(SMSOTPConstants.OTP_TOKEN, otpToken);
        
        // Store the actual OTP sent (may be different from generated for external SMS services)
        if (actualOtpSent != null && !actualOtpSent.isEmpty()) {
            context.setProperty("CLIENT_OTP_VALIDATION", actualOtpSent);
        }
        
        // Store the time when OTP was sent
        long sentTime = System.currentTimeMillis();
        context.setProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME, sentTime);
        
        // Store token validity period
        String tokenExpiryTimeStr = SMSOTPUtils.getTokenExpiryTime(context);
        if (tokenExpiryTimeStr != null) {
            try {
                long tokenExpiryTime = Long.parseLong(tokenExpiryTimeStr);
                context.setProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME, tokenExpiryTime);
            } catch (NumberFormatException e) {
                log.warn("Invalid token expiry time format: " + tokenExpiryTimeStr);
                // Set default expiry time (5 minutes)
                context.setProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME, 5L);
            }
        }
        
        if (log.isDebugEnabled()) {
            log.debug("OTP information stored in context. Token length: " + otpToken.length());
        }
    }

    /**
     * Generates a fallback OTP when the main generation fails
     * 
     * @param length Required OTP length
     * @return Fallback OTP token
     */
    private String generateFallbackOTP(int length) {
        StringBuilder fallbackOtp = new StringBuilder();
        for (int i = 0; i < length; i++) {
            fallbackOtp.append((int) (Math.random() * 10));
        }
        
        String fallback = fallbackOtp.toString();
        log.warn("Using fallback OTP generation: " + fallback);
        return fallback;
    }

    /**
     * Checks if OTP resend is enabled
     * 
     * @param context Authentication context
     * @return True if resend is enabled
     */
    public boolean isResendEnabled(AuthenticationContext context) {
        return SMSOTPUtils.isEnableResendCode(context);
    }

    /**
     * Checks if OTP retry is enabled
     * 
     * @param context Authentication context
     * @return True if retry is enabled
     */
    public boolean isRetryEnabled(AuthenticationContext context) {
        return SMSOTPUtils.isRetryEnabled(context);
    }

    /**
     * Result class for OTP validation
     */
    public static class OTPValidationResult {
        private boolean valid;
        private String message;
        
        public OTPValidationResult(boolean valid, String message) {
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
            return "OTPValidationResult{" +
                    "valid=" + valid +
                    ", message='" + message + '\'' +
                    '}';
        }
    }
}
