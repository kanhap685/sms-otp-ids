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
        // Get OTP length from configuration, default to 4 if not specified
        int tokenLength = getOTPLengthFromContext(context);
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
        
        log.info("OTP Validation Started:");
        log.info("  - User token: '" + userToken + "' (length: " + (userToken != null ? userToken.length() : "null") + ")");
        log.info("  - Context token: '" + contextToken + "' (length: " + (contextToken != null ? contextToken.length() : "null") + ")");
        log.info("  - Sent time: " + sentTime);
        log.info("  - Validity period: " + validityPeriod);
        
        // Check if tokens are provided
        if (userToken == null || userToken.trim().isEmpty()) {
            log.warn("OTP Validation Failed: User token is null or empty");
            return new OTPValidationResult(false, "Please enter the OTP code.");
        }
        
        if (contextToken == null || contextToken.trim().isEmpty()) {
            log.warn("OTP Validation Failed: Context token is null or empty");
            return new OTPValidationResult(false, "OTP session expired. Please try again.");
        }
        
        // Normalize tokens
        userToken = userToken.trim();
        contextToken = contextToken.trim();
        
        log.info("Normalized tokens:");
        log.info("  - User token: '" + userToken + "'");
        log.info("  - Context token: '" + contextToken + "'");
        
        // Check token match
        if (!userToken.equals(contextToken)) {
            log.warn("OTP Validation Failed: Token mismatch");
            log.warn("  - User: '" + userToken + "'");
            log.warn("  - Context: '" + contextToken + "'");
            return new OTPValidationResult(false, 
                "Invalid OTP code. Please enter the complete " + contextToken.length() + "-digit OTP sent to your mobile.");
        }
        
        // Check token expiry
        if (sentTime != null && validityPeriod != null) {
            long currentTime = System.currentTimeMillis();
            long elapsedTime = currentTime - sentTime;
            long validityInMillis = validityPeriod * 60 * 1000; // Convert minutes to milliseconds
            
            log.info("OTP Expiry Check:");
            log.info("  - Current time: " + currentTime);
            log.info("  - Sent time: " + sentTime);
            log.info("  - Elapsed time (ms): " + elapsedTime);
            log.info("  - Validity period (ms): " + validityInMillis);
            
            if (elapsedTime > validityInMillis) {
                log.warn("OTP Validation Failed: Token expired");
                log.warn("  - Elapsed: " + elapsedTime + "ms, Validity: " + validityInMillis + "ms");
                return new OTPValidationResult(false, "OTP has expired. Please request a new code.");
            }
        }
        
        log.info("OTP Validation Successful: All checks passed");
        return new OTPValidationResult(true, "OTP validation successful");
    }

    /**
     * Stores OTP information in authentication context with conflict handling
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
        
        try {
            // Store the generated OTP token for validation
            context.setProperty(SMSOTPConstants.OTP_TOKEN, otpToken);
            
            // Store the actual OTP sent (may be different from generated for external SMS services)
            if (actualOtpSent != null && !actualOtpSent.isEmpty()) {
                context.setProperty("CLIENT_OTP_VALIDATION", actualOtpSent);
            }
            
            // Store the time when OTP was sent
            long sentTime = System.currentTimeMillis();
            context.setProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME, sentTime);
            
            log.info("Successfully stored OTP context properties:");
            log.info("  - OTP Token: " + (otpToken != null ? "***" + otpToken.substring(Math.max(0, otpToken.length()-2)) : "null"));
            log.info("  - Actual OTP: " + (actualOtpSent != null ? "***" + actualOtpSent.substring(Math.max(0, actualOtpSent.length()-2)) : "null"));
            log.info("  - Sent Time: " + sentTime);
            
        } catch (Exception e) {
            log.error("Error storing OTP context properties: " + e.getMessage(), e);
            throw new RuntimeException("Failed to store OTP context", e);
        }
        
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
     * Gets OTP length from authentication context configuration
     * 
     * @param context Authentication context
     * @return OTP length (default 4 if not specified)
     */
    private int getOTPLengthFromContext(AuthenticationContext context) {
        int defaultLength = 4; // Default fallback
        
        try {
            // First try to get from SMS payload configuration
            String smsPayload = (String) context.getProperty("SMS_PAYLOAD_CONFIG");
            if (smsPayload != null && !smsPayload.trim().isEmpty()) {
                int lengthFromPayload = parseOTPLengthFromPayload(smsPayload);
                if (lengthFromPayload > 0) {
                    log.info("OTP length from SMS payload: " + lengthFromPayload);
                    return lengthFromPayload;
                }
            }
            
            // Try to get from EMAIL payload configuration
            String emailPayload = (String) context.getProperty("EMAIL_PAYLOAD_CONFIG");
            if (emailPayload != null && !emailPayload.trim().isEmpty()) {
                int lengthFromPayload = parseOTPLengthFromPayload(emailPayload);
                if (lengthFromPayload > 0) {
                    log.info("OTP length from EMAIL payload: " + lengthFromPayload);
                    return lengthFromPayload;
                }
            }
            
            // Try to get from authenticator properties
            java.util.Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String otpLengthStr = authenticatorProperties.get("otpDigit");
                if (otpLengthStr != null && !otpLengthStr.trim().isEmpty()) {
                    int lengthFromProps = Integer.parseInt(otpLengthStr.trim());
                    if (lengthFromProps > 0 && lengthFromProps <= 8) {
                        log.info("OTP length from authenticator properties: " + lengthFromProps);
                        return lengthFromProps;
                    }
                }
            }
            
            log.info("Using default OTP length: " + defaultLength);
            return defaultLength;
            
        } catch (Exception e) {
            log.warn("Error getting OTP length from context, using default: " + e.getMessage());
            return defaultLength;
        }
    }
    
    /**
     * Parses OTP length from JSON payload string
     * 
     * @param payload JSON payload string
     * @return OTP length or 0 if not found
     */
    private int parseOTPLengthFromPayload(String payload) {
        try {
            log.debug("Parsing OTP length from payload: " + payload);
            
            // Simple JSON parsing for otpDigit value
            // Look for "otpDigit":"number" or "otpDigit":number patterns
            
            // Pattern 1: "otpDigit":"6"
            String pattern1 = "\"otpDigit\"\\s*:\\s*\"(\\d+)\"";
            java.util.regex.Pattern p1 = java.util.regex.Pattern.compile(pattern1);
            java.util.regex.Matcher m1 = p1.matcher(payload);
            if (m1.find()) {
                int length = Integer.parseInt(m1.group(1));
                log.debug("Found otpDigit (quoted): " + length);
                return length;
            }
            
            // Pattern 2: "otpDigit":6
            String pattern2 = "\"otpDigit\"\\s*:\\s*(\\d+)";
            java.util.regex.Pattern p2 = java.util.regex.Pattern.compile(pattern2);
            java.util.regex.Matcher m2 = p2.matcher(payload);
            if (m2.find()) {
                int length = Integer.parseInt(m2.group(1));
                log.debug("Found otpDigit (unquoted): " + length);
                return length;
            }
            
            log.debug("No otpDigit found in payload");
            return 0;
            
        } catch (Exception e) {
            log.warn("Error parsing OTP length from payload: " + e.getMessage());
            return 0;
        }
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
