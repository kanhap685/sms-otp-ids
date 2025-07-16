package org.wso2.carbon.identity.custom.federated.authenticator.sms;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.custom.federated.authenticator.CustomFederatedAuthenticator;
import org.wso2.carbon.identity.custom.federated.authenticator.exception.SMSOTPException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static java.util.Base64.getEncoder;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

public class SMSOTPAuthenticator implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Log log = LogFactory.getLog(SMSOTPAuthenticator.class);

    public boolean canHandle(HttpServletRequest request) {
        String otpCode = request.getParameter(SMSOTPConstants.CODE);
        if (StringUtils.isNotEmpty(otpCode)) {
            return true;
        }

        String resend = request.getParameter(SMSOTPConstants.RESEND);
        if (StringUtils.isNotEmpty(resend) && StringUtils.isEmpty(otpCode)) {
            return true;
        }

        String mobileNumber = request.getParameter(SMSOTPConstants.MOBILE_NUMBER);
        if (StringUtils.isNotEmpty(mobileNumber)) {
            return true;
        }

        String otpToken = request.getParameter("OTPcode");
        if (StringUtils.isNotEmpty(otpToken)) {
            return true;
        }

        return false;
    }

    public String getFriendlyName() {
        return "SMSOTP-IDS";
    }

    public String getName() {
        return "SMSOTP-IDS";
    }

    public String getClaimDialectURI() {
        return SMSOTPConstants.OIDC_DIALECT;
    }

    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property smsUrl = new Property();
        smsUrl.setName(SMSOTPConstants.SMS_URL);
        smsUrl.setDisplayName("SMS URL");
        smsUrl.setRequired(true);
        smsUrl.setDescription("Enter client sms url value. If the phone number and text message are in URL, " +
                "specify them as $ctx.num and $ctx.msg");
        smsUrl.setDisplayOrder(0);
        configProperties.add(smsUrl);

        Property httpMethod = new Property();
        httpMethod.setName(SMSOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(true);
        httpMethod.setDescription("Enter the HTTP Method used by the SMS API");
        httpMethod.setDisplayOrder(1);
        configProperties.add(httpMethod);

        Property headers = new Property();
        headers.setName(SMSOTPConstants.HEADERS);
        headers.setDisplayName("HTTP Headers");
        headers.setRequired(false);
        headers.setDescription("Enter the headers used by the API separated by comma, with the Header name and value " +
                "separated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num and $ctx.msg");
        headers.setDisplayOrder(2);
        configProperties.add(headers);

        Property payload = new Property();
        payload.setName(SMSOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the SMS API. If the phone number and text message are " +
                "in Payload, specify them as $ctx.num and $ctx.msg");
        payload.setDisplayOrder(3);
        configProperties.add(payload);

        Property httpResponse = new Property();
        httpResponse.setName(SMSOTPConstants.HTTP_RESPONSE);
        httpResponse.setDisplayName("HTTP Response Code");
        httpResponse.setRequired(false);
        httpResponse.setDescription(
                "Enter the HTTP response code the API sends upon successful call. Leave empty if unknown");
        httpResponse.setDisplayOrder(4);
        configProperties.add(httpResponse);

        Property showErrorInfo = new Property();
        showErrorInfo.setName(SMSOTPConstants.SHOW_ERROR_INFO);
        showErrorInfo.setDisplayName("Show Detailed Error Information");
        showErrorInfo.setRequired(false);
        showErrorInfo.setDescription("Enter \"true\" if detailed error information from SMS provider needs to be " +
                "displayed in the UI");
        showErrorInfo.setDisplayOrder(5);
        configProperties.add(showErrorInfo);

        Property valuesToBeMasked = new Property();
        valuesToBeMasked.setName(SMSOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        valuesToBeMasked.setDisplayName("Mask values in Error Info");
        valuesToBeMasked.setRequired(false);
        valuesToBeMasked
                .setDescription("Enter comma separated Values to be masked by * in the detailed error messages");
        valuesToBeMasked.setDisplayOrder(6);
        configProperties.add(valuesToBeMasked);

        return configProperties;
    }

    public void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        try {
            // Direct SMS OTP handling
            handleSMSOTP(request, response, context);
        } catch (Exception e) {
            log.error("Error processing authentication request", e);
            throw new AuthenticationFailedException("Error processing authentication request", e);
        }
    }

    public void handleSMSOTP(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (context == null) {
            log.error("AuthenticationContext is null");
            throw new AuthenticationFailedException("AuthenticationContext is null");
        }

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());

        try {

            String usernameFromPreviousStep = null;
            AuthenticatedUser authenticatedUser;
            String mobileNumber;

            String tenantDomain = context.getTenantDomain();

            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.AUTHENTICATOR_NAME);

            // Handle tenant-specific configurations
            if (!tenantDomain.equals(SMSOTPConstants.SUPER_TENANT)) {
                log.debug("Handling authentication for tenant: " + tenantDomain);
            }

            // Get username from previous authentication step if available
            authenticatedUser = (AuthenticatedUser) context.getProperty(SMSOTPConstants.AUTHENTICATED_USER);
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getStepMap() != null) {
                for (Map.Entry<Integer, org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig> entry : context
                        .getSequenceConfig().getStepMap().entrySet()) {
                    if (entry.getKey() < context.getCurrentStep() && entry.getValue().getAuthenticatedUser() != null) {
                        authenticatedUser = entry.getValue().getAuthenticatedUser();
                        usernameFromPreviousStep = authenticatedUser.getUserName();
                        log.debug("Found username from previous step: " + usernameFromPreviousStep);
                        // Store the AuthenticatedUser in context for use in
                        // processAuthenticationResponse
                        context.setProperty(SMSOTPConstants.AUTHENTICATED_USER, authenticatedUser);
                        break;
                    }
                }
            }

            // Store the username for use in this federated authentication step
            if (usernameFromPreviousStep != null) {
                context.setProperty("usernameFromPreviousStep", usernameFromPreviousStep);
            }

            // Check if user exists - for federated flows, we assume user exists since they
            // came from external IdP
            // Use username from previous step or from context
            String usernameToCheck = usernameFromPreviousStep;
            if (StringUtils.isBlank(usernameToCheck)) {
                // If no username from previous step, try to find from context properties
                Object contextUsername = context.getProperty(SMSOTPConstants.USER_NAME);
                if (contextUsername != null) {
                    usernameToCheck = String.valueOf(contextUsername);
                }
            }

            boolean isUserExists = false;
            if (StringUtils.isNotBlank(usernameToCheck)) {
                try {
                    // For federated authenticator, assume user exists since they come from external
                    // IdP
                    isUserExists = true;
                    if (log.isDebugEnabled()) {
                        log.debug("Username to check: " + usernameToCheck + " (assuming exists for federated auth)");
                    }
                } catch (Exception e) {
                    log.warn("Error checking user existence for username: " + usernameToCheck, e);
                    isUserExists = false;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No username available to check user existence");
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("User exists: " + isUserExists + ", Username: " + usernameFromPreviousStep);
            }

            // SMS OTP authentication is mandatory and user doesn't disable SMS OTP claim in
            // user's profile.
            String errorPage = CustomFederatedAuthenticator.getErrorPage(context);

            if (isUserExists) {
                mobileNumber = getMobileNumber(request, response, context, usernameFromPreviousStep,
                        tenantDomain, queryParams);
                if (StringUtils.isNotEmpty(mobileNumber)) {
                    proceedWithSMSOTP(response, context, errorPage, mobileNumber, queryParams,
                            usernameFromPreviousStep);
                } else {
                    // getMobileNumber returned null, which means redirection already happened
                    if (log.isDebugEnabled()) {
                        log.debug("Mobile number is null, redirection already handled");
                    }
                    return;
                }
            } else {
                processFirstStepOnly(authenticatedUser, context);
            }

        } catch (javax.mail.AuthenticationFailedException e) {
            log.error("Authentication failed: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "Authentication failed: " + e.getMessage());
            return;
        } catch (SMSOTPException e) {
            log.error("SMS OTP exception: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "SMS OTP processing failed: " + e.getMessage());
            return;
        } catch (Exception e) {
            log.error("Unexpected error in handleSMSOTP: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "An unexpected error occurred. Please try again.");
            return;
        }
    }

    public void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Processing SMS OTP authentication response");
        }

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());

        String userToken = request.getParameter(SMSOTPConstants.CODE);
        if (StringUtils.isEmpty(userToken)) {
            userToken = request.getParameter("OTPcode");
        }

        String contextToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                .getProperty(SMSOTPConstants.AUTHENTICATED_USER);

        if (log.isDebugEnabled()) {
            log.debug("Validating OTP - User token length: " + (userToken != null ? userToken.length() : "null") +
                    ", Context token length: " + (contextToken != null ? contextToken.length() : "null"));
        }

        if (authenticatedUser == null) {
            log.error("AuthenticatedUser is null in processAuthenticationResponse");
            redirectToErrorPage(response, context, queryParams, "Authentication session expired. Please try again.");
            return;
        }

        if (StringUtils.isEmpty(userToken)) {
            redirectToErrorPage(response, context, queryParams, "Please enter the OTP code.");
            return;
        }

        if (StringUtils.isEmpty(contextToken)) {
            redirectToErrorPage(response, context, queryParams, "OTP session expired. Please try again.");
            return;
        }

        userToken = userToken.trim();
        contextToken = contextToken.trim();

        if (!userToken.equals(contextToken)) {
            if (log.isDebugEnabled()) {
                log.debug("OTP token mismatch. User token: '" + userToken + "' (" + userToken.length() +
                        " chars), Context token: '" + contextToken + "' (" + contextToken.length() + " chars)");
            }

            context.setProperty(SMSOTPConstants.CODE_MISMATCH, true);
            redirectToErrorPage(response, context, queryParams, 
                "Invalid OTP code. Please enter the complete " + contextToken.length() + "-digit OTP sent to your mobile.");
            return;
        }

        Long sentOTPTokenTime = (Long) context.getProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME);
        Long tokenValidityTime = (Long) context.getProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME);

        if (sentOTPTokenTime != null && tokenValidityTime != null) {
            long currentTime = System.currentTimeMillis();
            long elapsedTime = currentTime - sentOTPTokenTime;
            long validityPeriod = tokenValidityTime * 60 * 1000; // Convert minutes to milliseconds

            if (elapsedTime > validityPeriod) {
                context.setProperty(SMSOTPConstants.TOKEN_EXPIRED, "true");
                redirectToErrorPage(response, context, queryParams, "OTP has expired. Please request a new code.");
                return;
            }
        }

        try {
            String userStoreDomain = authenticatedUser.getUserStoreDomain();
            String userName = authenticatedUser.getUserName();
            String qualifiedUsername = (StringUtils.isNotEmpty(userStoreDomain) ? userStoreDomain + "/" : "")
                    + userName;

            SMSOTPUtils.getMobileNumberForUsername(qualifiedUsername);

            if (log.isDebugEnabled()) {
                log.debug("~~~~~~ SMS OTP authentication successful for user: " + userName + " ~~~~~~");
            }
            context.setSubject(authenticatedUser);

        } catch (SMSOTPException e) {
            log.error("Error getting mobile number for user: " + authenticatedUser.getUserName(), e);
            redirectToErrorPage(response, context, queryParams, "Error validating user information. Please try again.");
            return;
        } catch (javax.mail.AuthenticationFailedException e) {
            log.error("Authentication failed exception", e);
            redirectToErrorPage(response, context, queryParams, "Authentication failed. Please try again.");
            return;
        }
    }

    public String getContextIdentifier(HttpServletRequest request) {

        String state = request.getParameter(SMSOTPConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 0) {
                return stateElements[0];
            }
        }

        String sessionDataKey = request.getParameter("sessionDataKey");
        if (StringUtils.isNotBlank(sessionDataKey)) {
            return sessionDataKey;
        }

        return null;
    }

    public String getScreenAttribute(AuthenticationContext context, UserRealm userRealm, String username)
            throws UserStoreException, AuthenticationFailedException {

        String screenUserAttributeParam;
        String screenUserAttributeValue = null;
        String screenValue = null;
        int noOfDigits = 0;

        screenUserAttributeParam = SMSOTPUtils.getScreenUserAttribute(context);
        if (screenUserAttributeParam != null) {
            screenUserAttributeValue = userRealm.getUserStoreManager()
                    .getUserClaimValue(username, screenUserAttributeParam, null);
        }

        if (screenUserAttributeValue != null) {
            if ((SMSOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(SMSOTPUtils.getNoOfDigits(context));
            }
            screenValue = CustomFederatedAuthenticator.getMaskedValue(context, screenUserAttributeValue, noOfDigits);
        }
        return screenValue;
    }

    private String getMobileNumber(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context, String username, String tenantDomain,
            String queryParams)
            throws AuthenticationFailedException, SMSOTPException, javax.mail.AuthenticationFailedException {

        String mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
        if (StringUtils.isEmpty(mobileNumber)) {
            if (request.getParameter(SMSOTPConstants.MOBILE_NUMBER) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User has not registered a mobile number: " + username);
                }
                redirectToMobileNoReqPage(response, context, queryParams);
                return null; // Return null to indicate redirection happened
            } else {
                updateMobileNumberForUsername(context, request, username, tenantDomain);
                mobileNumber = SMSOTPUtils.getMobileNumberForUsername(username);
            }
        }
        return mobileNumber;
    }

    public static boolean isSendOTPDirectlyToMobile(AuthenticationContext context) {

        return Boolean
                .parseBoolean(SMSOTPUtils.getConfiguration(context, SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE));
    }

    private void proceedWithSMSOTP(HttpServletResponse response, AuthenticationContext context, String errorPage,
            String mobileNumber, String queryParams, String username)
            throws AuthenticationFailedException, javax.mail.AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Proceeding with OTP for user: " + username + ", mobile: " + mobileNumber);
        }

        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                .getProperty(SMSOTPConstants.AUTHENTICATED_USER);
        if (authenticatedUser == null && StringUtils.isNotEmpty(username)) {
            if (log.isDebugEnabled()) {
                log.debug("Creating AuthenticatedUser for username: " + username);
            }
            authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
            context.setProperty(SMSOTPConstants.AUTHENTICATED_USER, authenticatedUser);
        }

        String screenValue;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String loginPage = CustomFederatedAuthenticator.getLoginPage(context);

        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = (UserRealm) SMSOTPUtils.getUserRealm(tenantDomain);
        int tokenLength = 4; // Force 4-digit OTP
        boolean isEnableAlphanumericToken = SMSOTPUtils.isEnableAlphanumericToken(context);

        try {
            // Generate OTP token
            OneTimePassword token = new OneTimePassword();
            String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);

            // Check for configured token length but override to 4
            if ((SMSOTPUtils.getTokenLength(context)) != null) {
                int configTokenLength = Integer.parseInt(SMSOTPUtils.getTokenLength(context));
                if (log.isDebugEnabled()) {
                    log.debug("Config token length: " + configTokenLength + ", but using 4 digits");
                }
            }

            if ((SMSOTPUtils.getTokenExpiryTime(context)) != null) {
                long tokenExpiryTime = Integer.parseInt(SMSOTPUtils.getTokenExpiryTime(context));
                context.setProperty(SMSOTPConstants.TOKEN_VALIDITY_TIME, tokenExpiryTime);
            }

            String otpToken = token.generateToken(secret, String.valueOf(SMSOTPConstants.NUMBER_BASE), tokenLength,
                    isEnableAlphanumericToken);

            if (log.isDebugEnabled()) {
                log.debug("Generated OTP token with length: " + otpToken.length());
            }
            // Get SMS provider configuration
            String smsUrl = authenticatorProperties.get(SMSOTPConstants.SMS_URL);
            smsUrl = smsUrl + "sendOneTimePW.json";
            String httpMethod = authenticatorProperties.get(SMSOTPConstants.HTTP_METHOD);
            String headerString = authenticatorProperties.get(SMSOTPConstants.HEADERS);
            String payload = authenticatorProperties.get(SMSOTPConstants.PAYLOAD);
            String httpResponse = authenticatorProperties.get(SMSOTPConstants.HTTP_RESPONSE);

            String actualOtpSent = null;
            // Send SMS via configured provider
            if (StringUtils.isNotEmpty(smsUrl)) {
                actualOtpSent = sendRESTCall(context, smsUrl, httpMethod, headerString, payload,
                        httpResponse, mobileNumber, otpToken);
            }

            if (StringUtils.isEmpty(actualOtpSent)) {
                String errorMessage = "Failed to send SMS OTP";
                
                if (context.getProperty(SMSOTPConstants.ERROR_CODE) != null) {
                    errorMessage = context.getProperty(SMSOTPConstants.ERROR_CODE).toString();
                } else {
                    errorMessage = "Unable to send verification code. Please try again.";
                    context.setProperty(SMSOTPConstants.ERROR_CODE, SMSOTPConstants.UNABLE_SEND_CODE_VALUE);
                }
                
                // Redirect to error page instead of login page
                redirectToErrorPage(response, context, queryParams, errorMessage);
            } else {
                // SMS sent successfully, store actual OTP and redirect to login page
                if (log.isDebugEnabled()) {
                    log.debug("SMS sent successfully, storing actual OTP in context");
                }

                context.setProperty(SMSOTPConstants.OTP_TOKEN, actualOtpSent);
                long sentOTPTokenTime = System.currentTimeMillis();
                context.setProperty(SMSOTPConstants.SENT_OTP_TOKEN_TIME, sentOTPTokenTime);
                String url = CustomFederatedAuthenticator.getURL(loginPage, queryParams, getName());

                // Add screen value if user exists
                boolean isUserExists = StringUtils.isNotEmpty(username);
                if (isUserExists) {
                    screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
                    if (screenValue != null) {
                        url = url + SMSOTPConstants.SCREEN_VALUE + screenValue;
                    }
                }

                // Store actualOtpSent in session/context instead of URL for security
                if (StringUtils.isNotEmpty(actualOtpSent)) {
                    // Store in authentication context - more secure than URL parameter
                    context.setProperty("CLIENT_OTP_VALIDATION", actualOtpSent);
                    if (log.isDebugEnabled()) {
                        log.debug("Storing actualOtpSent in authentication context for secure client-side validation");
                    }
                }

                // Store payload configuration for JSP usage
                if (StringUtils.isNotEmpty(payload)) {
                    context.setProperty("SMS_PAYLOAD_CONFIG", payload);
                    log.info("Storing SMS payload configuration in authentication context: " + payload);
                    if (log.isDebugEnabled()) {
                        log.debug("Storing SMS payload configuration in authentication context for JSP");
                    }
                } else {
                    log.warn("SMS payload is empty, not storing in context");
                }

                response.sendRedirect(url);
            }
        } catch (IOException e) {
            log.error("Error while sending the HTTP request: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "Error sending SMS. Please try again.");
            return;
        } catch (UserStoreException e) {
            log.error("Failed to get the user from user store: " + e.getMessage(), e);
            redirectToErrorPage(response, context, queryParams, "Error accessing user information. Please try again.");
            return;
        }
    }

    public String sendRESTCall(AuthenticationContext context, String smsUrl, String httpMethod,
            String headerString, String payload, String httpResponse, String mobile,
            String otpToken)
            throws IOException, AuthenticationFailedException, javax.mail.AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Sending SMS to mobile: " + mobile + " with OTP length: " + otpToken.length());
        }

        HttpURLConnection httpConnection;
        String smsMessage = SMSOTPConstants.SMS_MESSAGE;
        String encodedMobileNo = URLEncoder.encode(mobile, "UTF-8");
        smsUrl = smsUrl.replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.msg",
                smsMessage.replaceAll("\\s", "+") + otpToken);

        URL smsProviderUrl = null;
        try {
            log.debug(">>>>>smsUrl: =>" + smsUrl);
            smsProviderUrl = new URL(smsUrl);
            log.debug(">>>>>smsProviderUrl: =>" + smsProviderUrl);
        } catch (MalformedURLException e) {
            log.error("Error while parsing SMS provider URL: " + smsUrl, e);
            context.setProperty(SMSOTPConstants.ERROR_CODE, "The SMS URL does not conform to URL specification");
            return null;
        }
        String subUrl = smsProviderUrl.getProtocol();
        if (subUrl.equals(SMSOTPConstants.HTTPS)) {
            httpConnection = (HttpsURLConnection) smsProviderUrl.openConnection();
            return getConnection(httpConnection, context, headerString, payload, httpResponse, encodedMobileNo,
                    smsMessage, otpToken, httpMethod);
        } else {
            httpConnection = (HttpURLConnection) smsProviderUrl.openConnection();
            return getConnection(httpConnection, context, headerString, payload, httpResponse, encodedMobileNo,
                    smsMessage, otpToken, httpMethod);
        }
    }

    private void redirectToMobileNoReqPage(HttpServletResponse response, AuthenticationContext context,
            String queryParams) throws AuthenticationFailedException {

        boolean isEnableMobileNoUpdate = SMSOTPUtils.isEnableMobileNoUpdate(context);
        if (isEnableMobileNoUpdate) {
            String loginPage = SMSOTPUtils.getMobileNumberRequestPage(context);
            try {
                String url = CustomFederatedAuthenticator.getURL(loginPage, queryParams, getName());
                if (log.isDebugEnabled()) {
                    log.debug("Redirecting to mobile number request page : " + url);
                }
                response.sendRedirect(url);
            } catch (IOException e) {
                log.error("Error redirecting to mobile number request page", e);
                redirectToErrorPage(response, context, queryParams, 
                    "System connection error. Please try again.");
                return;
            }
        } else {
            log.warn("Mobile number update is disabled but user has no mobile number registered");
            redirectToErrorPage(response, context, queryParams, 
                "Mobile number not found in system. Please contact administrator to register your mobile number.");
            return;
        }
    }

    private void updateMobileNumberForUsername(AuthenticationContext context, HttpServletRequest request,
            String username, String tenantDomain)
            throws SMSOTPException, AuthenticationFailedException {

        if (username != null && !context.isRetrying()) {
            if (log.isDebugEnabled()) {
                log.debug("Updating mobile number for user : " + username);
            }
            Map<String, String> attributes = new HashMap<>();
            attributes.put(SMSOTPConstants.MOBILE_CLAIM, request.getParameter(SMSOTPConstants.MOBILE_NUMBER));
            SMSOTPUtils.updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes,
                    tenantDomain);
        }
    }

    private String getConnection(HttpURLConnection httpConnection, AuthenticationContext context, String headerString,
            String payload, String httpResponse, String encodedMobileNo, String smsMessage,
            String otpToken, String httpMethod)
            throws AuthenticationFailedException, javax.mail.AuthenticationFailedException {

        try {
            // log.info("In Method getConnection >> Payload = " + payload);
            // log.info("In Method getConnection >> Header = " + headerString);
            httpConnection.setDoInput(true);
            httpConnection.setDoOutput(true);
            String[] headerArray;
            context.setProperty(SMSOTPConstants.GSSO_TRANSACTION_ID, null);
            com.google.gson.Gson gson = new com.google.gson.Gson();
            GssoSendOneTimePWResponse gssoresponse = new GssoSendOneTimePWResponse();
            if (StringUtils.isNotEmpty(headerString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Processing HTTP headers since header string is available");
                }
                headerString = headerString.trim().replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.msg",
                        smsMessage + otpToken);
                headerArray = headerString.split(",");
                for (String header : headerArray) {
                    String[] headerElements = header.split(":");
                    if (headerElements.length > 1) {
                        httpConnection.setRequestProperty(headerElements[0], headerElements[1]);
                    } else {
                        log.info("Either header name or value not found. Hence not adding header which contains " +
                                headerElements[0]);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No configured headers found. Header string is empty");
                }
            }

            // Processing HTTP Method
            if (log.isDebugEnabled()) {
                log.debug("Configured http method is " + httpMethod);
            }
            // log.info("In Method getConnection >> Header = " + headerString);
            if (SMSOTPConstants.GET_METHOD.equalsIgnoreCase(httpMethod)) {
                httpConnection.setRequestMethod(SMSOTPConstants.GET_METHOD);

            } else if (SMSOTPConstants.POST_METHOD.equalsIgnoreCase(httpMethod)) {
                httpConnection.setRequestMethod(SMSOTPConstants.POST_METHOD);

                if (StringUtils.isNotEmpty(payload)) {
                    encodedMobileNo = encodedMobileNo.replaceFirst("0", "66");
                    payload = payload.replaceAll("\\$ctx.num", encodedMobileNo);
                    log.info("GssoSendOneTimePW Request: " + payload);

                    OutputStreamWriter writer = null;
                    try {
                        log.debug("Establishing connection to SMS provider...");
                        writer = new OutputStreamWriter(httpConnection.getOutputStream(), SMSOTPConstants.CHAR_SET);
                        writer.write(payload);
                        // writer.flush(); // Ensure data is written
                        log.debug("Payload successfully sent to SMS provider");
                    } catch (IOException e) {
                        log.error("Failed to send payload to SMS provider. URL: " + httpConnection.getURL());
                        log.error("Payload that failed to send: " + payload);
                        log.error("Connection details - Connected: " + httpConnection.getDoOutput() +
                                ", Method: " + httpConnection.getRequestMethod());
                        throw new AuthenticationFailedException(
                                "Error while posting payload message: " + e.getMessage(), e);
                    } finally {
                        if (writer != null) {
                            try {
                                writer.close();
                            } catch (IOException e) {
                                log.warn("Error closing output stream writer", e);
                            }
                        }
                    }
                } else {
                    log.warn("POST method specified but payload is empty");
                }
            }
            log.debug("out from writer");
            log.debug("HTTP CONNECTION " + httpConnection.toString() + httpConnection.getInputStream());
            String bodyStr = IOUtils.toString(httpConnection.getInputStream(), SMSOTPConstants.CHAR_SET);
            log.info("GssoSendOneTimePWResponse = " + bodyStr);

            gssoresponse = gson.fromJson(bodyStr, GssoSendOneTimePWResponse.class);
            log.debug("GssoSendOneTimePWResponse" + gssoresponse.getSendOneTimePWResponse().getCode());
            log.debug("httpConnection.getResponseCode :: " + httpConnection.getResponseCode());

            if (StringUtils.isNotEmpty(httpResponse)) {
                if (httpResponse.trim().equals(String.valueOf(httpConnection.getResponseCode()))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Code is successfully sent to the mobile and recieved expected response code : "
                                + httpResponse);
                    }
                    // Extract and return the actual OTP sent via SMS by GSSOService
                    String actualOtpSent = gssoresponse.getSendOneTimePWResponse().getOneTimePassword();
                    log.info("=== ACTUAL OTP FROM GSSO SERVICE (HTTP Response Case) ===");
                    log.info("Actual OTP sent via SMS: '" + actualOtpSent + "'");
                    log.info("========================================================");
                    return actualOtpSent;
                }
            } else {
                if (httpConnection.getResponseCode() == 200 || httpConnection.getResponseCode() == 201
                        || httpConnection.getResponseCode() == 202) {

                    String gssoResponseStatus = gssoresponse.getSendOneTimePWResponse().getCode();
                    log.debug("gssoResponseStatus : " + gssoResponseStatus + " : "
                            + SMSOTPConstants.GSSO_RESPONSE_SUCCESS.equals(gssoResponseStatus));
                    if (SMSOTPConstants.GSSO_RESPONSE_SUCCESS.equals(gssoResponseStatus)) {
                        context.setProperty(SMSOTPConstants.GSSO_TRANSACTION_ID,
                                gssoresponse.getSendOneTimePWResponse().getTransactionID());
                        if (log.isDebugEnabled()) {
                            log.debug("Code is successfully sent to the mobile. Relieved HTTP response code is : "
                                    + httpConnection.getResponseCode());
                        }
                        log.info("Code is successfully sent to the mobile. Relieved HTTP response code is : "
                                + httpConnection.getResponseCode());
                        log.info("SendSMSOTP Response Code from GSSOService is : "
                                + gssoresponse.getSendOneTimePWResponse().getCode() + " and Response Message is "
                                + gssoresponse.getSendOneTimePWResponse().getDescription());

                        // Extract and return the actual OTP sent via SMS by GSSOService
                        String actualOtpSent = gssoresponse.getSendOneTimePWResponse().getOneTimePassword();
                        log.info("=== ACTUAL OTP FROM GSSO SERVICE ===");
                        log.info("Actual OTP sent via SMS: '" + actualOtpSent + "'");
                        log.info("===================================");
                        return actualOtpSent;
                    } else {
                        context.setProperty(SMSOTPConstants.ERROR_CODE,
                                "The Username/ Mobile Number is not registered into the system.Please contact CCC 02-2719191. ("
                                        + gssoresponse.getSendOneTimePWResponse().getCode() + ")");
                        log.error("Error while sending SMS: error code is "
                                + gssoresponse.getSendOneTimePWResponse().getCode() + " and error message is "
                                + gssoresponse.getSendOneTimePWResponse().getDescription());

                        return null;
                    }
                } else {
                    context.setProperty(SMSOTPConstants.ERROR_CODE, httpConnection.getResponseCode() + " : " +
                            httpConnection.getResponseMessage());
                    String content = getSanitizedErrorInfo(httpConnection, context, encodedMobileNo);

                    log.error("Error while sending SMS: error code is " + httpConnection.getResponseCode()
                            + " and error message is " + httpConnection.getResponseMessage());
                    context.setProperty(SMSOTPConstants.ERROR_INFO, content);
                    return null;
                }
            }
        } catch (MalformedURLException e) {
            throw new AuthenticationFailedException("Invalid URL ", e);
        } catch (ProtocolException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP method ", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP response ", e);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }
        return null;
    }

    private String getSanitizedErrorInfo(HttpURLConnection httpConnection, AuthenticationContext context,
            String encodedMobileNo)
            throws IOException, AuthenticationFailedException, javax.mail.AuthenticationFailedException {

        String contentRaw = readContent(httpConnection);

        String screenValue = getScreenValue(context);
        if (StringUtils.isEmpty(screenValue)) {
            int noOfDigits = 0;
            if ((SMSOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(SMSOTPUtils.getNoOfDigits(context));
            }
            screenValue = CustomFederatedAuthenticator.getMaskedValue(context, encodedMobileNo, noOfDigits);
        }
        String content = contentRaw.replace(encodedMobileNo, screenValue);
        try {
            String decodedMobileNo = URLDecoder.decode(encodedMobileNo, SMSOTPConstants.CHAR_SET);
            content = content.replace(decodedMobileNo, screenValue);
        } catch (java.io.UnsupportedEncodingException e) {
            log.warn("Failed to decode mobile number: " + e.getMessage());
        }
        content = maskConfiguredValues(context, content);
        context.setProperty(SMSOTPConstants.ERROR_INFO, content);

        String errorContent = content;
        if (log.isDebugEnabled()) {
            errorContent = contentRaw;
        }
        log.error(String.format("Following Error occurred while sending SMS for user: %s, %s", String.valueOf(context
                .getProperty(SMSOTPConstants.USER_NAME)), errorContent));

        return content;
    }

    private String readContent(HttpURLConnection httpConnection) throws IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(httpConnection.getErrorStream()));
        StringBuilder sb = new StringBuilder();
        String output;
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }
        return sb.toString();
    }

    private String maskConfiguredValues(AuthenticationContext context, String content) {

        String valuesToMask = context.getAuthenticatorProperties()
                .get(SMSOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        if (StringUtils.isNotEmpty(valuesToMask)) {
            String[] values = valuesToMask.split(SMSOTPConstants.MASKING_VALUE_SEPARATOR);
            for (String val : values) {
                content = content.replaceAll(val, CustomFederatedAuthenticator.getMaskedValue(context, val, 0));
            }

        }
        return content;
    }

    private String getScreenValue(AuthenticationContext context)
            throws AuthenticationFailedException, javax.mail.AuthenticationFailedException {

        String screenValue;
        String username = String.valueOf(context.getProperty(SMSOTPConstants.USER_NAME));
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = (UserRealm) SMSOTPUtils.getUserRealm(tenantDomain);
        try {
            screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the screen attribute for the user " +
                    tenantAwareUsername + " from user store. ", e);
        }
        return screenValue;
    }

    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Processing First step only. Skipping SMSOTP");
        }
        // the authentication flow happens with basic authentication.
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator()
                .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
            if (log.isDebugEnabled()) {
                log.debug("Found local authenticator in previous step. Hence setting a local user");
            }
            // Set the authenticated user for the step config directly
            stepConfig.setAuthenticatedUser(authenticatedUser);
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.BASIC);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Found federated authenticator in previous step. Hence setting a local user");
            }
            // Set the authenticated user for the step config directly
            stepConfig.setAuthenticatedUser(authenticatedUser);
            context.setProperty(SMSOTPConstants.AUTHENTICATION, SMSOTPConstants.FEDERETOR);
        }
    }

    /**
     * Redirect to SMS OTP error page with error messages
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
            String queryParams, String errorMessage) throws AuthenticationFailedException {
        try {
            String errorPage = CustomFederatedAuthenticator.getErrorPage(context);
            String redirectUrl = CustomFederatedAuthenticator.getURL(errorPage, queryParams, getName());
            
            // Add error message parameters
            String errorParam = "";
            if (StringUtils.isNotEmpty(errorMessage)) {
                errorParam = "&authFailure=true&authFailureMsg=" + URLEncoder.encode(errorMessage, "UTF-8");
            }
            
            // Add error code if available
            if (context.getProperty(SMSOTPConstants.ERROR_CODE) != null) {
                errorParam += "&errorCode=" + URLEncoder.encode(context.getProperty(SMSOTPConstants.ERROR_CODE).toString(), "UTF-8");
            }
            
            // Add error info if available and configured to show
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (context.getProperty(SMSOTPConstants.ERROR_INFO) != null &&
                Boolean.parseBoolean(authenticatorProperties.get(SMSOTPConstants.SHOW_ERROR_INFO))) {
                String errorInfo = context.getProperty(SMSOTPConstants.ERROR_INFO).toString();
                try {
                    errorParam += "&errorInfo=" + getEncoder().encodeToString(errorInfo.getBytes("UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    log.warn("UTF-8 encoding not supported, using default encoding", e);
                    errorParam += "&errorInfo=" + getEncoder().encodeToString(errorInfo.getBytes());
                }
            }
            
            String finalRedirectUrl = redirectUrl + errorParam;
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + finalRedirectUrl);
            }
            
            response.sendRedirect(finalRedirectUrl);
            
        } catch (IOException e) {
            log.error("Error redirecting to error page", e);
            throw new AuthenticationFailedException("Error redirecting to error page", e);
        }
    }

}
