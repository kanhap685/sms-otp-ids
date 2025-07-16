package org.wso2.carbon.identity.custom.federated.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPAuthenticator;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;

import net.minidev.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CustomFederatedAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1L;

    private static final Log log = LogFactory.getLog(CustomFederatedAuthenticator.class);
    private transient SMSOTPAuthenticator smsOTPAuthenticator;

    private SMSOTPAuthenticator getSmsOTPAuthenticator() {
        if (smsOTPAuthenticator == null) {
            smsOTPAuthenticator = new SMSOTPAuthenticator();
        }
        return smsOTPAuthenticator;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        // Check if SMS OTP can handle the request
        return getSmsOTPAuthenticator().canHandle(request);
    }

    @Override
    public String getFriendlyName() {
        return "Custom Federated Multi-OTP Authenticator";
    }

    @Override
    public String getName() {
        return "CustomFederatedAuthenticator";
    }

    @Override
    public String getClaimDialectURI() {
        return SMSOTPConstants.OIDC_DIALECT;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        // SMS Configuration Properties
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

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        if (context == null) {
            log.error("AuthenticationContext is null");
            redirectToErrorPage(response, context, "Authentication context is invalid. Please try again.");
            return;
        }

        try {
            
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties == null) {
                log.error("Authenticator properties is null");
                redirectToErrorPage(response, context, "Authenticator configuration is missing. Please contact administrator.");
                return;
            }

            String payload = authenticatorProperties.get(SMSOTPConstants.PAYLOAD);

            if (StringUtils.isEmpty(payload)) {
                log.error("Payload is empty or null");
                redirectToErrorPage(response, context, "SMS service configuration is missing. Please contact administrator.");
                return;
            }

            net.minidev.json.parser.JSONParser parser = new net.minidev.json.parser.JSONParser(
                    net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE);
            JSONObject root = null;
            try {
                root = (JSONObject) parser.parse(payload); // {"sendOneTimePW":{...}}
            } catch (net.minidev.json.parser.ParseException e) {
                log.error("Failed to parse payload JSON", e);
                redirectToErrorPage(response, context, "Invalid SMS service configuration. Please contact administrator.");
                return;
            }

            if (root == null) {
                log.error("Parsed JSON root is null");
                redirectToErrorPage(response, context, "Invalid SMS service configuration. Please contact administrator.");
                return;
            }

            JSONObject sendOTP = (JSONObject) root.get("sendOneTimePW"); // {...}
            if (sendOTP == null) {
                log.error("sendOneTimePW object not found in payload");
                redirectToErrorPage(response, context, "SMS service configuration is incomplete. Please contact administrator.");
                return;
            }

            log.debug("~~~~~~~~~~~~ start function handleSMSOTP ~~~~~~~~~~~~");

            getSmsOTPAuthenticator().handleSMSOTP(request, response, context);
            return;

        } catch (Exception e) {
            log.error("Error processing authentication request", e);
            redirectToErrorPage(response, context, "An unexpected error occurred. Please try again.");
            return;
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        if (context == null) {
            log.error("AuthenticationContext is null");
            redirectToErrorPage(response, context, "Authentication session expired. Please try again.");
            return;
        }

        try {
            // Check if this is a channel selection response
            String selectedChannel = request.getParameter("otpChannel");
            if (StringUtils.isNotEmpty(selectedChannel)) {
                log.debug("Processing channel selection: " + selectedChannel);
                
                // Store the selected channel in context
                context.setProperty("SELECTED_OTP_CHANNEL", selectedChannel);
                
                if ("SMS".equals(selectedChannel)) {
                    // Proceed with SMS OTP
                    getSmsOTPAuthenticator().handleSMSOTP(request, response, context);
                    return;
                } else if ("EMAIL".equals(selectedChannel)) {
                    // Proceed with Email OTP (placeholder for future implementation)
                    log.debug("Email OTP selected - implementing email flow");
                    // For now, fall back to SMS OTP
                    getSmsOTPAuthenticator().handleSMSOTP(request, response, context);
                    return;
                }
            }
            
            // Process SMS OTP authentication response
            getSmsOTPAuthenticator().processAuthenticationResponse(request, response, context);
        } catch (Exception e) {
            log.error("Error processing authentication response", e);
            redirectToErrorPage(response, context, "Error processing authentication response. Please try again.");
            return;
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        // Delegate to SMS authenticator since it has the same logic
        return getSmsOTPAuthenticator().getContextIdentifier(request);
    }

    /**
     * Common utility functions used by SMS OTP authenticator
     */

    public static String getErrorPage(AuthenticationContext context)
            throws AuthenticationFailedException {
        String errorPage = SMSOTPUtils.getErrorPageFromXMLFile(context);

        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used for SMS");
            }
        }
        return errorPage;
    }

    public static String getLoginPage(AuthenticationContext context)
            throws AuthenticationFailedException {
        String loginPage = SMSOTPUtils.getLoginPageFromXMLFile(context);

        if (StringUtils.isEmpty(loginPage)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.SMS_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used for SMS");
            }
        }
        return loginPage;
    }

    public static String getURL(String baseURI, String queryParams, String authenticatorName) {
        String url;
        String nameOfAuthenticators = SMSOTPConstants.NAME_OF_AUTHENTICATORS;

        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + nameOfAuthenticators + authenticatorName;
        } else {
            url = baseURI + "?" + nameOfAuthenticators + authenticatorName;
        }
        return url;
    }

    public static String getMaskedValue(AuthenticationContext context, String attributeValue, int noOfDigits) {
        String screenValue;
        String hiddenScreenValue;
        String digitsOrder = SMSOTPUtils.getDigitsOrder(context);

        int attributeLength = attributeValue.length();
        String backwardOrder = SMSOTPConstants.BACKWARD;

        if (backwardOrder.equals(digitsOrder)) {
            screenValue = attributeValue.substring(attributeLength - noOfDigits, attributeLength);
            hiddenScreenValue = attributeValue.substring(0, attributeLength - noOfDigits);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = ("*").concat(screenValue);
            }
        } else {
            screenValue = attributeValue.substring(0, noOfDigits);
            hiddenScreenValue = attributeValue.substring(noOfDigits, attributeLength);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = screenValue.concat("*");
            }
        }
        return screenValue;
    }

    /**
     * Redirect to SMS OTP error page with error messages
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
            String errorMessage) throws AuthenticationFailedException {
        try {
            String queryParams = "";
            if (context != null) {
                queryParams = context.getContextIdIncludedQueryParams();
            }
            
            String errorPage = getErrorPage(context);
            String redirectUrl = getURL(errorPage, queryParams, getName());
            
            // Add error message parameters
            String errorParam = "";
            if (StringUtils.isNotEmpty(errorMessage)) {
                errorParam = "&authFailure=true&authFailureMsg=" + java.net.URLEncoder.encode(errorMessage, "UTF-8");
            }
            
            // Add error code if available
            if (context != null && context.getProperty(SMSOTPConstants.ERROR_CODE) != null) {
                errorParam += "&errorCode=" + java.net.URLEncoder.encode(context.getProperty(SMSOTPConstants.ERROR_CODE).toString(), "UTF-8");
            }
            
            // Add error info if available and configured to show
            if (context != null && context.getAuthenticatorProperties() != null) {
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
                if (context.getProperty(SMSOTPConstants.ERROR_INFO) != null &&
                    Boolean.parseBoolean(authenticatorProperties.get(SMSOTPConstants.SHOW_ERROR_INFO))) {
                    String errorInfo = context.getProperty(SMSOTPConstants.ERROR_INFO).toString();
                    try {
                        errorParam += "&errorInfo=" + java.util.Base64.getEncoder().encodeToString(errorInfo.getBytes("UTF-8"));
                    } catch (java.io.UnsupportedEncodingException e) {
                        log.warn("UTF-8 encoding not supported, using default encoding", e);
                        errorParam += "&errorInfo=" + java.util.Base64.getEncoder().encodeToString(errorInfo.getBytes());
                    }
                }
            }
            
            String finalRedirectUrl = redirectUrl + errorParam;
            
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + finalRedirectUrl);
            }
            
            response.sendRedirect(finalRedirectUrl);
            
        } catch (java.io.IOException e) {
            log.error("Error redirecting to error page", e);
            throw new AuthenticationFailedException("Error redirecting to error page", e);
        }
    }
}
