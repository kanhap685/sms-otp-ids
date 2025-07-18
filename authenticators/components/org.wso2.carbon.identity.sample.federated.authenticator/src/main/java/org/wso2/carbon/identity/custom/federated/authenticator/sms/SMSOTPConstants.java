package org.wso2.carbon.identity.custom.federated.authenticator.sms;

public class SMSOTPConstants {
    public static final String AUTHENTICATOR_NAME = "SMSOTP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "SMS OTP";
    public static final String ALGORITHM_NAME = "SHA1PRNG";
    public static final String ALGORITHM_HMAC = "HmacSHA1";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-1";
    public static final String CHAR_SET = "UTF-8";

    public static final int SECRET_KEY_LENGTH = 5;
    public static final int NUMBER_BASE = 2;
    public static final int NUMBER_DIGIT = 4;
    public static final String CODE = "OTPcode";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String SAVED_OTP_LIST = "http://wso2.org/claims/otpbackupcodes";
    public static final String USER_SMSOTP_DISABLED_CLAIM_URI = "http://wso2.org/claims/identity/smsotp_disabled";

    public static final String SMS_URL = "sms_url";
    public static final String HTTP_METHOD = "http_method";
    public static final String HEADERS = "headers";
    public static final String PAYLOAD = "payload";
    public static final String HTTP_RESPONSE = "http_response";
    public static final String SHOW_ERROR_INFO = "show_detailed_error_info";
    public static final String VALUES_TO_BE_MASKED_IN_ERROR_INFO = "values_to_be_masked";
    public static final String SMS_MESSAGE = "Verification Code: ";
    public static final String BACKUP_CODE = "BackupCode";
    public static final String IS_ENABLED_RETRY = "RetryEnable";
    public static final String IS_ENABLED_RESEND = "ResendEnable";
    public static final String IS_SMSOTP_MANDATORY = "SMSOTPMandatory";
    public static final String IS_SEND_OTP_DIRECTLY_TO_MOBILE = "SendOTPDirectlyToMobile";
    public static final String IS_SMSOTP_ENABLE_BY_USER = "SMSOTPEnableByUserClaim";
    public static final String IS_ENABLE_MOBILE_NO_UPDATE = "CaptureAndUpdateMobileNumber";
    public static final String IS_ENABLE_ALPHANUMERIC_TOKEN = "EnableAlphanumericToken";
    public static final String TOKEN_EXPIRY_TIME = "TokenExpiryTime";
    public static final String TOKEN_LENGTH = "TokenLength";
    public static final String OTP_DIGIT_COUNT = "OTPDigitCount";
    public static final String OTP_LIFETIME_MINS = "OTPLifetimeMins";

    public static final String GET_METHOD = "GET";
    public static final String POST_METHOD = "POST";

    public static final String SMSOTP_AUTHENTICATION_ENDPOINT_URL = "SMSOTPAuthenticationEndpointURL";
    public static final String SMSOTP_AUTHENTICATION_ERROR_PAGE_URL = "SMSOTPAuthenticationEndpointErrorPage";

    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String SMS_LOGIN_PAGE = "smsotpauthenticationendpoint/otp-verification.jsp";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_PAGE = "smsotpauthenticationendpoint/otp-error.jsp";
    public static final String MOBILE_NUMBER_REQ_PAGE = "smsotpauthenticationendpoint/mobile-number-request.jsp";
    public static final String MOBILE_NUMBER = "MOBILE_NUMBER";

    public static final String RESEND = "resendCode";
    public static final String NAME_OF_AUTHENTICATORS = "authenticators=";
    public static final String RESEND_CODE = "&resendCode=";
    public static final String OTP_TOKEN = "otpToken";
    public static final String AUTHENTICATION = "authentication";
    public static final String BASIC = "basic";
    public static final String HTTPS = "https";
    public static final String SUPER_TENANT = "carbon.super";
    public static final String FEDERETOR = "federator";
    public static final String USER_NAME = "username";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String STATUS_CODE = "statusCode";
    public static final String UNABLE_SEND_CODE = "UnableSend";
    public static final String ERROR_MESSAGE = "&authFailure=true&authFailureMsg=";
    public static final String ERROR_MESSAGE_DETAILS = "&authFailureInfo=";
    public static final String AUTH_FAILURE_INFO = "authFailureInfo";
    public static final String ERROR_INFO = "errorInfo";
    public static final String MASKING_VALUE_SEPARATOR = ",";
    public static final String UNABLE_SEND_CODE_VALUE = "unable.send.code";
    public static final String ERROR_SMSOTP_DISABLE = "&authFailure=true&authFailureMsg=smsotp.disable";
    public static final String ERROR_SMSOTP_DISABLE_MSG = "smsotp.disable";
    public static final String SEND_OTP_DIRECTLY_DISABLE = "&authFailure=true&authFailureMsg=directly.send.otp.disable";
    public static final String SEND_OTP_DIRECTLY_DISABLE_MSG = "directly.send.otp.disable";
    public static final String ERROR_CODE_MISMATCH = "code.mismatch";
    public static final String ERROR_CODE = "errorCode";
    public static final String SCREEN_USER_ATTRIBUTE = "screenUserAttribute";
    public static final String NO_DIGITS = "noOfDigits";
    public static final String ORDER = "order";
    public static final String BACKWARD = "backward";
    public static final String SCREEN_VALUE = "&screenvalue=";
    public static final String CODE_MISMATCH = "codeMismatch";
    public static final String ORDER_OF_DIGITS = "&order=";
    public static final String TOKEN_VALIDITY_TIME = "tokenValidityTime";
    public static final String SENT_OTP_TOKEN_TIME = "sentOTPTokenTime";
    public static final String TOKEN_EXPIRED = "tokenExpired";
    public static final String TOKEN_EXPIRED_VALUE = "token.expired";
    public static final String ATTRIBUTE_SMS_SENT_TO = "send-to" ;
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String EVENT_NAME = "SMSOTP";
    public static final String FEDERATED_MOBILE_ATTRIBUTE_KEY = "federatedMobileAttributeKey";
    public static final String IS_SEND_OTP_TO_FEDERATED_MOBILE = "SendOtpToFederatedMobile";

    /*GSSO Consatants*/
    public static final String GSSO_SERVICE = "IDS";
    public static final String GSSO_TRANSACTION_ID = "transactionID";
    public static final String GSSO_RESPONSE_SUCCESS = "2000";





    /*Default code */
    public static final String LOGIN_TYPE = "OIDC";

    public static final String OAUTH_OIDC_SCOPE = "openid";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";

    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID_TOKEN = "id_token";

    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String CALLBACK_URL = "callbackUrl";
    public static final String OAUTH2_AUTHZ_URL = "OAuth2AuthzEPUrl";
    public static final String OAUTH2_TOKEN_URL = "OAuth2TokenEPUrl";

    public static final String HTTP_ORIGIN_HEADER = "Origin";
    public static final String SUB = "sub";

    public static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
}
