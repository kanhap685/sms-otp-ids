package org.wso2.carbon.identity.custom.federated.authenticator.sms;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.custom.federated.authenticator.exception.SMSOTPException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;

import java.util.HashMap;
import java.util.Map;

import javax.mail.AuthenticationFailedException;

public class SMSOTPUtils {

    private static final Log log = LogFactory.getLog(SMSOTPUtils.class);
    
    // SMS Parameters สำหรับเก็บ configuration values
    private static Map<String, String> smsParameters = new HashMap<>();
    
    // Initialize default SMS parameters
    static {
        smsParameters.put(SMSOTPConstants.IS_SMSOTP_MANDATORY, "false");
        // เพิ่ม configuration อื่นๆ ตามต้องการ
    }

    public static boolean isSMSOTPMandatory(AuthenticationContext context) {
        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SMSOTP_MANDATORY));
    }

    /**
     * ดึงค่า configuration จาก context หรือ default parameters
     * 
     * @param context AuthenticationContext
     * @param configName ชื่อ configuration ที่ต้องการ
     * @return ค่า configuration หรือ null ถ้าไม่พบ
     */
    public static String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        Object propertiesFromLocal = context.getProperty("GET_PROPERTY_FROM_REGISTRY"); // ใช้ string แทน constant ที่ไม่มี
        String tenantDomain = context.getTenantDomain();
        
        // ตรวจสอบว่าเป็น super tenant หรือมี properties จาก local registry
        if ((propertiesFromLocal != null || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) &&
                getSMSParameters().containsKey(configName)) {
            configValue = getSMSParameters().get(configName);
        } 
        // ถ้าไม่พบใน SMS parameters ให้ลองหาใน context properties
        else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + " for tenant " + tenantDomain + " : " +
                    configValue);
        }
        return configValue;
    }
    
    /**
     * ดึง SMS parameters map
     * 
     * @return Map ของ SMS parameters
     */
    public static Map<String, String> getSMSParameters() {
        return smsParameters;
    }
    
    /**
     * ตั้งค่า SMS parameter
     * 
     * @param key ชื่อ parameter
     * @param value ค่าของ parameter
     */
    public static void setSMSParameter(String key, String value) {
        smsParameters.put(key, value);
    }

    // public static String getErrorPageFromXMLFile(AuthenticationContext context) {

    //     return getConfiguration(context, SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL);
    // }

    public static boolean isSMSOTPDisableForLocalUser(String username, AuthenticationContext context)
            throws SMSOTPException {

        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnablingControlledByUser = isSMSOTPEnableOrDisableByUser(context);
            if (userRealm != null) {
                if (isEnablingControlledByUser) {
                    Map<String, String> claimValues = userRealm.getUserStoreManager().getUserClaimValues(username,
                            new String[]{SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI}, null);
                    return Boolean.parseBoolean(claimValues.get(SMSOTPConstants.USER_SMSOTP_DISABLED_CLAIM_URI));
                }
            } else {
                throw new SMSOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Failed while trying to access userRealm of the user : " + username, e);
        }
        return false;
    }

     public static boolean isSMSOTPEnableOrDisableByUser(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SMSOTP_ENABLE_BY_USER));
    }

    public static boolean isEnableResendCode(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLED_RESEND));
    }

    public static boolean isRetryEnabled(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLED_RETRY));
    }

    public static String getErrorPageFromXMLFile(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.SMSOTP_AUTHENTICATION_ERROR_PAGE_URL);
    }

    public static String getLoginPageFromXMLFile(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.SMSOTP_AUTHENTICATION_ENDPOINT_URL);
    }

    public static UserRealm getUserRealm(String tenantDomain) throws AuthenticationFailedException {

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            AuthenticationFailedException afe = new AuthenticationFailedException("Cannot find the user realm for the tenant domain "
                    + tenantDomain);
            afe.initCause(e);
            throw afe;
        }
        return userRealm;
    }

    public static String getMobileNumberForUsername(String username) throws SMSOTPException,
            AuthenticationFailedException {

        UserRealm userRealm;
        String mobile;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            userRealm = getUserRealm(tenantDomain);
            if (userRealm != null) {
                mobile = userRealm.getUserStoreManager()
                        .getUserClaimValue(tenantAwareUsername, SMSOTPConstants.MOBILE_CLAIM, null);
            } else {
                throw new SMSOTPException("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Cannot find the user " + username + " to get the mobile number ", e);
        }
        return mobile;
    }

     public static boolean isSendOTPDirectlyToMobile(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE));
    }

    public static String getMobileNumberRequestPage(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.MOBILE_NUMBER_REQ_PAGE);
    }

    public static boolean sendOtpToFederatedMobile(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_SEND_OTP_TO_FEDERATED_MOBILE));
    }

    public static String getScreenUserAttribute(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.SCREEN_USER_ATTRIBUTE);
    }

    public static String getNoOfDigits(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.NO_DIGITS);
    }

    public static boolean isEnableAlphanumericToken(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLE_ALPHANUMERIC_TOKEN));
    }

    public static String getTokenLength(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.TOKEN_LENGTH);
    }

     public static String getTokenExpiryTime(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.TOKEN_EXPIRY_TIME);
    }

     public static String getDigitsOrder(AuthenticationContext context) {

        return getConfiguration(context, SMSOTPConstants.ORDER);
    }

    public static boolean isEnableMobileNoUpdate(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, SMSOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE));
    }

    public static void updateUserAttribute(String username, Map<String, String> attribute, String tenantDomain)
            throws SMSOTPException {

        try {
            // updating user attributes is independent from tenant association.not tenant association check needed here.
            UserRealm userRealm;
            // user is always in the super tenant.
            userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new SMSOTPException("The specified tenant domain " + tenantDomain + " does not exist.");
            }
            // check whether user already exists in the system.
            SMSOTPUtils.verifyUserExists(username, tenantDomain);
            UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(username, attribute, null);
        } catch (UserStoreException | AuthenticationFailedException e) {
            throw new SMSOTPException("Exception occurred while connecting to User Store: Authentication is failed. ", e);
        }
    }

    public static void verifyUserExists(String username, String tenantDomain) throws SMSOTPException,
            AuthenticationFailedException {

        UserRealm userRealm;
        boolean isUserExist = false;
        try {
            userRealm = SMSOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new SMSOTPException("Super tenant realm not loaded.");
            }
            UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
            if (userStoreManager.isExistingUser(username)) {
                isUserExist = true;
            }
        } catch (UserStoreException e) {
            throw new SMSOTPException("Error while validating the user.", e);
        }
        if (!isUserExist) {
            if (log.isDebugEnabled()) {
                log.debug("User does not exist in the User Store");
            }
            throw new SMSOTPException("User does not exist in the User Store.");
        }
    }

}
