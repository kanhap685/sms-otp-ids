package org.wso2.carbon.identity.custom.federated.authenticator.sms;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

public class OneTimePassword {

    // These are used to calculate the check-sum digits.
    // 0 1 2 3 4 5 6 7 8 9
    private static final int[] doubleDigits = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};
    private static Log log = LogFactory.getLog(OneTimePassword.class);

    public static String getRandomNumber(int size) {

        StringBuilder generatedToken = new StringBuilder();
        try {
            SecureRandom number = SecureRandom.getInstance(SMSOTPConstants.ALGORITHM_NAME);
            // Generate 20 integers 0..20
            for (int i = 0; i < size; i++) {
                generatedToken.append(number.nextInt(9));
            }
        } catch (NoSuchAlgorithmException e) {
            log.error("Unable to find the Algorithm", e);
        }

        return generatedToken.toString();
    }

    /**
     * @param num    the number to calculate the checksum for
     * @param digits number of significant places in the number
     * @return the checksum of num
     */
    public static int calcChecksum(long num, int digits) {

        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-1
     * algorithm. HMAC computes a Hashed Message Authentication Code and in this
     * case SHA1 is the hash algorithm used.
     *
     * @param keyBytes the bytes to use for the HMAC-SHA-1 key
     * @param text     the message or text to be authenticated.
     * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or HMAC-SHA-1 digest
     *                                  algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-1 key.
     */

    public static byte[] hmacShaGenerate(byte[] keyBytes, byte[] text) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hmacSha;
        try {
            hmacSha = Mac.getInstance(SMSOTPConstants.ALGORITHM_HMAC);
        } catch (NoSuchAlgorithmException nsa) {
            hmacSha = Mac.getInstance(SMSOTPConstants.ALGORITHM_HMAC_SHA);
        }
        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        hmacSha.init(macKey);
        return hmacSha.doFinal(text);
    }

    /**
     * This method generates an OTP value for the given set of parameters.
     *
     * @param secret           the shared secret
     * @param movingFactor     the counter, or other value that changes on a per use
     *                         basis.
     * @param codeDigits       the number of digits in the OTP, not including the checksum,
     *                         if any.
     * @param addChecksum      a flag that indicates if a checksum digit
     *                         should be appended to the OTP.
     * @param truncationOffset the offset into the MAC result to begin truncation. If this
     *                         value is out of the range of 0 ... 15, then dynamic truncation
     *                         will be used. Dynamic truncation is when the last 4 bits of
     *                         the last byte of the MAC are used to determine the start
     *                         offset.
     * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or HMAC-SHA-1 digest
     *                                  algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-1 key.
     */
    public static String generateOTP(byte[] secret, long movingFactor, int codeDigits, boolean addChecksum,
                                     int truncationOffset) throws NoSuchAlgorithmException, InvalidKeyException {
        // put movingFactor value into text byte array
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }
        // compute hmac hash
        byte[] hash = hmacShaGenerate(secret, text);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, codeDigits));
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * This method generates an alphanumeric OTP value for the given set of parameters.
     *
     * @param secret           the shared secret
     * @param movingFactor     the counter, or other value that changes on a per use
     *                         basis.
     * @param codeDigits       the number of digits in the OTP, not including the checksum,
     *                         if any.
     * @param addChecksum      a flag that indicates if a checksum digit
     *                         should be appended to the OTP.
     * @param truncationOffset the offset into the MAC result to begin truncation. If this
     *                         value is out of the range of 0 ... 15, then dynamic truncation
     *                         will be used. Dynamic truncation is when the last 4 bits of
     *                         the last byte of the MAC are used to determine the start
     *                         offset.
     * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or HMAC-SHA-1 digest
     *                                  algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-1 key.
     */
    public static String generateAlphaNumericOTP(byte[] secret, long movingFactor, int codeDigits, boolean addChecksum,
                                                 int truncationOffset) throws NoSuchAlgorithmException, InvalidKeyException {
        // put movingFactor value into text byte array
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }
        // compute hmac hash
        byte[] hash = hmacShaGenerate(secret, text);
        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 8))) {
            offset = truncationOffset;
        }
        int firstBinary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | ((hash[offset + 3] & 0xff));
        int secondBinary = ((hash[offset + 4] & 0x7f) << 24) | ((hash[offset + 5] & 0xff) << 16)
                | ((hash[offset + 6] & 0xff) << 8) | ((hash[offset + 7] & 0xff));
        result = Integer.toString(firstBinary, 36).concat(Integer.toString(secondBinary, 36)).toUpperCase();
        while (result.length() < digits) {
            result = "A" + result;
        }
        result = result.substring(result.length() - digits, result.length());
        return result;
    }

    /**
     * Generate the token.
     *
     * @param key                       the key
     * @param base                      the base
     * @param digits                    the number of digits
     * @param isEnableAlphanumericToken a flag that indicates the token is alphanumeric or not
     * @return the generated token
     */
    public String generateToken(String key, String base, int digits, boolean isEnableAlphanumericToken) throws AuthenticationFailedException {

        int truncOffset = 0;
        if (isEnableAlphanumericToken) {
            try {
                return generateAlphaNumericOTP(key.getBytes(), Long.parseLong(base), digits, false, truncOffset);
            } catch (NoSuchAlgorithmException e) {
                throw new AuthenticationFailedException(" Unable to find the SHA1 Algorithm to generate OTP ", e);
            } catch (InvalidKeyException e) {
                throw new AuthenticationFailedException(" Unable to find the secret key ", e);
            }
        } else {
            try {
                return generateOTP(key.getBytes(), Long.parseLong(base), digits, false, truncOffset);
            } catch (NoSuchAlgorithmException e) {
                throw new AuthenticationFailedException(" Unable to find the SHA1 Algorithm to generate OTP ", e);
            } catch (InvalidKeyException e) {
                throw new AuthenticationFailedException(" Unable to find the secret key ", e);
            }
        }
    }
}
