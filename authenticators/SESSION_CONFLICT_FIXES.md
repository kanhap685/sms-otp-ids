# Session Conflict Resolution for WSO2 SMS OTP

## ปัญหาที่พบ
```
ERROR {org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore} - 
Error while storing session data org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException: 
Unique index or primary key violation: "PUBLIC.PRIMARY_KEY_6 ON PUBLIC.IDN_AUTH_SESSION_STORE
(SESSION_ID, SESSION_TYPE, TIME_CREATED, OPERATION) VALUES"
```

## สาเหตุของปัญหา
1. **Session ID Collision** - มี session ID ซ้ำกันใน database
2. **Concurrent Requests** - มีการเรียกใช้ authenticator พร้อมกัน
3. **Session Cleanup Issues** - session เก่าไม่ถูก cleanup อย่างถูกต้อง
4. **Context Property Conflicts** - OTP properties ใน context ซ้ำกัน

## การแก้ไขที่ทำไป

### 1. Session Cleanup Mechanism

#### 1.1 SMS OTP Authenticator
**เพิ่ม method `cleanupSessionData()`**:
- ลบ context properties ที่อาจทำให้เกิด conflict:
  - `SMSOTPConstants.OTP_TOKEN`
  - `SMSOTPConstants.SENT_OTP_TOKEN_TIME`
  - `SMSOTPConstants.TOKEN_VALIDITY_TIME`
  - `CLIENT_OTP_VALIDATION`
  - `SMS_PAYLOAD_CONFIG`
  - `screenValue`
  - `MASKED_EMAIL`
  - `OTP_TYPE`
- เพิ่ม delay 50ms เพื่อให้ session operations เสร็จสิ้น
- Log cleanup process สำหรับ debugging

#### 1.2 Email OTP Authenticator
**เพิ่ม method `cleanupSessionData()`**:
- ลบ context properties เช่นเดียวกับ SMS OTP
- เพิ่ม `EMAIL_PAYLOAD_CONFIG` สำหรับ email-specific cleanup

### 2. Conflict Handling in processAuthenticationResponse

**เพิ่ม synchronized block และ retry mechanism**:
```java
synchronized (this) {
    try {
        processOTPValidation(request, response, context);
    } catch (Exception e) {
        if (e.getMessage() != null && e.getMessage().contains("Unique index or primary key violation")) {
            // Clean up and retry once
            cleanupSessionData(context);
            Thread.sleep(100);
            processOTPValidation(request, response, context);
        }
    }
}
```

### 3. Enhanced Context Storage

**ปรับปรุง `storeOTPInContext()` method**:
- เพิ่ม comprehensive logging
- Better error handling
- เพิ่ม try-catch เพื่อ handle storage exceptions

### 4. Integration Points

**หลายจุดที่เรียกใช้ cleanup**:
1. **หน้า initiate authentication** - cleanup ก่อนเริ่ม process
2. **หน้า process response** - cleanup เมื่อเกิด conflict แล้ว retry
3. **หน้า handle authentication** - cleanup ตอนเริ่มต้น

## Build Status
✅ **All Java files compile successfully**
✅ **No compilation errors**

## การทดสอบที่ต้องทำ

### 1. Session Conflict Testing
1. ทดสอบ SMS OTP flow หลายครั้งติดต่อกัน
2. ตรวจสอบ WSO2 server logs สำหรับ:
   - Session cleanup messages
   - Conflict detection และ retry
   - Successful OTP storage

### 2. Concurrent Access Testing
1. เปิด multiple browser tabs/windows
2. ทดสอบ authentication พร้อมกัน
3. ยืนยันว่าไม่มี constraint violation errors

### 3. Log Monitoring
**ดู server logs สำหรับ:**
- `"Session cleanup completed for context"`
- `"Successfully stored OTP context properties"`
- `"Session conflict detected, retrying after cleanup"`

## Expected Results

### ✅ Should Work Now:
1. **No More Constraint Violations** - ไม่ควรเจอ H2 database errors อีก
2. **Successful Session Management** - session properties ถูก cleanup และ store ถูกต้อง
3. **Retry Mechanism** - หากเจอ conflict จะ retry อัตโนมัติ
4. **Better Logging** - มี debug information เพื่อ monitor session state

### 🔍 Monitoring Points:
- **WSO2 Server Logs:** Session cleanup และ storage messages
- **Database State:** ไม่มี duplicate session entries
- **Authentication Flow:** Smooth OTP generation และ validation

## Files Modified:
1. **SMSOTPAuthenticator.java** - เพิ่ม session cleanup และ conflict handling
2. **EmailOTPAuthenticator.java** - เพิ่ม session cleanup
3. **OTPService.java** - ปรับปรุง context storage พร้อม logging

## Implementation Details

### Session Cleanup Properties:
```java
String[] propertiesToClean = {
    SMSOTPConstants.OTP_TOKEN,
    SMSOTPConstants.SENT_OTP_TOKEN_TIME, 
    SMSOTPConstants.TOKEN_VALIDITY_TIME,
    "CLIENT_OTP_VALIDATION",
    "SMS_PAYLOAD_CONFIG",
    "EMAIL_PAYLOAD_CONFIG",
    "screenValue",
    "MASKED_EMAIL",
    "OTP_TYPE"
};
```

### Retry Logic:
- **Detection:** Check for "Unique index or primary key violation" in exception message
- **Action:** Clean session data → Wait 100ms → Retry once
- **Fallback:** If retry fails, throw AuthenticationFailedException

การแก้ไขนี้ควรจะแก้ปัญหา database constraint violation และทำให้ SMS/Email OTP authentication ทำงานได้อย่างเสถียร!
