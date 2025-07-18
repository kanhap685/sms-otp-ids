# Dynamic OTP Length Implementation

## ปัญหาที่พบ
- OTPService ใช้ hard-coded 4-digit OTP แทนที่จะดึงจาก `otpDigit` ใน payload configuration
- Comment: `"Always use 4-digit OTP as per requirement"` แต่ต้องการใช้ค่าจาก `"otpDigit":"6"`

## การแก้ไขที่ทำไป

### 1. OTPService.java - Dynamic OTP Length

#### 1.1 Updated generateOTP() Method
**เปลี่ยนจาก:**
```java
// Always use 4-digit OTP as per requirement
int tokenLength = 4;
```

**เป็น:**
```java
// Get OTP length from configuration, default to 4 if not specified
int tokenLength = getOTPLengthFromContext(context);
```

#### 1.2 Added getOTPLengthFromContext() Method
**ลำดับการหา OTP length:**
1. **SMS Payload** - `SMS_PAYLOAD_CONFIG` context property
2. **Email Payload** - `EMAIL_PAYLOAD_CONFIG` context property  
3. **Authenticator Properties** - `otpDigit` property
4. **Default** - 4 digits หากไม่พบ

#### 1.3 Added parseOTPLengthFromPayload() Method
**รองรับ JSON patterns:**
- `"otpDigit":"6"` (quoted value)
- `"otpDigit":6` (unquoted value)
- Uses regex parsing for robust extraction

**Enhanced Logging:**
- Log payload parsing process
- Log OTP length source (payload/properties/default)
- Debug information for troubleshooting

### 2. SMS OTP Authenticator - Set Payload Before Generation

#### 2.1 Reordered sendSMSOTP() Process
**เปลี่ยน process order:**
1. ✅ **Create SMS Configuration** → **Set SMS Payload in Context** → **Generate OTP**
2. ❌ ~~Generate OTP → Create SMS Configuration~~

**Code:**
```java
// Store SMS payload in context so OTP service can read the otpDigit configuration
if (StringUtils.isNotEmpty(smsConfig.getPayload())) {
    context.setProperty("SMS_PAYLOAD_CONFIG", smsConfig.getPayload());
    log.info("Set SMS payload in context for OTP generation: " + smsConfig.getPayload());
}

// Generate OTP (now it can read otpDigit from the payload)
String otpCode = otpService.generateOTP(context);
```

### 3. Email OTP Authenticator - Set Payload Before Generation

#### 3.1 Reordered sendEmailOTP() Process
**เช่นเดียวกับ SMS:**
1. Create Email Configuration → Set Email Payload in Context → Generate OTP

**Code:**
```java
// Store Email payload in context so OTP service can read the otpDigit configuration
if (emailConfig.getPayload() != null && !emailConfig.getPayload().trim().isEmpty()) {
    context.setProperty("EMAIL_PAYLOAD_CONFIG", emailConfig.getPayload());
}

// Generate OTP (now it can read otpDigit from the payload)
String otpCode = otpService.generateOTP(context);
```

### 4. Logging & Debugging

**Enhanced Logging:**
- OTP length detection source
- Payload parsing results
- Final OTP configuration used
- Error handling for invalid configurations

## Configuration Priority

### OTP Length Detection Priority:
1. **SMS_PAYLOAD_CONFIG** (highest priority)
2. **EMAIL_PAYLOAD_CONFIG** 
3. **Authenticator Properties** (`otpDigit`)
4. **Default (4 digits)** (lowest priority)

### Supported Payload Formats:
```json
// Format 1: Quoted value
{"otpDigit":"6","lifeTimeoutMins":"5"}

// Format 2: Unquoted value  
{"otpDigit":6,"lifeTimeoutMins":5}

// Format 3: Nested structure
{"sendOneTimePW":{"otpDigit":"6","lifeTimeoutMins":"5"}}
```

## Build Status
✅ **All Java files compile successfully**
✅ **No compilation errors**
✅ **Enhanced logging implemented**

## Expected Results

### ✅ Should Work Now:
1. **Dynamic OTP Length** - จะใช้ค่าจาก `"otpDigit":"6"` แทน hard-coded 4
2. **Backward Compatibility** - หากไม่มี configuration จะใช้ default 4 digits
3. **Both SMS & Email** - ทั้งสองรองรับ dynamic length
4. **Robust Parsing** - หลาย JSON format patterns
5. **Comprehensive Logging** - ดู debug info ได้ใน server logs

### 🔍 Testing Points:
1. **Server Logs** ต้องเห็น:
   - `"OTP length from SMS payload: 6"`
   - `"Set SMS payload in context for OTP generation"`
   - `"Successfully generated OTP token with length: 6"`

2. **UI Frontend** ต้องเห็น:
   - OTP input fields แสดง 6 ตำแหน่งแทน 4
   - Browser console logs แสดง `activeOtpLength: 6`

3. **OTP Generation** ต้องได้:
   - 6-digit OTP code (เช่น `123456` แทน `1234`)

## Files Modified:
1. **OTPService.java** - Dynamic OTP length generation
2. **SMSOTPAuthenticator.java** - Set payload before OTP generation
3. **EmailOTPAuthenticator.java** - Set payload before OTP generation

## Implementation Flow:

```
Configuration → Context → OTP Service → Generation
     ↓             ↓          ↓           ↓
SMS Payload → SMS_PAYLOAD → parseOTP → 6-digit OTP
   CONFIG      _CONFIG      Length
```

ตอนนี้ OTP จะใช้ความยาวจาก `"otpDigit":"6"` ใน payload แทน hard-coded 4 digits แล้ว! 🎉
