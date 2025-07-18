# การปรับปรุงการตรวจสอบ OTP และข้อความแสดงผลข้อผิดพลาด

## การปรับปรุงที่ทำ

### 1. การตรวจสอบ OTP แบบ Real-time

**ไฟล์**: `smsotp.jsp`

- เพิ่มการตรวจสอบ OTP ทันทีเมื่อผู้ใช้ป้อนครบตามจำนวนหลักที่กำหนด
- เปรียบเทียบกับ OTP ที่ server ส่งมา (หากมี)
- แสดงข้อความแจ้งเตือนทันทีหาก OTP ไม่ถูกต้อง

```javascript
// Check if OTP is complete and validate immediately if we have the actual OTP
const currentOtp = getOtpValue();
if (currentOtp.length === activeOtpLength && actualOtpSent && actualOtpSent.trim() !== '') {
    const cleanActualOtp = actualOtpSent.replace(/[^0-9]/g, '');
    if (cleanActualOtp && currentOtp !== cleanActualOtp) {
        setTimeout(() => {
            const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
            showOtpError(`รหัส ${methodText} OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid ${methodText} OTP code. Please try again.`);
            console.log('DEBUG: Real-time OTP Mismatch - User:', currentOtp, 'Expected:', cleanActualOtp);
        }, 500); // Small delay to let user finish typing
    }
}
```

### 2. การแสดงข้อความแสดงผลข้อผิดพลาดที่ปรับปรุง

**การเปลี่ยนแปลง**:
- เพิ่ม inline error message container แยกจาก server error
- ปรับปรุงฟังก์ชัน `showOtpError` ให้แสดงผลทั้งใน UI และ alert
- เพิ่มการเขย่า (shake animation) สำหรับ input fields เมื่อเกิด error

```html
<!-- Client-side error message container -->
<div class="error-message" id="clientError" style="display: none;">
</div>
```

```javascript
function showOtpError(message) {
    // Hide server error and show client error
    const serverError = document.getElementById('serverError');
    const clientError = document.getElementById('clientError');
    
    if (serverError) {
        serverError.style.display = 'none';
    }
    
    if (clientError) {
        clientError.textContent = message;
        clientError.style.display = 'block';
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            clientError.style.display = 'none';
        }, 5000);
    }
    
    // Add visual error state to inputs with shake animation
    otpInputs.forEach(input => {
        if (!input.disabled) {
            input.style.borderColor = '#dc3545';
            input.style.backgroundColor = '#fff5f5';
            input.style.animation = 'shake 0.5s ease-in-out';
        }
    });
    
    // Also show alert for immediate attention
    alert(message);
    
    // Remove error styling after 3 seconds
    setTimeout(() => {
        otpInputs.forEach(input => {
            input.style.borderColor = '#e1e5e9';
            input.style.backgroundColor = '';
            input.style.animation = '';
        });
    }, 3000);
    
    // Clear inputs and focus on first
    clearOtpInputs();
}
```

### 3. การจัดการ Server Error

**การเปลี่ยนแปลง**:
- ตรวจสอบ server error เมื่อโหลดหน้า
- แสดง visual feedback หากมี error จาก server
- ล้าง input fields เพื่อให้ผู้ใช้ป้อนใหม่

```javascript
// Check if there's a server error and handle it
const serverError = document.getElementById('serverError');
if (serverError && serverError.style.display !== 'none') {
    // If there's a server error, trigger OTP error handling
    setTimeout(() => {
        const errorText = serverError.textContent || serverError.innerText;
        if (errorText.includes('Invalid') || errorText.includes('ไม่ถูกต้อง') || 
            errorText.includes('mismatch') || errorText.includes('fail')) {
            // Apply error styling to inputs
            otpInputs.forEach(input => {
                if (!input.disabled) {
                    input.style.borderColor = '#dc3545';
                    input.style.backgroundColor = '#fff5f5';
                    input.style.animation = 'shake 0.5s ease-in-out';
                }
            });
            
            // Clear inputs for retry
            clearOtpInputs();
        }
    }, 100);
}
```

### 4. การปรับปรุง Form Submission

**การเปลี่ยนแปลง**:
- ใช้ `showOtpError` แทน `alert` สำหรับความสอดคล้อง
- ตรวจสอบ OTP ก่อนส่งไปยัง server
- แสดง loading state และ timeout handling

```javascript
// Handle form submission
if (otpForm) {
    otpForm.addEventListener('submit', function(e) {
        const otpValue = getOtpValue();
        
        // Basic client-side validation only
        if (otpValue.length !== activeOtpLength) {
            e.preventDefault();
            const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
            showOtpError(`กรุณากรอกรหัส ${methodText} OTP ให้ครบ ${activeOtpLength} หลัก / Please enter a complete ${activeOtpLength}-digit ${methodText} OTP code.`);
            return;
        }

        // Validate that OTP contains only numbers
        if (!/^\d+$/.test(otpValue)) {
            e.preventDefault();
            const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
            showOtpError(`รหัส ${methodText} OTP ต้องเป็นตัวเลขเท่านั้น / ${methodText} OTP code must contain only numbers.`);
            return;
        }

        // Optional: Check OTP against actual OTP sent (if available) for immediate feedback
        if (actualOtpSent && actualOtpSent.trim() !== '') {
            const cleanActualOtp = actualOtpSent.replace(/[^0-9]/g, '');
            if (cleanActualOtp && otpValue !== cleanActualOtp) {
                e.preventDefault();
                const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                showOtpError(`รหัส ${methodText} OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid ${methodText} OTP code. Please try again.`);
                console.log('DEBUG: OTP Mismatch - User:', otpValue, 'Expected:', cleanActualOtp);
                return;
            }
        }

        // Show loading state
        verifyBtn.textContent = 'Verifying...';
        verifyBtn.disabled = true;
        
        // Add a timeout to handle potential hanging requests
        setTimeout(() => {
            if (verifyBtn.textContent === 'Verifying...') {
                verifyBtn.textContent = 'Verify Code';
                verifyBtn.disabled = false;
                showOtpError('หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง / Request timeout. Please try again.');
            }
        }, 30000); // 30 second timeout
    });
}
```

### 5. การเพิ่ม CSS Animation

**การเปลี่ยนแปลง**:
- เพิ่ม shake animation สำหรับ input fields เมื่อเกิด error

```javascript
// Add CSS animation for shake effect
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
    }
`;
document.head.appendChild(style);
```

## ประโยชน์ของการปรับปรุง

### 1. ผู้ใช้ได้รับ Feedback ทันที
- ไม่ต้องรอส่งฟอร์มไปยัง server ก่อนรู้ว่า OTP ผิด
- ประหยัดเวลาและทรัพยากร server

### 2. User Experience ที่ดีขึ้น
- แสดงข้อความแจ้งเตือนที่ชัดเจนทั้งภาษาไทยและอังกฤษ
- Visual feedback ที่ดีด้วย animation และสี
- Auto-clear inputs เพื่อให้ผู้ใช้ป้อนใหม่ได้ง่าย

### 3. ความสอดคล้อง
- ใช้ฟังก์ชัน error handling เดียวกันทั้งหมด
- รองรับทั้ง SMS และ EMAIL OTP

### 4. Debugging ที่ดีขึ้น
- Console logging สำหรับการ debug
- แสดงข้อมูล OTP ที่คาดหวัง vs ที่ป้อน

## ข้อความแจ้งเตือนที่รองรับ

1. **รหัส OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid OTP code. Please try again.**
   - เมื่อ OTP ไม่ตรงกับที่ server ส่งมา

2. **รหัส OTP ต้องเป็นตัวเลขเท่านั้น / OTP code must contain only numbers.**
   - เมื่อผู้ใช้ป้อนตัวอักษรหรือสัญลักษณ์

3. **กรุณากรอกรหัส OTP ให้ครบ X หลัก / Please enter a complete X-digit OTP code.**
   - เมื่อ OTP ไม่ครบตามจำนวนหลักที่กำหนด

4. **หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง / Request timeout. Please try again.**
   - เมื่อการส่งฟอร์ม timeout

## การทดสอบ

1. ป้อน OTP ที่ผิด → ควรแสดงข้อความ "รหัส OTP ไม่ถูกต้อง"
2. ป้อนตัวอักษร → ควรแสดงข้อความ "รหัส OTP ต้องเป็นตัวเลขเท่านั้น"
3. ป้อน OTP ไม่ครบ → ควรแสดงข้อความ "กรุณากรอกรหัส OTP ให้ครบ"
4. ป้อน OTP ถูกต้อง → ควรส่งไปยัง server เพื่อตรวจสอบ

ระบบนี้จะช่วยให้ผู้ใช้ได้รับข้อมูลป้อนกลับที่ชัดเจนและรวดเร็วยิ่งขึ้น 🚀
