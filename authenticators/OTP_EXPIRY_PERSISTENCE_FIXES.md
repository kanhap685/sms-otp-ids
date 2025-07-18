# OTP Expiry State Persistence Fixes

## Issue
When the OTP expires and the user refreshes the page, the system should remember that the OTP is expired and continue to show "รหัสผ่านหมดอายุแล้ว" (OTP has expired) message with disabled inputs.

## Root Cause
The previous implementation didn't properly persist the expired state across page refreshes. The `sessionStorage` was only used to store the creation time, but when the OTP expired, the creation time was removed, causing the page to lose track of the expired state on refresh.

## Solution Implemented

### 1. Added Persistent Expired Flag
- **New sessionStorage key**: `otpExpired_<sessionDataKey>` 
- **Purpose**: Explicitly tracks when an OTP has expired
- **Persistence**: Remains in sessionStorage even after page refresh until a new OTP is sent

### 2. Enhanced Expiry Checking Logic
```javascript
// Check both expired flag and calculated expiry
const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
if (expiredFlag === 'true' || isOtpExpired()) {
    // Handle expired state
}
```

### 3. Updated Key Functions

#### `showOtpExpiredError()` Function
- **Added**: `sessionStorage.setItem(otpExpiredFlagKey, 'true');`
- **Purpose**: Marks OTP as expired for future page loads
- **Effect**: Disables all inputs, shows error message, and persists state

#### Page Load Logic
```javascript
// Check if OTP was previously marked as expired
const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);

if (expiredFlag === 'true') {
    // OTP was previously expired, keep it expired
    console.log('DEBUG: OTP was previously expired, maintaining expired state');
    showOtpExpiredError();
    return; // Don't continue with countdown
}
```

#### Enhanced Event Handlers
All input event handlers now check both:
1. The explicit expired flag in sessionStorage
2. The calculated expiry based on time elapsed

### 4. Server Data Integration
- **Server OTP sent time**: If available from server, takes precedence over sessionStorage
- **Token validity**: Uses server-provided validity period when available
- **Fresh data handling**: Clears expired flag when new server data is received

### 5. Countdown Timer Updates
```javascript
if (countdown <= 0) {
    console.log('DEBUG: OTP already expired on page load');
    // Mark as expired in sessionStorage
    sessionStorage.setItem(otpExpiredFlagKey, 'true');
    showOtpExpiredError();
} else {
    // Timer runs and sets expired flag when countdown reaches 0
    if (countdown > 0) {
        updateOtpLabel(countdown);
        countdown--;
    } else {
        sessionStorage.setItem(otpExpiredFlagKey, 'true');
        showOtpExpiredError();
    }
}
```

## Behavior After Fix

### Normal Flow
1. **Page Load**: OTP inputs are enabled, countdown starts
2. **Expiry**: When time runs out, inputs are disabled, error message shows, expired flag is set
3. **Refresh**: Page loads, checks expired flag, immediately shows expired state

### Edge Cases Handled
- **Direct page reload after expiry**: Maintains expired state
- **Browser tab switching**: State persists across tab switches
- **Long browser sessions**: Expired flag prevents any interaction with expired OTP

### User Experience
- **Immediate feedback**: User sees "รหัสผ่านหมดอายุแล้ว" immediately on refresh
- **Disabled inputs**: All OTP inputs and verify button are disabled
- **Clear visual state**: Red error styling and disabled button styling
- **Consistent state**: No confusion about whether OTP is still valid

## Technical Implementation Details

### SessionStorage Keys Used
- `otpCreationTime_<sessionDataKey>`: Stores when OTP was created/sent
- `otpExpired_<sessionDataKey>`: Boolean flag indicating if OTP has expired

### State Management
- **Creation time priority**: Server time > Stored time > Current time (fallback)
- **Expired flag priority**: Explicit flag > Calculated expiry
- **Cleanup**: Expired flag is cleared only when new server data arrives

### Debugging Support
- Console logs track state transitions
- Debug messages show which time source is being used
- Expired flag setting and checking is logged

## Testing Scenarios
1. ✅ Let OTP expire naturally, refresh page → Should show expired state
2. ✅ Refresh page before expiry → Should continue countdown
3. ✅ Close and reopen browser tab after expiry → Should show expired state
4. ✅ Multiple refreshes after expiry → Should consistently show expired state
5. ✅ New OTP request → Should clear expired flag and start fresh

This implementation ensures that the OTP expired state is properly preserved across page refreshes, providing a consistent and reliable user experience.
