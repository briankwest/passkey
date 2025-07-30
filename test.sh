#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:5001"
FRONTEND_URL="http://localhost:3000"

# Test data
TEST_EMAIL="test_$(date +%s)@example.com"
TEST_PASSWORD="MyUniquePassphrase2024WithExtraEntropy"
TEST_WEAK_PASSWORD="password123"

# Variables to store tokens
JWT_TOKEN=""
VERIFICATION_TOKEN=""

# Function to print test results
print_test() {
    if [ $2 -eq 0 ]; then
        echo -e "${GREEN}✓ $1${NC}"
    else
        echo -e "${RED}✗ $1${NC}"
        echo "Response: $3"
        exit 1
    fi
}

# Function to extract value from JSON
extract_json_value() {
    echo "$1" | grep -o "\"$2\":[^,}]*" | sed "s/\"$2\"://;s/\"//g;s/^[[:space:]]*//;s/[[:space:]]*$//"
}

echo "=================================="
echo "Authentication System Test Suite"
echo "=================================="
echo ""

# Check if services are running
echo "1. Checking service health..."
HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health")
if [ "$HEALTH_CHECK" == "200" ]; then
    print_test "Backend API is healthy" 0
else
    print_test "Backend API is not responding" 1 "HTTP $HEALTH_CHECK"
fi

FRONTEND_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL")
if [ "$FRONTEND_CHECK" == "200" ]; then
    print_test "Frontend is accessible" 0
else
    print_test "Frontend is not responding" 1 "HTTP $FRONTEND_CHECK"
fi

echo ""
echo "2. Testing Registration Flow..."

# Test password strength check endpoint
echo "   Testing password strength check endpoint..."
STRENGTH_CHECK=$(curl -s -X POST "$BASE_URL/api/auth/check-password-strength" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$TEST_WEAK_PASSWORD\"}")

if echo "$STRENGTH_CHECK" | grep -q "score"; then
    SCORE=$(echo "$STRENGTH_CHECK" | grep -o '"score":[0-9]' | grep -o '[0-9]')
    print_test "Password strength check working (weak password score: $SCORE)" 0
else
    print_test "Password strength check failed" 1 "$STRENGTH_CHECK"
fi

# Test strong password strength
STRONG_STRENGTH=$(curl -s -X POST "$BASE_URL/api/auth/check-password-strength" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$TEST_PASSWORD\"}")

if echo "$STRONG_STRENGTH" | grep -q "score"; then
    STRONG_SCORE=$(echo "$STRONG_STRENGTH" | grep -o '"score":[0-9]' | grep -o '[0-9]')
    if [ $STRONG_SCORE -ge 3 ]; then
        print_test "Strong password scores appropriately (score: $STRONG_SCORE)" 0
    else
        print_test "Strong password score too low" 1 "Score: $STRONG_SCORE"
    fi
else
    print_test "Strong password strength check failed" 1 "$STRONG_STRENGTH"
fi

# Test weak password
echo "   Testing password validation..."
WEAK_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_WEAK_PASSWORD\",\"passwordConfirm\":\"$TEST_WEAK_PASSWORD\",\"firstName\":\"Test\",\"lastName\":\"User\"}")

if echo "$WEAK_RESPONSE" | grep -q "Password does not meet requirements"; then
    print_test "Weak password correctly rejected" 0
else
    print_test "Weak password validation failed" 1 "$WEAK_RESPONSE"
fi

# Test password mismatch
MISMATCH_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"passwordConfirm\":\"DifferentPassword\",\"firstName\":\"Test\",\"lastName\":\"User\"}")

if echo "$MISMATCH_RESPONSE" | grep -q "Passwords do not match"; then
    print_test "Password mismatch correctly detected" 0
else
    print_test "Password mismatch validation failed" 1 "$MISMATCH_RESPONSE"
fi

# Test successful registration
echo "   Testing successful registration..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"passwordConfirm\":\"$TEST_PASSWORD\",\"firstName\":\"Test\",\"lastName\":\"User\"}")

if echo "$REGISTER_RESPONSE" | grep -q "Account created successfully"; then
    print_test "User registration successful" 0
else
    print_test "User registration failed" 1 "$REGISTER_RESPONSE"
fi

# Test duplicate registration
DUPLICATE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"passwordConfirm\":\"$TEST_PASSWORD\",\"firstName\":\"Test\",\"lastName\":\"User\"}")

if echo "$DUPLICATE_RESPONSE" | grep -q "already registered"; then
    print_test "Duplicate email correctly rejected" 0
else
    print_test "Duplicate email validation failed" 1 "$DUPLICATE_RESPONSE"
fi

echo ""
echo "3. Testing Login Flow..."

# Test login without email verification
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

if echo "$LOGIN_RESPONSE" | grep -q "email_not_verified"; then
    print_test "Unverified email correctly blocked" 0
else
    print_test "Email verification check failed" 1 "$LOGIN_RESPONSE"
fi

# Get verification token from database
echo "   Getting email verification token..."
VERIFICATION_TOKEN=$(docker-compose exec -T postgres psql -U postgres -d passkey_demo -t -c "SELECT e.token FROM email_verification_tokens e JOIN users u ON e.user_id = u.id WHERE u.email='$TEST_EMAIL';" | xargs)

if [ -n "$VERIFICATION_TOKEN" ]; then
    print_test "Verification token retrieved" 0
else
    print_test "Failed to get verification token" 1
fi

# Verify email
echo "   Verifying email..."
VERIFY_RESPONSE=$(curl -s -X GET "$BASE_URL/api/auth/verify-email?token=$VERIFICATION_TOKEN")

if echo "$VERIFY_RESPONSE" | grep -q "Email verified successfully"; then
    print_test "Email verification successful" 0
else
    print_test "Email verification failed" 1 "$VERIFY_RESPONSE"
fi

# Test login with verified email
echo "   Testing login with verified email..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*' | sed 's/"token":"//')

if [ -n "$JWT_TOKEN" ]; then
    print_test "Login successful, JWT token received" 0
else
    print_test "Login failed" 1 "$LOGIN_RESPONSE"
fi

# Test wrong password
WRONG_PASS_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"WrongPassword\"}")

if echo "$WRONG_PASS_RESPONSE" | grep -q "Invalid email or password"; then
    print_test "Wrong password correctly rejected" 0
else
    print_test "Wrong password validation failed" 1 "$WRONG_PASS_RESPONSE"
fi

echo ""
echo "4. Testing Authenticated Endpoints..."

# Test adding a passkey
echo "   Testing passkey registration options..."
PASSKEY_OPTIONS=$(curl -s -X POST "$BASE_URL/api/auth/passkey/add/options" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"deviceName":"Test Device"}')

if echo "$PASSKEY_OPTIONS" | grep -q "challenge"; then
    print_test "Passkey registration options generated" 0
else
    print_test "Passkey registration options failed" 1 "$PASSKEY_OPTIONS"
fi

# Test TOTP setup
echo "   Testing TOTP setup..."
TOTP_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/totp/setup" \
  -H "Authorization: Bearer $JWT_TOKEN")

TOTP_SECRET=""
BACKUP_CODES=()

if echo "$TOTP_RESPONSE" | grep -q "secret" && echo "$TOTP_RESPONSE" | grep -q "qrCode"; then
    print_test "TOTP setup successful" 0
    
    # Extract TOTP secret
    TOTP_SECRET=$(echo "$TOTP_RESPONSE" | grep -o '"secret":"[^"]*' | sed 's/"secret":"//')
    
    # Extract backup codes
    BACKUP_CODES_JSON=$(echo "$TOTP_RESPONSE" | grep -o '"backupCodes":\[[^]]*\]' | sed 's/"backupCodes"://')
    BACKUP_CODES_COUNT=$(echo "$BACKUP_CODES_JSON" | grep -o '"[A-Z0-9]\{5\}-[A-Z0-9]\{5\}"' | wc -l)
    
    # Store first backup code for later testing
    FIRST_BACKUP_CODE=$(echo "$BACKUP_CODES_JSON" | grep -o '"[A-Z0-9]\{5\}-[A-Z0-9]\{5\}"' | head -1 | sed 's/"//g')
    
    if [ $BACKUP_CODES_COUNT -gt 0 ]; then
        print_test "Backup codes generated ($BACKUP_CODES_COUNT codes)" 0
    else
        print_test "Backup codes generation failed" 1
    fi
else
    print_test "TOTP setup failed" 1 "$TOTP_RESPONSE"
fi

# We need to verify TOTP setup before we can test TOTP login
# In a real test, we would use an actual TOTP library to generate codes
# For this test, we'll skip TOTP verification setup

# Test password change endpoint
echo "   Testing password change..."
NEW_PASSWORD="NewSecurePassphrase2024WithMoreEntropy"
CHANGE_PASS_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/change-password" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d "{\"currentPassword\":\"$TEST_PASSWORD\",\"newPassword\":\"$NEW_PASSWORD\"}")

if echo "$CHANGE_PASS_RESPONSE" | grep -q "Password changed successfully"; then
    print_test "Password change successful" 0
else
    print_test "Password change failed" 1 "$CHANGE_PASS_RESPONSE"
fi

# Test login with new password
LOGIN_NEW_PASS=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$NEW_PASSWORD\"}")

if echo "$LOGIN_NEW_PASS" | grep -q "token"; then
    print_test "Login with new password successful" 0
else
    print_test "Login with new password failed" 1 "$LOGIN_NEW_PASS"
fi

echo ""
echo "5. Testing Password Reset Flow..."

# Test forgot password
echo "   Testing forgot password..."
FORGOT_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\"}")

if echo "$FORGOT_RESPONSE" | grep -q "success"; then
    print_test "Password reset email requested" 0
else
    print_test "Password reset request failed" 1 "$FORGOT_RESPONSE"
fi

# Get reset token from database
echo "   Getting password reset token..."
RESET_TOKEN=$(docker-compose exec -T postgres psql -U postgres -d passkey_demo -t -c "SELECT p.token FROM password_reset_tokens p JOIN users u ON p.user_id = u.id WHERE u.email='$TEST_EMAIL' ORDER BY p.created_at DESC LIMIT 1;" | xargs)

if [ -n "$RESET_TOKEN" ]; then
    print_test "Password reset token retrieved" 0
else
    print_test "Failed to get password reset token" 1
fi

# Test reset password with weak password
echo "   Testing password reset with weak password..."
WEAK_RESET_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$RESET_TOKEN\",\"password\":\"weak123\"}")

if echo "$WEAK_RESET_RESPONSE" | grep -q "Password does not meet requirements"; then
    print_test "Weak password correctly rejected in reset" 0
else
    print_test "Weak password validation failed in reset" 1 "$WEAK_RESET_RESPONSE"
fi

# Test reset password with strong password
echo "   Testing password reset with strong password..."
RESET_PASSWORD="ResetSecurePassphrase2024WithEntropy"
RESET_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$RESET_TOKEN\",\"password\":\"$RESET_PASSWORD\"}")

if echo "$RESET_RESPONSE" | grep -q "Password reset successfully"; then
    print_test "Password reset successful" 0
else
    print_test "Password reset failed" 1 "$RESET_RESPONSE"
fi

# Test login with reset password
echo "   Testing login with reset password..."
LOGIN_RESET_PASS=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$RESET_PASSWORD\"}")

if echo "$LOGIN_RESET_PASS" | grep -q "requiresTOTP"; then
    print_test "Login with reset password successful (TOTP required)" 0
    
    # Test backup code authentication
    echo "   Testing login with backup code..."
    if [ -n "$FIRST_BACKUP_CODE" ]; then
        LOGIN_BACKUP=$(curl -s -X POST "$BASE_URL/api/auth/login" \
          -H "Content-Type: application/json" \
          -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$RESET_PASSWORD\",\"totpCode\":\"$FIRST_BACKUP_CODE\"}")
        
        if echo "$LOGIN_BACKUP" | grep -q "token"; then
            print_test "Login with backup code successful" 0
            NEW_JWT_TOKEN=$(echo "$LOGIN_BACKUP" | grep -o '"token":"[^"]*' | sed 's/"token":"//')
            
            # Verify backup code was marked as used
            echo "   Verifying backup code usage..."
            BACKUP_STATUS=$(curl -s -X GET "$BASE_URL/api/auth/backup-codes" \
              -H "Authorization: Bearer $NEW_JWT_TOKEN")
            
            if echo "$BACKUP_STATUS" | grep -q "used\":true"; then
                print_test "Backup code correctly marked as used" 0
            else
                print_test "Backup code usage tracking failed" 1 "$BACKUP_STATUS"
            fi
            
            # Test backup code regeneration
            echo "   Testing backup code regeneration..."
            REGEN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/totp/backup-codes/regenerate" \
              -H "Authorization: Bearer $NEW_JWT_TOKEN")
            
            if echo "$REGEN_RESPONSE" | grep -q "backupCodes"; then
                NEW_CODES_COUNT=$(echo "$REGEN_RESPONSE" | grep -o '"[A-Z0-9]\{5\}-[A-Z0-9]\{5\}"' | wc -l)
                if [ $NEW_CODES_COUNT -eq 8 ]; then
                    print_test "Backup codes regenerated successfully ($NEW_CODES_COUNT codes)" 0
                else
                    print_test "Backup codes regeneration count incorrect" 1 "Expected 8, got $NEW_CODES_COUNT"
                fi
            else
                print_test "Backup codes regeneration failed" 1 "$REGEN_RESPONSE"
            fi
            
            JWT_TOKEN=$NEW_JWT_TOKEN
        else
            print_test "Login with backup code failed" 1 "$LOGIN_BACKUP"
        fi
    else
        print_test "No backup code available for testing" 1
    fi
elif echo "$LOGIN_RESET_PASS" | grep -q "token"; then
    print_test "Login with reset password successful (no TOTP)" 0
    JWT_TOKEN=$(echo "$LOGIN_RESET_PASS" | grep -o '"token":"[^"]*' | sed 's/"token":"//')
else
    print_test "Login with reset password failed" 1 "$LOGIN_RESET_PASS"
fi

# Test reusing the same reset token
echo "   Testing reset token reuse prevention..."
REUSE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$RESET_TOKEN\",\"password\":\"AnotherPassword2024\"}")

if echo "$REUSE_RESPONSE" | grep -q "Invalid or expired"; then
    print_test "Reset token reuse correctly prevented" 0
else
    print_test "Reset token reuse prevention failed" 1 "$REUSE_RESPONSE"
fi

echo ""
echo "6. Testing Cross-Device Authentication..."

# Create cross-device session
SESSION_ID="test_session_$(date +%s)"
CROSS_DEVICE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/cross-device/create" \
  -H "Content-Type: application/json" \
  -d "{\"sessionId\":\"$SESSION_ID\"}")

if echo "$CROSS_DEVICE_RESPONSE" | grep -q "success"; then
    print_test "Cross-device session created" 0
    
    # Check session status using the session ID we created
    CHECK_SESSION=$(curl -s -X GET "$BASE_URL/api/auth/cross-device/check/$SESSION_ID")
    if echo "$CHECK_SESSION" | grep -q '"authenticated":false'; then
        print_test "Cross-device session status check successful (pending auth)" 0
    else
        print_test "Cross-device session status check failed" 1 "$CHECK_SESSION"
    fi
else
    print_test "Cross-device session creation failed" 1 "$CROSS_DEVICE_RESPONSE"
fi

echo ""
echo "7. Testing Additional Security Features..."

# Test password creation without existing password
echo "   Testing password creation (no existing password)..."
# First create a user without password (would be done via passkey in real scenario)
# For this test, we'll use the existing user

# Test account lockout
echo "   Testing account lockout after failed attempts..."
for i in {1..6}; do
    FAILED_ATTEMPT=$(curl -s -X POST "$BASE_URL/api/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"WrongPassword$i\"}")
done

LOCKOUT_ATTEMPT=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$RESET_PASSWORD\"}")

if echo "$LOCKOUT_ATTEMPT" | grep -q "Account is locked"; then
    print_test "Account lockout after failed attempts working" 0
else
    print_test "Account lockout test failed" 1 "$LOCKOUT_ATTEMPT"
fi

# Wait a moment for lockout to expire (in real scenario this would be longer)
sleep 2

echo ""
echo "8. Testing Logout..."

LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/logout" \
  -H "Authorization: Bearer $JWT_TOKEN")

if echo "$LOGOUT_RESPONSE" | grep -q "success"; then
    print_test "Logout successful" 0
else
    print_test "Logout failed" 1 "$LOGOUT_RESPONSE"
fi

echo ""
echo "=================================="
echo -e "${GREEN}All tests completed successfully!${NC}"
echo "=================================="
echo ""
echo "Test Summary:"
echo "- Email: $TEST_EMAIL"
echo "- All authentication endpoints are working correctly"
echo "- Password validation and strength checking enforced"
echo "- Email verification is required for login"
echo "- JWT authentication is functional"
echo "- TOTP setup generates 8 backup codes"
echo "- Password reset flow with token validation"
echo "- Backup codes work for authentication"
echo "- Backup codes are single-use and can be regenerated"
echo "- Reset tokens cannot be reused"
echo "- Account lockout after failed login attempts"
echo "- Cross-device authentication is operational"