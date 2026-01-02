# OPA Policy: Enforce MFA + Session Limits for PAM
# Zero-Trust Privileged Access Control
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.mfa_session_limits

default allow = false

# Allow if MFA verified
allow {
    input.mfa_verified == true
}

# Allow if under session limit (max 5 concurrent)
allow {
    active_sessions := count(input.active_sessions)
    active_sessions < 5
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Access denied: MFA required or session limit (5) exceeded. Current: %d", [count(input.active_sessions)])
}

# Demo test cases
test_allow_mfa_verified {
    allow with input as {"mfa_verified": true}
}

test_deny_no_mfa {
    not allow with input as {"mfa_verified": false}
}

test_allow_under_limit {
    allow with input as {"active_sessions": ["s1", "s2", "s3", "s4"]}
}

test_deny_over_limit {
    not allow with input as {"active_sessions": ["s1", "s2", "s3", "s4", "s5", "s6"]}
}
