import React, { useEffect, useState } from 'react';
export const DeviceCheck: React.FC = () => {
  const [checks, setChecks] = useState({
    webauthn: false,
    platform: false,
    secureContext: false,
    userVerification: false
  });
  useEffect(() => {
    // Check WebAuthn support
    const webauthnSupported = !!window.PublicKeyCredential;
    // Check secure context (HTTPS)
    const isSecureContext = window.isSecureContext;
    // Check platform authenticator
    const checkPlatform = async () => {
      if (webauthnSupported) {
        try {
          const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          setChecks(prev => ({ ...prev, platform: available }));
        } catch (e) {
          console.error('Platform check failed:', e);
        }
      }
    };
    setChecks({
      webauthn: webauthnSupported,
      secureContext: isSecureContext,
      platform: false,
      userVerification: webauthnSupported
    });
    checkPlatform();
  }, []);
  const allChecksPass = Object.values(checks).every(check => check);
  if (allChecksPass) return null;
  return (
    <div className="device-check-alert">
      <h3>Device Compatibility Check</h3>
      <ul className="check-list">
        <li className={checks.webauthn ? 'check-pass' : 'check-fail'}>
          {checks.webauthn ? '✓' : '✗'} WebAuthn API Support
          {!checks.webauthn && <span className="check-hint">Update your browser</span>}
        </li>
        <li className={checks.secureContext ? 'check-pass' : 'check-fail'}>
          {checks.secureContext ? '✓' : '✗'} Secure Context (HTTPS)
          {!checks.secureContext && <span className="check-hint">Use HTTPS connection</span>}
        </li>
        <li className={checks.platform ? 'check-pass' : 'check-fail'}>
          {checks.platform ? '✓' : '✗'} Platform Authenticator
          {!checks.platform && <span className="check-hint">Enable biometrics/PIN</span>}
        </li>
      </ul>
      {!allChecksPass && (
        <div className="check-help">
          <p>To use passkeys, please ensure:</p>
          <ul>
            <li>You're using a modern browser (Chrome, Safari, Edge, Firefox)</li>
            <li>Your device has biometric authentication or PIN enabled</li>
            <li>You're accessing the site via HTTPS (or localhost)</li>
          </ul>
        </div>
      )}
    </div>
  );
};