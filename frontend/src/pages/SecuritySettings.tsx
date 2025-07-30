import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { ErrorAlert } from '../components/ErrorAlert';
interface Passkey {
    id: string;
    name?: string;
    device_name?: string;
    created_at: string;
    last_used?: string;
    last_used_at?: string;
}
interface TOTPStatus {
    enabled: boolean;
    created_at?: string;
}
interface BackupCode {
    code: string;
    used: boolean;
}
interface AuthMethod {
    method: string;
    timestamp: string;
    ip_address?: string;
    user_agent?: string;
}
const SecuritySettings: React.FC = () => {
    const navigate = useNavigate();
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    // Security data
    const [passkeys, setPasskeys] = useState<Passkey[]>([]);
    const [totpStatus, setTotpStatus] = useState<TOTPStatus>({ enabled: false });
    const [backupCodes, setBackupCodes] = useState<{ codes: BackupCode[], hasUnusedCodes: boolean }>({ codes: [], hasUnusedCodes: false });
    const [recentActivity, setRecentActivity] = useState<AuthMethod[]>([]);
    const [hasPassword, setHasPassword] = useState(true); // Default to true until we check
    // Modal states
    const [showAddPasskey, setShowAddPasskey] = useState(false);
    const [showTOTPSetup, setShowTOTPSetup] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const [deviceName, setDeviceName] = useState('');
    // TOTP setup data
    const [totpSetupData, setTotpSetupData] = useState<any>(null);
    const [totpCode, setTotpCode] = useState('');
    // Password change
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [passwordStrength, setPasswordStrength] = useState<any>(null);
    useEffect(() => {
        const abortController = new AbortController();
        const loadData = async () => {
            try {
                setLoading(true);
                await Promise.all([
                    loadUserProfile(abortController.signal),
                    loadPasskeys(abortController.signal),
                    loadTOTPStatus(abortController.signal),
                    loadBackupCodes(abortController.signal),
                    loadRecentActivity(abortController.signal)
                ]);
            } catch (err: any) {
                if (err.name !== 'AbortError') {
                    setError('Failed to load security data');
                }
            } finally {
                setLoading(false);
            }
        };
        loadData();
        return () => {
            abortController.abort();
        };
    }, []);
    useEffect(() => {
        if (newPassword) {
            checkPasswordStrength(newPassword);
        } else {
            setPasswordStrength(null);
        }
    }, [newPassword]);
    // Remove unused loadSecurityData function
    const loadUserProfile = async (signal?: AbortSignal) => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/user/profile`, {
                signal,
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (!response.ok) {
                throw new Error('Failed to load user profile');
            }
            const data = await response.json();
            setHasPassword(data.has_password);
        } catch (err: any) {
            if (err.name !== 'AbortError') {
                console.error('Failed to load user profile:', err);
            }
        }
    };
    const loadPasskeys = async (signal?: AbortSignal) => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/passkeys`, {
                signal,
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setPasskeys(data);
            } else {
                console.error('Failed to load passkeys:', response.status, await response.text());
            }
        } catch (err: any) {
            if (err.name !== 'AbortError') {
                console.error('Failed to load passkeys:', err);
            }
        }
    };
    const loadTOTPStatus = async (signal?: AbortSignal) => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/totp/status`, {
                signal,
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setTotpStatus(data);
            }
        } catch (err: any) {
            if (err.name !== 'AbortError') {
                console.error('Failed to load TOTP status:', err);
            }
        }
    };
    const loadBackupCodes = async (signal?: AbortSignal) => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/backup-codes`, {
                signal,
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setBackupCodes(data);
            }
        } catch (err: any) {
            if (err.name !== 'AbortError') {
                console.error('Failed to load backup codes:', err);
            }
        }
    };
    const loadRecentActivity = async (signal?: AbortSignal) => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/recent-activity`, {
                signal,
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setRecentActivity(data);
            }
        } catch (err: any) {
            if (err.name !== 'AbortError') {
                console.error('Failed to load recent activity:', err);
            }
        }
    };
    const handleAddPasskey = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        try {
            // Start registration
            const optionsResponse = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/passkey/add/options`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({ deviceName })
            });
            if (!optionsResponse.ok) {
                throw new Error('Failed to start passkey registration');
            }
            const options = await optionsResponse.json();
            // Create credential using SimpleWebAuthn
            const credential = await startRegistration(options);
            // Complete registration
            const completeResponse = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/passkey/add/verify`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    credential,
                    deviceName: deviceName || 'Security Key'
                })
            });
            if (!completeResponse.ok) {
                throw new Error('Failed to complete passkey registration');
            }
            setSuccess('Passkey added successfully');
            setShowAddPasskey(false);
            setDeviceName('');
            await loadPasskeys();
        } catch (err: any) {
            setError(err.message || 'Failed to add passkey');
        }
    };
    const handleDeletePasskey = async (passkeyId: string) => {
        if (!confirm('Are you sure you want to remove this passkey?')) {
            return;
        }
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/passkeys/${passkeyId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (!response.ok) {
                throw new Error('Failed to delete passkey');
            }
            setSuccess('Passkey removed successfully');
            await loadPasskeys();
        } catch (err) {
            setError('Failed to remove passkey');
        }
    };
    const handleSetupTOTP = async () => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/totp/setup`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (!response.ok) throw new Error('Failed to setup TOTP');
            const setup = await response.json();
            setTotpSetupData(setup);
            setShowTOTPSetup(true);
        } catch (err) {
            setError('Failed to setup two-factor authentication');
        }
    };
    const handleVerifyTOTP = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/totp/verify-setup`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({ token: totpCode })
            });
            if (!response.ok) {
                throw new Error('Invalid verification code');
            }
            setSuccess('Two-factor authentication enabled successfully');
            setShowTOTPSetup(false);
            setTotpCode('');
            setTotpSetupData(null);
            await loadTOTPStatus();
            await loadBackupCodes();
        } catch (err) {
            setError('Invalid verification code. Please try again.');
        }
    };
    const handleDisableTOTP = async () => {
        if (!confirm('Are you sure you want to disable two-factor authentication? This will make your account less secure.')) {
            return;
        }
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/totp`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (!response.ok) {
                throw new Error('Failed to disable TOTP');
            }
            setSuccess('Two-factor authentication disabled');
            await loadTOTPStatus();
            await loadBackupCodes();
        } catch (err) {
            setError('Failed to disable two-factor authentication');
        }
    };
    const handleChangePassword = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        if (newPassword !== confirmPassword) {
            setError('New passwords do not match');
            return;
        }
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/change-password`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    currentPassword: hasPassword ? currentPassword : undefined,
                    newPassword
                })
            });
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to change password');
            }
            setSuccess(hasPassword ? 'Password changed successfully' : 'Password created successfully');
            setHasPassword(true); // Update state after creating password
            setShowChangePassword(false);
            setCurrentPassword('');
            setNewPassword('');
            setConfirmPassword('');
        } catch (err: any) {
            setError(err.message || 'Failed to change password');
        }
    };
    const checkPasswordStrength = async (password: string) => {
        try {
            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/check-password-strength`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });
            if (response.ok) {
                const result = await response.json();
                setPasswordStrength(result);
            }
        } catch (err) {
            console.error('Failed to check password strength:', err);
        }
    };
    const downloadBackupCodes = (codes: string[]) => {
        const content = `Backup Codes for Passkey Demo
Generated: ${new Date().toISOString()}
${codes.join('\n')}
Each code can only be used once.
Store these codes in a secure location.`;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `backup-codes-${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    };
    const getMethodIcon = (method: string): string => {
        const icons: Record<string, string> = {
            'passkey': '🔑',
            'password': '🔒',
            'totp': '📱',
            'backup_code': '🎫'
        };
        return icons[method] || '🔐';
    };
    const getPasswordStrengthClass = (score: number): string => {
        return ['weak', 'fair', 'good', 'strong'][score] || 'weak';
    };
    if (loading) {
        return <div className="container">Loading security settings...</div>;
    }
    return (
        <div className="container">
            <div className="auth-container" style={{ maxWidth: '800px' }}>
                <h1>Security Settings</h1>
                {error && <ErrorAlert error={error} />}
                {success && (
                    <div className="success-alert">
                        {success}
                        <button onClick={() => setSuccess(null)}>&times;</button>
                    </div>
                )}
                {/* Passkeys Section */}
                <div className="security-section">
                    <h2>Passkeys</h2>
                    <p className="section-description">
                        Passkeys provide passwordless authentication using biometrics or security keys.
                    </p>
                    {passkeys.length === 0 ? (
                        <p className="empty-state">No passkeys registered yet.</p>
                    ) : (
                        <div className="auth-method-list">
                            {passkeys.map(passkey => (
                                <div key={passkey.id} className="auth-method-item">
                                    <div className="method-info">
                                        <div className="method-name">{passkey.name || passkey.device_name || 'Unnamed Passkey'}</div>
                                        <div className="method-details">
                                            Added: {new Date(passkey.created_at).toLocaleDateString()}
                                            {(passkey.last_used || passkey.last_used_at) && ` | Last used: ${new Date(passkey.last_used || passkey.last_used_at || '').toLocaleDateString()}`}
                                        </div>
                                    </div>
                                    <button 
                                        className="delete-btn"
                                        onClick={() => handleDeletePasskey(passkey.id)}
                                    >
                                        Remove
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}
                    <button className="primary-btn" onClick={() => setShowAddPasskey(true)}>
                        Add New Passkey
                    </button>
                </div>
                {/* Two-Factor Authentication Section */}
                <div className="security-section">
                    <h2>Two-Factor Authentication (2FA)</h2>
                    <p className="section-description">
                        Add an extra layer of security with TOTP authentication.
                    </p>
                    {totpStatus.enabled ? (
                        <div className="totp-enabled">
                            <span className="status-badge enabled">Enabled</span>
                            <p>Two-factor authentication is active since {new Date(totpStatus.created_at!).toLocaleDateString()}</p>
                            <button className="secondary-btn" onClick={handleDisableTOTP}>
                                Disable 2FA
                            </button>
                        </div>
                    ) : (
                        <div className="totp-disabled">
                            <span className="status-badge disabled">Disabled</span>
                            <p>Enable two-factor authentication for enhanced security</p>
                            <button className="primary-btn" onClick={handleSetupTOTP}>
                                Enable 2FA
                            </button>
                        </div>
                    )}
                </div>
                {/* Backup Codes Section */}
                {backupCodes.codes.length > 0 && (
                    <div className="security-section">
                        <h2>Backup Codes</h2>
                        <p className="section-description">
                            Use these codes to access your account if you lose access to your other authentication methods.
                        </p>
                        <div className="backup-codes-info">
                            <p>{backupCodes.codes.filter(c => !c.used).length} of {backupCodes.codes.length} codes remaining</p>
                            {backupCodes.codes.filter(c => !c.used).length < 3 && (
                                <p className="warning">Warning: You have few backup codes left. Consider regenerating them.</p>
                            )}
                            <div className="codes-list">
                                {backupCodes.codes.map((code, index) => (
                                    <div key={index} className={`backup-code-item ${code.used ? 'used' : ''}`}>
                                        <code>{code.code}</code>
                                        {code.used && <span className="used-label">Used</span>}
                                    </div>
                                ))}
                            </div>
                            <button 
                                className="secondary-btn" 
                                onClick={async () => {
                                    if (confirm('This will generate new backup codes and invalidate the old ones. Continue?')) {
                                        try {
                                            const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/totp/backup-codes/regenerate`, {
                                                method: 'POST',
                                                headers: {
                                                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                                                }
                                            });
                                            if (response.ok) {
                                                const data = await response.json();
                                                if (data.backupCodes && data.backupCodes.length > 0) {
                                                    // Download the new codes
                                                    downloadBackupCodes(data.backupCodes);
                                                    setSuccess('New backup codes generated and downloaded');
                                                } else {
                                                    setSuccess('New backup codes generated');
                                                }
                                                await loadBackupCodes();
                                            } else {
                                                const error = await response.text();
                                                setError(`Failed to regenerate backup codes: ${error}`);
                                            }
                                        } catch (err) {
                                            setError('Failed to regenerate backup codes');
                                        }
                                    }
                                }}
                            >
                                Regenerate Backup Codes
                            </button>
                        </div>
                    </div>
                )}
                {/* Password Section */}
                <div className="security-section">
                    <h2>Password</h2>
                    <p className="section-description">Manage your account password.</p>
                    <button className="secondary-btn" onClick={() => setShowChangePassword(true)}>
                        {hasPassword ? 'Change Password' : 'Create Password'}
                    </button>
                </div>
                {/* Recent Activity */}
                <div className="security-section">
                    <h2>Recent Security Activity</h2>
                    {recentActivity.length === 0 ? (
                        <p className="empty-state">No recent activity</p>
                    ) : (
                        <div className="security-log">
                            {recentActivity.slice(0, 10).map((item, index) => (
                                <div key={index} className="activity-item">
                                    <div className="activity-method">
                                        {getMethodIcon(item.method)} {item.method}
                                    </div>
                                    <div className="activity-details">
                                        {new Date(item.timestamp).toLocaleString()}
                                        {item.ip_address && ` • ${item.ip_address}`}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
                <button className="logout-btn" onClick={() => navigate('/profile')}>
                    Back to Profile
                </button>
            </div>
            {/* Add Passkey Modal */}
            {showAddPasskey && (
                <div className="modal">
                    <div className="modal-content">
                        <span className="close" onClick={() => setShowAddPasskey(false)}>&times;</span>
                        <h2>Add New Passkey</h2>
                        <form onSubmit={handleAddPasskey}>
                            <div className="form-group">
                                <label htmlFor="deviceName">Device Name</label>
                                <input
                                    type="text"
                                    id="deviceName"
                                    value={deviceName}
                                    onChange={(e) => setDeviceName(e.target.value)}
                                    placeholder="e.g., MacBook Pro, YubiKey 5C"
                                    required
                                />
                            </div>
                            <button type="submit" className="primary-btn">Create Passkey</button>
                        </form>
                    </div>
                </div>
            )}
            {/* TOTP Setup Modal */}
            {showTOTPSetup && totpSetupData && (
                <div className="modal">
                    <div className="modal-content">
                        <span className="close" onClick={() => {
                            setShowTOTPSetup(false);
                            setTotpSetupData(null);
                            setTotpCode('');
                        }}>&times;</span>
                        <h2>Setup Two-Factor Authentication</h2>
                        <div className="totp-setup">
                            <ol>
                                <li>Install an authenticator app like Google Authenticator or Authy</li>
                                <li>Scan this QR code or enter the manual code</li>
                            </ol>
                            <div className="qr-code">
                                <img src={totpSetupData.qrCode} alt="TOTP QR Code" />
                            </div>
                            <div className="manual-entry">
                                <p>Manual entry code:</p>
                                <code className="secret-code">{totpSetupData.secret}</code>
                            </div>
                            <form onSubmit={handleVerifyTOTP}>
                                <div className="form-group">
                                    <label htmlFor="totpCode">Enter verification code from your app</label>
                                    <input
                                        type="text"
                                        id="totpCode"
                                        value={totpCode}
                                        onChange={(e) => setTotpCode(e.target.value)}
                                        pattern="[0-9]{6}"
                                        maxLength={6}
                                        placeholder="000000"
                                        required
                                    />
                                </div>
                                <button type="submit" className="primary-btn">Verify and Enable</button>
                            </form>
                            {totpSetupData.backupCodes && (
                                <div className="backup-codes-preview">
                                    <h3>Save Your Backup Codes</h3>
                                    <p>Store these codes in a safe place. You can use them to access your account if you lose your authenticator.</p>
                                    <div className="codes-grid">
                                        {totpSetupData.backupCodes.map((code: string, index: number) => (
                                            <code key={index}>{code}</code>
                                        ))}
                                    </div>
                                    <button 
                                        className="secondary-btn"
                                        onClick={() => downloadBackupCodes(totpSetupData.backupCodes)}
                                    >
                                        Download Codes
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
            {/* Change Password Modal */}
            {showChangePassword && (
                <div className="modal">
                    <div className="modal-content">
                        <span className="close" onClick={() => {
                            setShowChangePassword(false);
                            setCurrentPassword('');
                            setNewPassword('');
                            setConfirmPassword('');
                        }}>&times;</span>
                        <h2>{hasPassword ? 'Change Password' : 'Create Password'}</h2>
                        <form onSubmit={handleChangePassword}>
                            {hasPassword && (
                                <div className="form-group">
                                    <label htmlFor="currentPassword">Current Password</label>
                                    <input
                                        type="password"
                                        id="currentPassword"
                                        value={currentPassword}
                                        onChange={(e) => setCurrentPassword(e.target.value)}
                                        required
                                    />
                                </div>
                            )}
                            <div className="form-group">
                                <label htmlFor="newPassword">New Password</label>
                                <input
                                    type="password"
                                    id="newPassword"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    required
                                />
                                {passwordStrength && (
                                    <div className="password-strength">
                                        <div className={`strength-meter ${getPasswordStrengthClass(passwordStrength.score)}`}>
                                            <div 
                                                className="strength-bar" 
                                                style={{ width: `${(passwordStrength.score + 1) * 20}%` }}
                                            />
                                        </div>
                                        <p className="strength-text">
                                            {passwordStrength.feedback || `Password strength: ${getPasswordStrengthClass(passwordStrength.score)}`}
                                        </p>
                                    </div>
                                )}
                            </div>
                            <div className="form-group">
                                <label htmlFor="confirmPassword">Confirm New Password</label>
                                <input
                                    type="password"
                                    id="confirmPassword"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                />
                            </div>
                            <button type="submit" className="primary-btn">Update Password</button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};
export default SecuritySettings;