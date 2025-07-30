import Mailgun from 'mailgun.js';
import formData from 'form-data';
import { config } from '../config';
import { query } from '../db';
interface EmailConfig {
  apiKey: string;
  domain: string;
  from: string;
  fromName: string;
}
interface EmailUser {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
}
export class EmailService {
  private mailgun: any;
  private emailConfig: EmailConfig;
  constructor() {
    this.emailConfig = {
      apiKey: config.email.mailgunApiKey,
      domain: config.email.mailgunDomain,
      from: config.email.fromEmail,
      fromName: config.email.fromName
    };
    const mailgun = new Mailgun(formData);
    this.mailgun = mailgun.client({
      username: 'api',
      key: this.emailConfig.apiKey
    });
  }
  async sendVerificationEmail(user: EmailUser, token: string): Promise<void> {
    const verificationUrl = `${config.app.url}/verify-email?token=${token}`;
    const messageData = {
      from: `${this.emailConfig.fromName} <${this.emailConfig.from}>`,
      to: user.email,
      subject: 'Verify your email address',
      html: this.getVerificationEmailTemplate(user, verificationUrl),
      text: this.getVerificationEmailText(user, verificationUrl)
    };
    try {
      const result = await this.mailgun.messages.create(this.emailConfig.domain, messageData);
      // Log email send
      await this.logEmailSend({
        userId: user.id,
        email: user.email,
        type: 'verification',
        status: 'sent',
        mailgunId: result.id
      });
    } catch (error) {
      await this.logEmailSend({
        userId: user.id,
        email: user.email,
        type: 'verification',
        status: 'failed'
      });
      throw error;
    }
  }
  async sendWelcomeEmail(user: EmailUser): Promise<void> {
    const messageData = {
      from: `${this.emailConfig.fromName} <${this.emailConfig.from}>`,
      to: user.email,
      subject: `Welcome to ${config.app.name}!`,
      html: this.getWelcomeEmailTemplate(user),
      text: this.getWelcomeEmailText(user)
    };
    try {
      const result = await this.mailgun.messages.create(this.emailConfig.domain, messageData);
      await this.logEmailSend({
        userId: user.id,
        email: user.email,
        type: 'welcome',
        status: 'sent',
        mailgunId: result.id
      });
    } catch (error) {
    }
  }
  async checkRateLimit(email: string, type: string): Promise<boolean> {
    const result = await query(
      `SELECT COUNT(*) as count FROM email_logs 
       WHERE email = $1 AND type = $2 
       AND sent_at > NOW() - INTERVAL '1 hour'`,
      [email, type]
    );
    return parseInt(result.rows[0].count) < 3; // Max 3 per hour
  }
  private async logEmailSend(data: {
    userId: string;
    email: string;
    type: string;
    status: string;
    mailgunId?: string;
  }): Promise<void> {
    await query(
      `INSERT INTO email_logs (user_id, email, type, status, mailgun_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [data.userId, data.email, data.type, data.status, data.mailgunId]
    );
  }
  async sendPasswordResetEmail(user: EmailUser, resetToken: string): Promise<void> {
    const origin = config.webauthn.origin || 'http://localhost:3000';
    const resetUrl = `${origin}/reset-password?token=${resetToken}`;
    const html = this.getPasswordResetEmailTemplate(user, resetUrl);
    const text = this.getPasswordResetEmailText(user, resetUrl);
    const messageData = {
      from: `${this.emailConfig.fromName} <${this.emailConfig.from}>`,
      to: user.email,
      subject: 'Reset Your Password',
      html,
      text
    };
    try {
      const result = await this.mailgun.messages.create(this.emailConfig.domain, messageData);
      await this.logEmailSend({
        userId: user.id,
        email: user.email,
        type: 'password_reset',
        status: 'sent',
        mailgunId: result.id
      });
    } catch (error: any) {
      await this.logEmailSend({
        userId: user.id,
        email: user.email,
        type: 'password_reset',
        status: 'failed'
      });
      throw new Error('Failed to send password reset email');
    }
  }
  private getPasswordResetEmailTemplate(user: EmailUser, resetUrl: string): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Reset Your Password</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
    .content { padding: 20px; background-color: #f4f4f4; }
    .button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Password Reset Request</h1>
    </div>
    <div class="content">
      <h2>Hello${user.firstName ? ` ${user.firstName}` : ''},</h2>
      <p>We received a request to reset your password for your Passkey Demo account.</p>
      <p>Click the button below to reset your password:</p>
      <p style="text-align: center;">
        <a href="${resetUrl}" class="button">Reset Password</a>
      </p>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all; background: #fff; padding: 10px; border: 1px solid #ddd;">
        ${resetUrl}
      </p>
      <p><strong>This link will expire in 1 hour for security reasons.</strong></p>
      <p>If you didn't request a password reset, you can safely ignore this email.</p>
    </div>
    <div class="footer">
      <p>This is an automated message from Passkey Demo.</p>
    </div>
  </div>
</body>
</html>
    `;
  }
  private getVerificationEmailTemplate(user: EmailUser, verificationUrl: string): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Verify your email</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #4F46E5; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { padding: 30px; background: #f8f9fa; border: 1px solid #e9ecef; border-top: none; }
    .button { 
      display: inline-block; 
      padding: 14px 30px; 
      background: #4F46E5; 
      color: white; 
      text-decoration: none; 
      border-radius: 5px; 
      margin: 20px 0;
      font-weight: bold;
    }
    .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    .url-box { background: #fff; padding: 10px; border: 1px solid #ddd; word-break: break-all; font-size: 14px; margin: 10px 0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${config.app.name}</h1>
    </div>
    <div class="content">
      <h2>Hello${user.firstName ? ' ' + user.firstName : ''}!</h2>
      <p>Thanks for creating an account. Please verify your email address by clicking the button below:</p>
      <div style="text-align: center;">
        <a href="${verificationUrl}" class="button">Verify Email Address</a>
      </div>
      <p>Or copy and paste this link into your browser:</p>
      <div class="url-box">${verificationUrl}</div>
      <p><strong>This link will expire in 24 hours.</strong></p>
      <p>If you didn't create an account, you can safely ignore this email.</p>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ${config.app.name}. All rights reserved.</p>
      <p>This is an automated email, please do not reply.</p>
    </div>
  </div>
</body>
</html>
    `;
  }
  private getVerificationEmailText(user: EmailUser, verificationUrl: string): string {
    return `
Hello${user.firstName ? ' ' + user.firstName : ''}!
Thanks for creating an account with ${config.app.name}.
Please verify your email address by visiting this link:
${verificationUrl}
This link will expire in 24 hours.
If you didn't create an account, you can safely ignore this email.
© ${new Date().getFullYear()} ${config.app.name}. All rights reserved.
    `;
  }
  private getWelcomeEmailTemplate(user: EmailUser): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Welcome to ${config.app.name}</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #4F46E5; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { padding: 30px; background: #f8f9fa; border: 1px solid #e9ecef; border-top: none; }
    .feature { margin: 20px 0; padding: 15px; background: white; border-radius: 5px; }
    .button { 
      display: inline-block; 
      padding: 14px 30px; 
      background: #4F46E5; 
      color: white; 
      text-decoration: none; 
      border-radius: 5px; 
      margin: 20px 0;
      font-weight: bold;
    }
    .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Welcome to ${config.app.name}!</h1>
    </div>
    <div class="content">
      <h2>Hi${user.firstName ? ' ' + user.firstName : ''}!</h2>
      <p>Your account has been successfully verified. Here's what you can do next:</p>
      <div class="feature">
        <h3>🔐 Add a Passkey</h3>
        <p>Enable passwordless login with your device's biometrics or security key.</p>
      </div>
      <div class="feature">
        <h3>🛡️ Enable Two-Factor Authentication</h3>
        <p>Add an extra layer of security with TOTP authentication.</p>
      </div>
      <div class="feature">
        <h3>👤 Complete Your Profile</h3>
        <p>Add your display name and other profile information.</p>
      </div>
      <div style="text-align: center;">
        <a href="${config.app.url}/settings/security" class="button">Go to Security Settings</a>
      </div>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ${config.app.name}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
    `;
  }
  private getWelcomeEmailText(user: EmailUser): string {
    return `
Hi${user.firstName ? ' ' + user.firstName : ''}!
Welcome to ${config.app.name}!
Your account has been successfully verified. Here's what you can do next:
• Add a Passkey - Enable passwordless login with your device's biometrics or security key
• Enable Two-Factor Authentication - Add an extra layer of security
• Complete Your Profile - Add your display name and other information
Visit your security settings: ${config.app.url}/settings/security
© ${new Date().getFullYear()} ${config.app.name}. All rights reserved.
    `;
  }
  private getPasswordResetEmailText(user: EmailUser, resetUrl: string): string {
    return `
Hello${user.firstName ? ` ${user.firstName}` : ''},
We received a request to reset your password for your Passkey Demo account.
Click this link to reset your password:
${resetUrl}
This link will expire in 1 hour for security reasons.
If you didn't request a password reset, you can safely ignore this email.
This is an automated message from Passkey Demo.
    `;
  }
}