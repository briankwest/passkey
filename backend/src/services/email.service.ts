import Mailgun from 'mailgun.js';
import formData from 'form-data';
import { config } from '../config';
import { query } from '../db';
import * as fs from 'fs/promises';
import * as path from 'path';
const Mustache = require('mustache');

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
  private templateCache: Map<string, { html: string; text: string }> = new Map();

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

  private async loadTemplate(templateName: string, type: 'html' | 'txt'): Promise<string> {
    const cacheKey = `${templateName}-${type}`;
    
    // Check cache first
    const cached = this.templateCache.get(templateName);
    if (cached) {
      return type === 'html' ? cached.html : cached.text;
    }

    // Load both HTML and text templates
    // In development, templates are in src/templates, in production they'll be copied to dist/../src/templates
    const basePath = process.env.NODE_ENV === 'production' 
      ? path.join(__dirname, '..', '..', '..', 'src', 'templates', 'email')
      : path.join(__dirname, '..', 'templates', 'email');
    const htmlPath = path.join(basePath, `${templateName}.html`);
    const txtPath = path.join(basePath, `${templateName}.txt`);

    try {
      const [htmlContent, txtContent] = await Promise.all([
        fs.readFile(htmlPath, 'utf-8'),
        fs.readFile(txtPath, 'utf-8')
      ]);

      // Cache the templates
      this.templateCache.set(templateName, { html: htmlContent, text: txtContent });

      return type === 'html' ? htmlContent : txtContent;
    } catch (error) {
      throw new Error(`Failed to load email template: ${templateName}.${type}`);
    }
  }

  private async renderTemplate(templateName: string, type: 'html' | 'txt', data: Record<string, any>): Promise<string> {
    const template = await this.loadTemplate(templateName, type);
    return Mustache.render(template, data);
  }

  async sendVerificationEmail(user: EmailUser, token: string): Promise<void> {
    const verificationUrl = `${config.app.url}/verify-email?token=${token}`;
    
    const templateData = {
      firstName: user.firstName,
      appName: config.app.name,
      verificationUrl,
      year: new Date().getFullYear()
    };

    const messageData = {
      from: `${this.emailConfig.fromName} <${this.emailConfig.from}>`,
      to: user.email,
      subject: 'Verify your email address',
      html: await this.renderTemplate('verification', 'html', templateData),
      text: await this.renderTemplate('verification', 'txt', templateData)
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
    const templateData = {
      firstName: user.firstName,
      appName: config.app.name,
      securitySettingsUrl: `${config.app.url}/settings/security`,
      year: new Date().getFullYear()
    };

    const messageData = {
      from: `${this.emailConfig.fromName} <${this.emailConfig.from}>`,
      to: user.email,
      subject: `Welcome to ${config.app.name}!`,
      html: await this.renderTemplate('welcome', 'html', templateData),
      text: await this.renderTemplate('welcome', 'txt', templateData)
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
      // Silently fail for welcome emails
    }
  }

  async sendPasswordResetEmail(user: EmailUser, resetToken: string): Promise<void> {
    const origin = config.webauthn.origin || 'http://localhost:3000';
    const resetUrl = `${origin}/reset-password?token=${resetToken}`;
    
    const templateData = {
      firstName: user.firstName,
      appName: config.app.name,
      resetUrl,
      year: new Date().getFullYear()
    };

    const messageData = {
      from: `${this.emailConfig.fromName} <${this.emailConfig.from}>`,
      to: user.email,
      subject: 'Reset Your Password',
      html: await this.renderTemplate('password-reset', 'html', templateData),
      text: await this.renderTemplate('password-reset', 'txt', templateData)
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
}