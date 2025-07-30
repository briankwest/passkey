import { Request } from 'express';

/**
 * Get the real client IP address from the request
 * Handles various proxy configurations and headers
 */
export function getClientIp(req: Request): string {
  // Check X-Forwarded-For header (can contain multiple IPs)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    // X-Forwarded-For can be a comma-separated list, take the first one
    const ips = Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor;
    return ips.split(',')[0].trim();
  }

  // Check X-Real-IP header (nginx)
  const xRealIp = req.headers['x-real-ip'];
  if (xRealIp) {
    return Array.isArray(xRealIp) ? xRealIp[0] : xRealIp;
  }

  // Fallback to req.ip (which should work with trust proxy)
  return req.ip || req.socket.remoteAddress || 'unknown';
}