import { Request, Response, NextFunction } from 'express';
import { asyncHandler, ValidationError, NotFoundError } from '../middleware/errorHandler';

/**
 * Base controller class that provides common functionality
 * and ensures all methods use proper error handling
 */
export abstract class BaseController {
  /**
   * Wraps an async method with error handling
   * This can be used as a decorator or called directly
   */
  protected handleAsync(fn: Function) {
    return asyncHandler(fn.bind(this));
  }

  /**
   * Helper method to validate required fields
   * Throws ValidationError if any required fields are missing
   */
  protected validateRequired(data: any, fields: string[]): void {
    const missing = fields.filter(field => !data[field]);
    if (missing.length > 0) {
      throw new ValidationError(`Missing required fields: ${missing.join(', ')}`);
    }
  }
}

// Example usage:
// export class UserController extends BaseController {
//   getProfile = this.handleAsync(async (req: Request, res: Response) => {
//     const userId = (req as any).user.userId;
//     const user = await userService.getUserById(userId);
//     if (!user) {
//       throw new NotFoundError('User not found');
//     }
//     res.json(user);
//   });
// }