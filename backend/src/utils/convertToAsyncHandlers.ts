import * as fs from 'fs';
import * as path from 'path';

// Script to help convert controller methods to use asyncHandler
// This shows the pattern but would need to be run manually for each controller

const convertController = (filePath: string) => {
  let content = fs.readFileSync(filePath, 'utf8');
  
  // Convert async methods to use asyncHandler
  content = content.replace(
    /async\s+(\w+)\s*\(\s*req:\s*Request,\s*res:\s*Response\s*\)\s*{\s*try\s*{/g,
    '$1 = asyncHandler(async (req: Request, res: Response) => {'
  );
  
  // Remove catch blocks that just return 500 errors
  content = content.replace(
    /}\s*catch\s*\([^)]+\)\s*{\s*res\.status\(500\)\.json\(\s*{\s*error:\s*'[^']+'\s*}\s*\);\s*}\s*}/g,
    '})'
  );
  
  // Convert return res.status(400).json({ error: '...' }) to throw ValidationError
  content = content.replace(
    /return\s+res\.status\(400\)\.json\(\s*{\s*error:\s*'([^']+)'\s*}\s*\);/g,
    "throw new ValidationError('$1');"
  );
  
  // Convert return res.status(401).json({ error: '...' }) to throw AuthError
  content = content.replace(
    /return\s+res\.status\(401\)\.json\(\s*{\s*error:\s*'([^']+)'\s*}\s*\);/g,
    "throw new AuthError('$1');"
  );
  
  // Convert return res.status(404).json({ error: '...' }) to throw NotFoundError
  content = content.replace(
    /return\s+res\.status\(404\)\.json\(\s*{\s*error:\s*'([^']+)'\s*}\s*\);/g,
    "throw new NotFoundError('$1');"
  );
  
  return content;
};

// Example usage (commented out to prevent accidental execution)
// const authControllerPath = path.join(__dirname, '../../controllers/auth.controller.ts');
// const converted = convertController(authControllerPath);
// console.log(converted);

export { convertController };