import fs from 'fs';
import path from 'path';
import { pool } from './index';

async function initializeDatabase() {
  try {
    // Drop all existing tables and recreate from scratch
    // This is only for development - in production we would use proper migrations
    console.log('Dropping existing tables...');
    
    const dropTablesQuery = `
      DROP TABLE IF EXISTS email_logs CASCADE;
      DROP TABLE IF EXISTS auth_methods CASCADE;
      DROP TABLE IF EXISTS password_history CASCADE;
      DROP TABLE IF EXISTS email_verification_tokens CASCADE;
      DROP TABLE IF EXISTS backup_codes CASCADE;
      DROP TABLE IF EXISTS user_totp CASCADE;
      DROP TABLE IF EXISTS passkeys CASCADE;
      DROP TABLE IF EXISTS users CASCADE;
      DROP FUNCTION IF EXISTS update_updated_at_column CASCADE;
    `;
    
    await pool.query(dropTablesQuery);
    
    console.log('Creating database schema...');
    const schemaPath = path.join(__dirname, '../../database/schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    await pool.query(schema);
    console.log('Database initialization completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
}

initializeDatabase();