import fs from 'fs';
import path from 'path';
import { pool } from './index';

async function migrate() {
  try {
    const schemaPath = path.join(__dirname, '../../../database/schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    await pool.query(schema);
    console.log('Database migration completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

migrate();