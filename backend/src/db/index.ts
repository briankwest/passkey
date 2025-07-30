import { Pool } from 'pg';
import { config } from '../config';
export const pool = new Pool({
  connectionString: config.database.url
});
export const query = (text: string, params?: any[]) => pool.query(text, params);