import fs from 'fs';
import pkg from 'pg';
const { Client } = pkg;

// Database connection configuration
const client = new Client({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'Admin@123456',
  port: 5432,
});

async function insertData() {
  try {
    // Connect to PostgreSQL
    await client.connect();

    // Read JSON file
    const fileContent = fs.readFileSync('json.json', 'utf-8');
    const data = fileContent.split('\n').filter(line => line.trim() !== '').map(line => JSON.parse(line));
    // Beautify the data of "short_description"
    data.forEach(record => {
      if (record.short_description) {
        record.short_description = record.short_description.replace(/[\n\t]/g, '');
      }
    });
    
    console.log("Data read from file!");
    console.log(data);

    // Insert each JSON record into the table
    for (const record of data) {
      await client.query(`
        INSERT INTO vulnerabilities (id, package, purl, ptype, pusage, version, fix_version, severity, cvss_score, short_description)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
      `, [
        record.id,
        record.package,
        record.purl,
        record.package_type,
        record.package_usage,
        record.version,
        record.fix_version,
        record.severity,
        parseFloat(record.cvss_score),
        record.short_description
      ]);
    }

    console.log("Data insertion complete!");
  } catch (err) {
    console.error("Error inserting data", err);
  } finally {
    // Close the connection
    await client.end();
  }
}

insertData();


// database table
// id
// bom-ref
// score
// severity
// description
// fix_version
// recommendation
// insights

