import fs from 'fs';
import pkg from 'pg';
const { Client } = pkg;

// Database connection configuration
const db = new Client({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'Admin@123456',
  port: 5432,
});

async function insertData() {
  try {
    // Connect to PostgreSQL
    await db.connect();

  // Read JSON file
  // const fileContent = fs.readFileSync('scan-results.json', 'utf-8');
  // const vulnerabilityRecords = fileContent.split('\n')
  //   .filter(line => line.trim() !== '')
  //   .map(line => {
  //     try {
  //       return JSON.parse(line);
  //     } catch (err) {
  //       console.error('Error parsing line:', line);
  //       console.error('Parse error:', err);
  //       return null;
  //     }
  //   })
  //   .filter(record => record !== null);

  // console.log("Data read from file!");
  // console.log("Number of valid records:", vulnerabilityRecords.length);
  // Create test records
    const vulnerabilityRecords = [
      {
        vulnerability_id: 'CVE-2023-1234',
        package: 'org.apache.logging.log4j:log4j-core',
        affected_versions: '2.14.1',
        severity: 'HIGH',
        score: 8.5,
        unaffected_versions: '2.15.0',
        description: 'Remote code execution vulnerability in Log4j',
        recommendation: 'Upgrade to version 2.15.0 or later',
        insights: 'Critical vulnerability affecting logging functionality'
      },
      {
        vulnerability_id: 'CVE-2023-5678',
        package: 'com.fasterxml.jackson.core:jackson-databind',
        affected_versions: '2.13.0',
        severity: 'MEDIUM',
        score: 6.5,
        unaffected_versions: '2.13.1',
        description: 'Deserialization vulnerability in Jackson',
        recommendation: 'Update to latest version',
        insights: 'Affects data processing components'
      },
      {
        vulnerability_id: 'CVE-2023-9012',
        package: 'org.springframework:spring-core',
        affected_versions: '5.3.20',
        severity: 'LOW',
        score: 3.2,
        unaffected_versions: '5.3.21',
        description: 'Information disclosure in Spring Framework',
        recommendation: 'Patch system to latest version',
        insights: 'Minor security impact'
      },
      {
        vulnerability_id: 'CVE-2023-3456',
        package: 'com.google.guava:guava',
        affected_versions: '30.1.1',
        severity: 'CRITICAL',
        score: 9.1,
        unaffected_versions: '31.0.0',
        description: 'Buffer overflow in Guava library',
        recommendation: 'Immediate upgrade required',
        insights: 'Severe security risk'
      },
      {
        vulnerability_id: 'CVE-2023-7890',
        package: 'org.postgresql:postgresql',
        affected_versions: '42.2.24',
        severity: 'HIGH',
        score: 7.8,
        unaffected_versions: '42.2.25',
        description: 'SQL injection vulnerability',
        recommendation: 'Update database driver',
        insights: 'Affects database operations'
      },
      {
        vulnerability_id: 'CVE-2023-2468',
        package: 'org.apache.commons:commons-lang3',
        affected_versions: '3.11',
        severity: 'MEDIUM',
        score: 5.5,
        unaffected_versions: '3.12',
        description: 'Path traversal vulnerability',
        recommendation: 'Upgrade Commons Lang',
        insights: 'Impacts file operations'
      },
      {
        vulnerability_id: 'CVE-2023-1357',
        package: 'ch.qos.logback:logback-classic',
        affected_versions: '1.2.5',
        severity: 'LOW',
        score: 2.8,
        unaffected_versions: '1.2.6',
        description: 'Logging configuration exposure',
        recommendation: 'Update logging framework',
        insights: 'Minor configuration issue'
      },
      {
        vulnerability_id: 'CVE-2023-8901',
        package: 'org.yaml:snakeyaml',
        affected_versions: '1.28',
        severity: 'HIGH',
        score: 8.2,
        unaffected_versions: '1.29',
        description: 'YAML parsing vulnerability',
        recommendation: 'Upgrade SnakeYAML dependency',
        insights: 'Affects configuration parsing'
      },
      {
        vulnerability_id: 'CVE-2023-4567',
        package: 'com.h2database:h2',
        affected_versions: '1.4.200',
        severity: 'CRITICAL',
        score: 9.8,
        unaffected_versions: '2.0.0',
        description: 'Remote code execution in H2',
        recommendation: 'Major version upgrade required',
        insights: 'Critical database vulnerability'
      }
    ];
    // Insert each JSON record into the table
    for (const record of vulnerabilityRecords) {
      await db.query(`
        INSERT INTO vulnerabilities_test (
        id, 
        package_url,
        affected_version,
        severity,
        cvss_score, 
        fix_version, 
        short_description,
        recommendation,
        insights
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO NOTHING
        RETURNING id;
      `, [
          record.vulnerability_id,
          record.package,
          record.affected_versions,
          record.severity,
          record.score,
          record.unaffected_versions,
          record.description,
          record.recommendation,
          record.insights
      ]);
    }

    console.log("Data insertion complete!");
  } catch (err) {
    console.error("Error inserting data", err);
  } finally {
    // Close the connection
    await db.end();
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

