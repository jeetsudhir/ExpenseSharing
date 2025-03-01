import os
import psycopg2

# Get the database URL from environment variable
db_url = os.environ.get('DATABASE_URL')

# Connect to the database
conn = psycopg2.connect(db_url)
conn.autocommit = True
cursor = conn.cursor()

# Execute the ALTER TABLE statement
try:
    cursor.execute('ALTER TABLE "user" ALTER COLUMN password TYPE VARCHAR(255);')
    print("Successfully altered password column length")
except Exception as e:
    print(f"Error altering table: {e}")

# Close the connection
cursor.close()
conn.close()