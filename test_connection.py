import psycopg2

def test_connection():
    try:
        # Hardcoded connection parameters
        conn = psycopg2.connect(
            dbname="postgres",
            user="postgres.ilgcqsimufbmfbyrfgta",
            password="BonCabe15.EIGER",
            host="aws-0-ap-southeast-1.pooler.supabase.com",
            port="5432",
            sslmode="require"
        )
        
        # Create a cursor
        cursor = conn.cursor()
        
        # Execute a simple query
        cursor.execute('SELECT version();')
        
        # Fetch the result
        db_version = cursor.fetchone()
        
        # Print the result
        print(f"Connection successful! PostgreSQL version: {db_version[0]}")
        
        # Close cursor and connection
        cursor.close()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Connection error: {e}")
        return False

if __name__ == "__main__":
    test_connection()