import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import sys
from werkzeug.security import generate_password_hash

# Database configuration
DB_NAME = "improve writting"
DB_USER = "postgres"
DB_PASSWORD = "485"
DB_HOST = "localhost"
DB_PORT = "5432"

def connect_to_postgres():
    """Connect to PostgreSQL server"""
    try:
        # Try to connect to our database first
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except psycopg2.OperationalError:
        # If our database doesn't exist, connect to default postgres database
        conn = psycopg2.connect(
            dbname='postgres',
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        return conn

def setup_database():
    """Setup database if it doesn't exist"""
    try:
        # Try connecting to our database first
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        print(f"Database '{DB_NAME}' already exists.")
        conn.close()
        return True
        
    except psycopg2.OperationalError:
        # If database doesn't exist, create it
        try:
            conn = connect_to_postgres()
            cursor = conn.cursor()
            print(f"Creating database '{DB_NAME}'...")
            cursor.execute(f'CREATE DATABASE "{DB_NAME}"')
            print("Database created successfully!")
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            print(f"Error creating database: {e}")
            return False

def setup_tables():
    """Setup tables if they don't exist"""
    try:
        from app import app, db, User
        
        with app.app_context():
            # Create tables without dropping existing ones
            db.create_all()
            print("Database tables verified/created successfully!")
            
            # Only create test user if it doesn't exist
            if not User.query.filter_by(username='test').first():
                test_user = User(
                    username='test',
                    email='test@example.com'
                )
                test_user.set_password('test123')
                db.session.add(test_user)
                db.session.commit()
                print("Test user created.")
            else:
                print("Test user already exists.")
                
    except Exception as e:
        print(f"Error setting up tables: {e}")
        return False
    return True

def main():
    """Main setup function"""
    print("=== Database Setup ===")
    
    try:
        # Setup database if needed
        if setup_database():
            # Setup tables
            if setup_tables():
                print("\nSetup completed successfully!")
            else:
                print("\nError setting up tables!")
        else:
            print("\nError setting up database!")
            
    except Exception as e:
        print(f"\nError during setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
