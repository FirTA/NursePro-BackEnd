# Place this file in your_app/management/commands/test_db.py

from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError

class Command(BaseCommand):
    help = 'Tests the database connection to Supabase'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Testing database connection...'))
        
        try:
            db_conn = connections['default']
            c = db_conn.cursor()
            c.execute('SELECT version();')
            db_version = c.fetchone()
            self.stdout.write(self.style.SUCCESS(f'Connection successful! PostgreSQL version: {db_version[0]}'))
            
            # Check table privileges to ensure you can create tables
            c.execute("""
                SELECT 
                    tablename 
                FROM 
                    pg_catalog.pg_tables 
                WHERE 
                    schemaname != 'pg_catalog' 
                    AND schemaname != 'information_schema'
                LIMIT 5;
            """)
            tables = c.fetchall()
            if tables:
                self.stdout.write(self.style.SUCCESS('Found existing tables:'))
                for table in tables:
                    self.stdout.write(f"- {table[0]}")
            else:
                self.stdout.write(self.style.WARNING('No tables found. You might need to run migrations.'))
            
        except OperationalError as e:
            self.stdout.write(self.style.ERROR(f'Unable to connect to the database: {e}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {e}'))