"""
Database Migration Script for VAPT Engine v2.1.0
Ensures all required columns (scan_mode, ai_mode, etc.) exist in the SQLite database.
"""
import sqlite3
import os

db_path = "vapt.db"

def sync():
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found. It will be created by the app on next startup.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get current columns
    cursor.execute("PRAGMA table_info(scans)")
    columns = [col[1] for col in cursor.fetchall()]
    print(f"Current columns in 'scans': {columns}")

    # Columns that should exist
    required_columns = {
        "scan_mode": "TEXT DEFAULT 'offline'",
        "ai_mode": "TEXT DEFAULT 'offline'",
        "scan_type": "TEXT DEFAULT 'Auto'"
    }

    modified = False
    for col, definition in required_columns.items():
        if col not in columns:
            print(f"Adding missing column: {col}...")
            try:
                cursor.execute(f"ALTER TABLE scans ADD COLUMN {col} {definition}")
                modified = True
            except Exception as e:
                print(f"Error adding {col}: {e}")

    if modified:
        conn.commit()
        print("Database schema updated successfully.")
    else:
        print("Database schema is already up to date.")

    conn.close()

if __name__ == "__main__":
    sync()
