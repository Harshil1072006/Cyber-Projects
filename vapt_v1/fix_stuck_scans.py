"""Fix stuck scans using raw SQLite (avoids SQLAlchemy schema mismatch)."""
import sqlite3

db_path = "vapt.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check if ai_mode column exists, add it if not
cursor.execute("PRAGMA table_info(scans)")
columns = [col[1] for col in cursor.fetchall()]
print(f"Columns in 'scans' table: {columns}")

if "ai_mode" not in columns:
    print("Adding missing 'ai_mode' column...")
    cursor.execute("ALTER TABLE scans ADD COLUMN ai_mode TEXT DEFAULT 'offline'")
    conn.commit()
    print("Column added.")

# Find and fix stuck scans
cursor.execute("SELECT id, status, filename FROM scans")
rows = cursor.fetchall()

if not rows:
    print("\nNo scans in database.")
else:
    stuck_statuses = ("pending", "processing_files", "scanning", "ai_analysis")
    fixed = 0
    print(f"\nTotal scans: {len(rows)}")
    for row in rows:
        sid, status, fname = row
        tag = "STUCK" if status in stuck_statuses else "ok"
        print(f"  [{tag}] ID={sid} | status={status} | file={fname}")
        if status in stuck_statuses:
            cursor.execute("UPDATE scans SET status='failed' WHERE id=?", (sid,))
            fixed += 1

    conn.commit()
    print(f"\nFixed {fixed} stuck scan(s) -> marked as 'failed'.")

conn.close()
print("Done.")
