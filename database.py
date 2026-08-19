import sqlite3

DB_NAME = "breaches.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_or_username TEXT,
            domain TEXT,
            masked_password TEXT,
            plain_password TEXT,
            target_url TEXT,
            category TEXT,
            added_date TEXT,
            leak_source TEXT,
            is_unlocked INTEGER DEFAULT 0
        )
    """)
    
    cursor.execute("SELECT COUNT(*) FROM credentials")
    if cursor.fetchone()[0] == 0:
        sample_records = [
            ("f2018134093@umt.edu.pk", "umt.edu.pk", "MaliKA_A986", "MaliKA_A986", "http://upwork.com", "Employees", "2026-08-16", "StealerLog_v1", 1),
            ("f2019105057@umt.edu.pk", "umt.edu.pk", "Aimenh00", "Aimenh00", "http://online.umt.edu.pk/account/resetpassword", "Employees", "2026-08-16", "StealerLog_v1", 1),
            ("f2019105057@umt.edu.pk", "umt.edu.pk", "Farazq07", "Farazq07", "http://online.umt.edu.pk/account/resetpassword", "Employees", "2026-08-16", "StealerLog_v1", 1),
            ("f2019088054@umt.edu.pk", "umt.edu.pk", "hassaan123", "hassaan123", "http://coursera.org/programs/grow-with-google", "Customers", "2026-08-16", "RedLine_Dump", 1),
            ("afreen.abbas930@gmail.com", "umt.edu.pk", "827460", "827460", "http://onlineadmissions.umt.edu.pk/login", "Customers", "2026-08-16", "RedLine_Dump", 1),
            ("f2018266059@umt.edu.pk", "umt.edu.pk", "🔒 Locked", "K2Y5jRFN", "http://lms.umt.edu.pk/moodle/login/index.php", "Customers", "2026-08-16", "DarkWeb_Feed", 0),
            ("user22@umt.edu.pk", "umt.edu.pk", "🔒 Locked", "SecP@ss2026", "http://socialbakers.com", "third_parties", "2026-08-16", "DarkWeb_Feed", 0),
            ("researcher@umt.edu.pk", "umt.edu.pk", "🔒 Locked", "Research!99", "http://researchgate.net", "third_parties", "2026-08-16", "DarkWeb_Feed", 0),
        ]
        cursor.executemany("""
            INSERT INTO credentials 
            (email_or_username, domain, masked_password, plain_password, target_url, category, added_date, leak_source, is_unlocked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sample_records)
        conn.commit()

    conn.close()

def search_breaches(query, search_type="domain", category_filter="All"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    clean_query = query.strip().lower()
    
    if search_type == "Domain":
        sql = "SELECT id, email_or_username, masked_password, plain_password, target_url, category, added_date, is_unlocked FROM credentials WHERE LOWER(domain) LIKE ?"
    else:
        sql = "SELECT id, email_or_username, masked_password, plain_password, target_url, category, added_date, is_unlocked FROM credentials WHERE LOWER(email_or_username) LIKE ?"
        
    params = [f"%{clean_query}%"]
        
    if category_filter != "All":
        sql += " AND category = ?"
        params.append(category_filter)
        
    cursor.execute(sql, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_stats(query, search_type="domain"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    clean_query = query.strip().lower()
    column = "domain" if search_type == "Domain" else "email_or_username"
    
    cursor.execute(f"SELECT COUNT(*) FROM credentials WHERE LOWER({column}) LIKE ? AND category = 'Employees'", (f"%{clean_query}%",))
    emp_count = cursor.fetchone()[0]
    
    cursor.execute(f"SELECT COUNT(*) FROM credentials WHERE LOWER({column}) LIKE ? AND category = 'Customers'", (f"%{clean_query}%",))
    cust_count = cursor.fetchone()[0]
    
    conn.close()
    return emp_count, cust_count
