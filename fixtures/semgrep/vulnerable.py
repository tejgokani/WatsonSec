# WatsonSec fixture — intentionally vulnerable Python for Semgrep adapter testing.
# DO NOT use this code in production.

import os
import subprocess
import sqlite3

def run_query(user_input):
    # Semgrep should flag: sql injection (string concatenation in query)
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
    return cursor.fetchall()

def run_command(filename):
    # Semgrep should flag: os.system with unsanitized input (command injection)
    os.system("cat " + filename)

def eval_input(code):
    # Semgrep should flag: eval with user-controlled input
    return eval(code)

def read_file(path):
    # Semgrep should flag: open with unsanitized path (path traversal)
    with open(path, "r") as f:
        return f.read()
