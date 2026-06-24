# WatsonSec fixture — intentionally vulnerable Python for Bandit adapter testing.
# DO NOT use in production.

import os
import subprocess
import hashlib
import pickle
import yaml

# B102 exec used
def run_code(user_code):
    exec(user_code)  # noqa

# B105 hardcoded password
PASSWORD = "super_secret_password_123"

# B404, B602 subprocess with shell=True
def run_shell(cmd):
    return subprocess.call(cmd, shell=True)  # noqa

# B301 pickle deserialise (insecure)
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)  # noqa

# B506 yaml.load without Loader
def parse_yaml(content):
    return yaml.load(content)  # noqa

# B303 MD5 use (weak hashing)
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # noqa

# B608 SQL injection via string concatenation
def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")  # noqa
    return cursor.fetchall()
