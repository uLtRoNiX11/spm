"""
SPM - Secure Password Manager
Class 12 Computer Science Project  (Python + MySQL)

What it does
  * You protect the vault with ONE master password.
  * Site, username, password and notes are ENCRYPTED before they are saved
    in the MySQL table, so the database only ever contains scrambled text.
  * Add, view, search, edit and delete logins; generate random passwords.
  * Auto-locks after 5 minutes of inactivity; slows down wrong guesses.

How the encryption works (all written by hand, no extra libraries)
  1. KEY DERIVATION: the master password + a random "salt" is mixed into a
     big number and stretched by repeating a formula many times. The result
     is the secret key. The master password itself is never stored.
  2. STREAM CIPHER: a formula called an LCG (linear congruential generator)
     produces a stream of pseudo-random numbers from the key. Each byte of
     the data is XOR-ed with one number from that stream.
  3. NONCE: every saved field gets its own random value mixed into the key,
     so saving the same text twice gives different scrambled results.
  4. CHECK VALUE: a marker and a checksum are added to the data before
     encrypting. A wrong key or changed data fails the check on decrypting.

IMPORTANT: this is a learning project. The cipher shows how encryption
works but is NOT as strong as professional ones such as AES. Do not trust
it with passwords that matter.
"""

import os
import time
import random
import getpass
import mysql.connector

# ----------------------------------------------------------------------
# Settings (change DB_PASSWORD to your own MySQL password)
# ----------------------------------------------------------------------
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = ""
DB_NAME = "spm_db"

IDLE_LIMIT = 300          # seconds of inactivity before auto-lock
MIN_MASTER_LEN = 12       # shortest allowed master password
MAX_FAILS = 5             # wrong guesses before the delay starts
STRETCH_ROUNDS = 200000   # more rounds = slower to guess, slower to unlock

# LCG settings: state = (MULT * state + INC) mod MOD, using 128-bit numbers
MOD = 2 ** 128
MULT = 0x2360ED051FC65DA44385DF649FCCF645
INC = 0x5851F42D4C957F2D14057B7EF767814F

MARKER = "SPM1".encode("utf-8")   # placed at the start of every plaintext

# SystemRandom takes randomness from the operating system, which is safer
# than the normal random generator for salts, nonces and passwords.
rng = random.SystemRandom()

con = None    # the MySQL connection (set in connect_db)


# ======================================================================
# PART 1 - ENCRYPTION
# ======================================================================

def next_state(state):
    """One step of the LCG formula."""
    return (MULT * state + INC) % MOD


def text_to_state(text):
    """Mix every character of a text into one big number."""
    state = 1
    for ch in text:
        state = next_state((state + ord(ch)) % MOD)
    return state


def random_hex(n):
    """n random hexadecimal characters (used for salt and nonce)."""
    digits = "0123456789abcdef"
    out = ""
    for _ in range(n):
        out += rng.choice(digits)
    return out


def derive_key(master, salt):
    """Master password + salt -> secret key (a 128-bit number)."""
    state = text_to_state(salt + master)
    for _ in range(STRETCH_ROUNDS):      # key stretching
        state = next_state(state)
    return state


def keystream_byte(state):
    """Take 8 bits from the middle of the state (the top bits of an LCG
    are less predictable than the bottom bits)."""
    return (state >> 64) & 255


def encrypt(key, text):
    """Return the text as scrambled hexadecimal. The first 16 characters
    of the result are the nonce, needed again for decrypting."""
    nonce = random_hex(16)
    state = next_state((key + text_to_state(nonce)) % MOD)

    data = list(MARKER) + list(text.encode("utf-8"))
    total = sum(data) % 65536                  # checksum, stored in 2 bytes
    data.append(total // 256)
    data.append(total % 256)

    result = nonce
    for b in data:
        state = next_state(state)
        result += "{:02x}".format(b ^ keystream_byte(state))
    return result


def decrypt(key, token):
    """Reverse of encrypt(). Raises ValueError if the key is wrong or the
    stored data was changed."""
    try:
        nonce = token[:16]
        body = token[16:]
        state = next_state((key + text_to_state(nonce)) % MOD)

        data = []
        for i in range(0, len(body), 2):
            state = next_state(state)
            data.append(int(body[i:i + 2], 16) ^ keystream_byte(state))

        good = len(data) >= 6 and bytes(data[:4]) == MARKER
        if good:
            total = sum(data[:-2]) % 65536
            good = (data[-2] * 256 + data[-1]) == total
        if not good:
            raise ValueError("check failed")
        return bytes(data[4:-2]).decode("utf-8")
    except (ValueError, IndexError):
        raise ValueError("Wrong key, or the data was changed.")


def generate_password(length=16):
    """Random password with at least one lowercase, uppercase, digit and
    symbol."""
    sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ",
            "23456789", "!@#$%^&*-_=+?"]
    everything = "".join(sets)
    chars = []
    for s in sets:
        chars.append(rng.choice(s))
    while len(chars) < length:
        chars.append(rng.choice(everything))
    rng.shuffle(chars)
    return "".join(chars)


# ======================================================================
# PART 2 - DATABASE (MySQL)
# ======================================================================

def connect_db():
    """Connect to MySQL and create the database and tables if needed."""
    global con
    con = mysql.connector.connect(host=DB_HOST, user=DB_USER,
                                  password=DB_PASSWORD)
    cur = con.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS " + DB_NAME)
    cur.execute("USE " + DB_NAME)
    # meta: stores the salt and the verifier (used to check the master password)
    cur.execute("CREATE TABLE IF NOT EXISTS meta ("
                "meta_key VARCHAR(20) PRIMARY KEY, "
                "meta_value TEXT NOT NULL)")
    # credentials: every column holds ENCRYPTED text only
    cur.execute("CREATE TABLE IF NOT EXISTS credentials ("
                "id INT AUTO_INCREMENT PRIMARY KEY, "
                "site_enc TEXT NOT NULL, "
                "user_enc TEXT NOT NULL, "
                "pass_enc TEXT NOT NULL, "
                "notes_enc TEXT NOT NULL, "
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    con.commit()


def get_meta(name):
    cur = con.cursor()
    cur.execute("SELECT meta_value FROM meta WHERE meta_key = %s", (name,))
    row = cur.fetchone()
    if row is None:
        return None
    return row[0]


def set_meta(name, value):
    cur = con.cursor()
    cur.execute("REPLACE INTO meta (meta_key, meta_value) VALUES (%s, %s)",
                (name, value))
    con.commit()


def db_add(key, site, username, password, notes):
    cur = con.cursor()
    cur.execute("INSERT INTO credentials (site_enc, user_enc, pass_enc, "
                "notes_enc) VALUES (%s, %s, %s, %s)",
                (encrypt(key, site), encrypt(key, username),
                 encrypt(key, password), encrypt(key, notes)))
    con.commit()


def db_get(rec_id):
    """Return the raw (encrypted) row for an id, or None."""
    cur = con.cursor()
    cur.execute("SELECT id, site_enc, user_enc, pass_enc, notes_enc "
                "FROM credentials WHERE id = %s", (rec_id,))
    return cur.fetchone()


def db_update(key, rec_id, site, username, password, notes):
    cur = con.cursor()
    cur.execute("UPDATE credentials SET site_enc = %s, user_enc = %s, "
                "pass_enc = %s, notes_enc = %s, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = %s",
                (encrypt(key, site), encrypt(key, username),
                 encrypt(key, password), encrypt(key, notes), rec_id))
    con.commit()


def db_delete(rec_id):
    cur = con.cursor()
    cur.execute("DELETE FROM credentials WHERE id = %s", (rec_id,))
    con.commit()


def load_all(key):
    """Decrypt site and username of every row (passwords stay encrypted
    until the user asks to see them). Returns a list of [id, site, user]."""
    cur = con.cursor()
    cur.execute("SELECT id, site_enc, user_enc FROM credentials")
    items = []
    for rec_id, site_enc, user_enc in cur.fetchall():
        try:
            items.append([rec_id, decrypt(key, site_enc),
                          decrypt(key, user_enc)])
        except ValueError:
            items.append([rec_id, "[unreadable entry]", ""])
    items.sort(key=sort_by_site)
    return items


def sort_by_site(item):
    return item[1].lower()


# ======================================================================
# PART 3 - MASTER PASSWORD, LOCKING AND SCREEN HELPERS
# ======================================================================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def setup_vault():
    """First run: create the master password. Returns the key."""
    print("Welcome to SPM. Create your vault.")
    print("Your master password is never saved. If you forget it, your")
    print("data cannot be recovered.\n")
    while True:
        first = getpass.getpass("Choose a master password: ")
        if len(first) < MIN_MASTER_LEN:
            print("Use at least", MIN_MASTER_LEN, "characters.")
            continue
        if first != getpass.getpass("Confirm master password: "):
            print("The passwords do not match. Try again.")
            continue
        break
    salt = random_hex(32)
    print("Creating vault...")
    key = derive_key(first, salt)
    set_meta("salt", salt)
    set_meta("verifier", encrypt(key, "SPM-OK"))
    return key


def unlock_vault():
    """Ask for the master password until it is right. Returns the key, or
    None if the user presses Enter on an empty prompt to quit."""
    salt = get_meta("salt")
    verifier = get_meta("verifier")
    fails = 0
    while True:
        master = getpass.getpass("Master password (Enter to quit): ")
        if master == "":
            return None
        key = derive_key(master, salt)
        try:
            if decrypt(key, verifier) == "SPM-OK":
                return key
        except ValueError:
            pass                      # wrong password
        fails += 1
        print("Wrong master password.")
        if fails >= MAX_FAILS:
            wait = min(30 * 2 ** (fails - MAX_FAILS), 900)
            print("Too many wrong attempts. Please wait", wait, "seconds.")
            time.sleep(wait)


# ======================================================================
# PART 4 - MENU ACTIONS
# ======================================================================

def ask_id(prompt):
    """Ask for a record id and make sure the record exists."""
    text = input(prompt).strip()
    if not text.isdigit():
        print("Please enter a number.")
        return None
    row = db_get(int(text))
    if row is None:
        print("No login with that ID.")
        return None
    return row


def ask_password(prompt):
    """Let the user type a password (hidden) or press g to generate one."""
    pw = getpass.getpass(prompt)
    if pw.lower() == "g":
        pw = generate_password()
        print("Generated password:", pw)
    return pw


def show_table(items):
    if len(items) == 0:
        print("No logins to show.")
        return
    print("{:<5}{:<30}{:<30}".format("ID", "Site", "Username"))
    print("-" * 65)
    for rec_id, site, username in items:
        print("{:<5}{:<30}{:<30}".format(rec_id, site[:28], username[:28]))


def add_login(key):
    print("\n--- Add login ---")
    site = input("Site or app: ").strip()
    if site == "":
        print("Site is required.")
        return
    username = input("Username or email: ").strip()
    password = ask_password("Password (type it, or g to generate): ")
    if password == "":
        print("Password is required.")
        return
    notes = input("Notes (optional): ")
    db_add(key, site, username, password, notes)
    print("Login saved.")


def view_all(key):
    print("\n--- All logins ---")
    show_table(load_all(key))


def search_logins(key):
    print("\n--- Search ---")
    term = input("Search for: ").strip().lower()
    found = []
    for item in load_all(key):
        if term in item[1].lower() or term in item[2].lower():
            found.append(item)
    show_table(found)


def show_entry(key):
    print("\n--- Show full login ---")
    row = ask_id("Enter ID: ")
    if row is None:
        return
    try:
        print("\nSite     :", decrypt(key, row[1]))
        print("Username :", decrypt(key, row[2]))
        print("Password :", decrypt(key, row[3]))
        print("Notes    :", decrypt(key, row[4]))
    except ValueError:
        print("This entry is damaged or was changed outside the program.")
        return
    input("\nPress Enter to hide the password...")
    clear_screen()          # remove the password from the screen


def edit_login(key):
    print("\n--- Edit login ---")
    row = ask_id("Enter ID: ")
    if row is None:
        return
    try:
        site = decrypt(key, row[1])
        username = decrypt(key, row[2])
        password = decrypt(key, row[3])
        notes = decrypt(key, row[4])
    except ValueError:
        print("This entry is damaged and cannot be edited.")
        return
    print("Press Enter to keep the current value.")
    new_site = input("Site [" + site + "]: ").strip()
    new_user = input("Username [" + username + "]: ").strip()
    new_pass = ask_password("New password (Enter = keep, g = generate): ")
    new_notes = input("Notes [" + notes + "]: ")
    if new_site != "":
        site = new_site
    if new_user != "":
        username = new_user
    if new_pass != "":
        password = new_pass
    if new_notes != "":
        notes = new_notes
    db_update(key, row[0], site, username, password, notes)
    print("Login updated.")


def delete_login():
    print("\n--- Delete login ---")
    row = ask_id("Enter ID: ")
    if row is None:
        return
    if input("Type YES to delete this login permanently: ") == "YES":
        db_delete(row[0])
        print("Login deleted.")
    else:
        print("Cancelled.")


def generator_menu():
    print("\n--- Password generator ---")
    text = input("Length (8 to 64, default 16): ").strip()
    length = 16
    if text.isdigit() and 8 <= int(text) <= 64:
        length = int(text)
    print("Password:", generate_password(length))


# ======================================================================
# PART 5 - MAIN PROGRAM
# ======================================================================

MENU = """
========== SPM - Secure Password Manager ==========
 1. Add login            5. Edit login
 2. View all logins      6. Delete login
 3. Show full login      7. Generate password
 4. Search               8. Lock vault
 0. Exit
==================================================="""


def main():
    try:
        connect_db()
    except mysql.connector.Error as err:
        print("Could not connect to MySQL:", err)
        print("Check that MySQL is running and DB_USER / DB_PASSWORD are right.")
        return

    if get_meta("salt") is None:
        key = setup_vault()
    else:
        print("SPM is locked.")
        key = unlock_vault()
    if key is None:
        return

    last_active = time.time()
    while True:
        print(MENU)
        choice = input("Choose an option: ").strip()

        # Auto-lock: if too much time passed, throw the key away
        if time.time() - last_active > IDLE_LIMIT:
            key = None
            clear_screen()
            print("Locked automatically after", IDLE_LIMIT // 60,
                  "minutes of inactivity.")
            key = unlock_vault()
            if key is None:
                break
            last_active = time.time()
            continue

        if choice == "1":
            add_login(key)
        elif choice == "2":
            view_all(key)
        elif choice == "3":
            show_entry(key)
        elif choice == "4":
            search_logins(key)
        elif choice == "5":
            edit_login(key)
        elif choice == "6":
            delete_login()
        elif choice == "7":
            generator_menu()
        elif choice == "8":
            key = None
            clear_screen()
            print("Vault locked.")
            key = unlock_vault()
            if key is None:
                break
        elif choice == "0":
            break
        else:
            print("Invalid option.")
        last_active = time.time()

    key = None
    con.close()
    print("Goodbye.")


if __name__ == "__main__":
    try:
        main()
    except mysql.connector.Error as err:
        print("Database error:", err)
    except KeyboardInterrupt:
        print("\nGoodbye.")
