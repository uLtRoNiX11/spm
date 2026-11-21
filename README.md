<div align="center">

<h1>SPM</h1>

<p><b>Secure Password Manager</b></p>

<p>
A console password manager written in Python and MySQL.<br>
Your logins are encrypted before they reach the database, and only your master password can unlock them.
</p>

<p>
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/mysql-database-4479A1?style=for-the-badge&logo=mysql&logoColor=white" alt="MySQL">
  <img src="https://img.shields.io/badge/interface-console-2d5a4a?style=for-the-badge" alt="Console">
</p>

<p>
  <img src="https://img.shields.io/badge/encryption-custom%20stream%20cipher-2d5a4a?style=flat-square" alt="Encryption">
  <img src="https://img.shields.io/badge/extra%20libraries-mysql--connector%20only-2d5a4a?style=flat-square" alt="Dependencies">
  <img src="https://img.shields.io/badge/purpose-educational-2d5a4a?style=flat-square" alt="Educational">
</p>

<p>
  <a href="#features">Features</a> &nbsp;|&nbsp;
  <a href="#how-it-works">How it works</a> &nbsp;|&nbsp;
  <a href="#getting-started">Getting started</a> &nbsp;|&nbsp;
  <a href="#usage">Usage</a> &nbsp;|&nbsp;
  <a href="#database-design">Database</a> &nbsp;|&nbsp;
  <a href="#limitations">Limitations</a>
</p>

</div>

<hr>

<h2 id="features">Features</h2>

<table>
  <tr>
    <td width="50%" valign="top">
      <h4>Master password</h4>
      One password unlocks the whole vault. It is never saved anywhere.
    </td>
    <td width="50%" valign="top">
      <h4>Encrypted storage</h4>
      Site, username, password, and notes are encrypted before they are written to MySQL.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h4>Full management</h4>
      Add, view, search, edit, and delete logins from a simple numbered menu.
    </td>
    <td width="50%" valign="top">
      <h4>Password generator</h4>
      Random passwords with lowercase, uppercase, digits, and symbols, from 8 to 64 characters.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h4>Auto-lock</h4>
      The vault locks after 5 minutes of inactivity, or any time you choose Lock.
    </td>
    <td width="50%" valign="top">
      <h4>Guess protection</h4>
      After 5 wrong master passwords, each further attempt is delayed by an increasing wait.
    </td>
  </tr>
</table>

<h2 id="tech-stack">Tech Stack</h2>

<table>
  <tr>
    <th align="left">Part</th>
    <th align="left">Technology</th>
  </tr>
  <tr>
    <td>Language</td>
    <td>Python 3.8+</td>
  </tr>
  <tr>
    <td>Database</td>
    <td>MySQL or MariaDB, through <code>mysql-connector-python</code></td>
  </tr>
  <tr>
    <td>Encryption</td>
    <td>Hand-written in Python (key stretching and a stream cipher)</td>
  </tr>
  <tr>
    <td>Standard modules</td>
    <td><code>random</code>, <code>time</code>, <code>os</code>, <code>getpass</code></td>
  </tr>
</table>

<h2 id="how-it-works">How it works</h2>

<p>
SPM uses your master password in two separate steps: it <b>unlocks</b> the vault, and it <b>creates the key</b> that encrypts every stored field.
</p>

<pre>
 Master password + random salt
              |
              v
   Key stretching (200,000 rounds)
              |
              v
     Secret key (128-bit number, memory only)
              |
     +--------+--------------------------+
     |                                   |
     v                                   v
 Encrypt a known value            Encrypt each field
 (the "verifier")                 (site, username, password, notes)
     |                                   |
     v                                   v
 Used to check your password      Scrambled text stored in MySQL
</pre>

<table>
  <tr>
    <th align="left" width="50%">Unlocking the vault</th>
    <th align="left" width="50%">Encrypting stored data</th>
  </tr>
  <tr>
    <td valign="top">
      <ul>
        <li>The master password is <b>never stored</b>, not even as a hash.</li>
        <li>It is mixed with a random salt and stretched many times to make guessing slow.</li>
        <li>A small known value, the verifier, is encrypted with the key and saved.</li>
        <li>If your typed password decrypts the verifier, it is correct.</li>
        <li>The key lives only in program memory and is discarded on lock or exit.</li>
      </ul>
    </td>
    <td valign="top">
      <ul>
        <li>A <b>stream cipher</b> turns the key into a long stream of numbers using a linear congruential generator.</li>
        <li>Each byte of data is combined (XOR) with one number from that stream.</li>
        <li>Every field gets its own random <b>nonce</b>, so saving the same text twice gives different results.</li>
        <li>A marker and a checksum are added before encrypting. A wrong key or changed data fails the check.</li>
        <li>The database holds only scrambled text, the salt, and the verifier.</li>
      </ul>
    </td>
  </tr>
</table>

<p>
Passwords are <b>encrypted, not hashed</b>, because the program must be able to show them again once you unlock the vault.
</p>

<h2 id="getting-started">Getting started</h2>

<h3>1. Install MySQL</h3>

<p>
Install MySQL or MariaDB and make sure the server is running. On Debian or Ubuntu:
</p>

<pre><code>sudo apt install mysql-server
sudo systemctl start mysql</code></pre>

<p>
On Windows or macOS, use the installer from <a href="https://dev.mysql.com/downloads/">dev.mysql.com</a>.
</p>

<h3>2. Create a database user (recommended)</h3>

<p>
Open the MySQL shell and run the lines below, replacing the password. On many Linux systems the <code>root</code> account cannot log in with a password, so a dedicated user is easier.
</p>

<pre><code>CREATE USER 'spm'@'localhost' IDENTIFIED BY 'choose-a-db-password';
GRANT ALL PRIVILEGES ON spm_db.* TO 'spm'@'localhost';
FLUSH PRIVILEGES;</code></pre>

<h3>3. Download and install</h3>

<pre><code>git clone https://github.com/uLtRoNiX11/spm
cd spm
pip install mysql-connector-python</code></pre>

<h3>4. Configure</h3>

<p>Open <code>spm.py</code> and edit the settings at the top:</p>

<pre><code>DB_HOST = "localhost"
DB_USER = "spm"                      # the user you created
DB_PASSWORD = "choose-a-db-password" # your MySQL password
DB_NAME = "spm_db"</code></pre>

<p>
This is your <b>MySQL</b> login, not your SPM master password. They are two different passwords.
</p>

<h3>5. Run</h3>

<pre><code>python spm.py</code></pre>

<p>
The program creates the <code>spm_db</code> database and its tables automatically on first run.
</p>

<h2 id="usage">Usage</h2>

<p>
On first launch, SPM asks you to create a master password of at least 12 characters. On later launches it asks for that password to unlock the vault. Press Enter on an empty prompt to quit.
</p>

<pre>
========== SPM - Secure Password Manager ==========
 1. Add login            5. Edit login
 2. View all logins      6. Delete login
 3. Show full login      7. Generate password
 4. Search               8. Lock vault
 0. Exit
===================================================
</pre>

<table>
  <tr>
    <th align="left" width="28%">Option</th>
    <th align="left">What it does</th>
  </tr>
  <tr>
    <td><b>1. Add login</b></td>
    <td>Saves a site, username, password, and notes. Type <code>g</code> at the password prompt to generate one.</td>
  </tr>
  <tr>
    <td><b>2. View all logins</b></td>
    <td>Lists the ID, site, and username of every login. Passwords are not shown here.</td>
  </tr>
  <tr>
    <td><b>3. Show full login</b></td>
    <td>Decrypts one login by ID and shows the password. The screen is cleared when you press Enter.</td>
  </tr>
  <tr>
    <td><b>4. Search</b></td>
    <td>Finds logins whose site or username contains your search text.</td>
  </tr>
  <tr>
    <td><b>5. Edit login</b></td>
    <td>Changes any field. Press Enter to keep the current value.</td>
  </tr>
  <tr>
    <td><b>6. Delete login</b></td>
    <td>Removes a login permanently after you type <code>YES</code> to confirm.</td>
  </tr>
  <tr>
    <td><b>7. Generate password</b></td>
    <td>Creates a random password of the length you choose.</td>
  </tr>
  <tr>
    <td><b>8. Lock vault</b></td>
    <td>Discards the key and asks for the master password again.</td>
  </tr>
</table>

<h3>Check that your data is really encrypted</h3>

<p>Open the MySQL shell and look at the raw table:</p>

<pre><code>USE spm_db;
SELECT id, site_enc, user_enc, pass_enc FROM credentials;</code></pre>

<p>
Every value should be a long string of hexadecimal characters. You should not see any readable site, username, or password.
</p>

<h2 id="database-design">Database design</h2>

<p><b>Table: <code>meta</code></b> (vault settings)</p>

<table>
  <tr>
    <th align="left">Column</th>
    <th align="left">Type</th>
    <th align="left">Purpose</th>
  </tr>
  <tr>
    <td><code>meta_key</code></td>
    <td>VARCHAR(20), primary key</td>
    <td>Either <code>salt</code> or <code>verifier</code></td>
  </tr>
  <tr>
    <td><code>meta_value</code></td>
    <td>TEXT</td>
    <td>The random salt, or the encrypted verifier</td>
  </tr>
</table>

<p><b>Table: <code>credentials</code></b> (your logins)</p>

<table>
  <tr>
    <th align="left">Column</th>
    <th align="left">Type</th>
    <th align="left">Purpose</th>
  </tr>
  <tr>
    <td><code>id</code></td>
    <td>INT, auto increment, primary key</td>
    <td>Unique login number</td>
  </tr>
  <tr>
    <td><code>site_enc</code></td>
    <td>TEXT</td>
    <td>Encrypted site or app name</td>
  </tr>
  <tr>
    <td><code>user_enc</code></td>
    <td>TEXT</td>
    <td>Encrypted username or email</td>
  </tr>
  <tr>
    <td><code>pass_enc</code></td>
    <td>TEXT</td>
    <td>Encrypted password</td>
  </tr>
  <tr>
    <td><code>notes_enc</code></td>
    <td>TEXT</td>
    <td>Encrypted notes</td>
  </tr>
  <tr>
    <td><code>updated_at</code></td>
    <td>TIMESTAMP</td>
    <td>Last change time (the only readable column)</td>
  </tr>
</table>

<h2 id="project-structure">Project structure</h2>

<pre>
spm/
├── spm.py          Whole program, in five parts:
│                     1. Encryption (key derivation, cipher, generator)
│                     2. Database (MySQL functions)
│                     3. Master password and locking
│                     4. Menu actions
│                     5. Main program loop
└── README.md
</pre>

<h2 id="limitations">Limitations</h2>

<table>
  <tr>
    <td>
      <b>This is a learning project, not a professional security tool.</b><br>
      The cipher is written from scratch to show how encryption works. It is not as strong as standard ciphers such as AES, and its checksum cannot stop a determined attacker from tampering with data. Do not store passwords that matter to you.
    </td>
  </tr>
  <tr>
    <td>
      <b>Your master password cannot be recovered.</b><br>
      It is not stored anywhere. If you forget it, your data is permanently unreadable.
    </td>
  </tr>
</table>

<ul>
  <li>Master password strength matters most. Use a long passphrase of several random words.</li>
  <li>Back up your data by exporting the <code>spm_db</code> database with <code>mysqldump</code>. The backup is as safe as the encryption.</li>
  <li>Python cannot reliably erase secrets from memory, so the key may remain there until the program closes.</li>
  <li>Malware on your computer could capture what you type.</li>
  <li>There is no clipboard copy, because the console cannot do it without extra libraries. Passwords are shown on screen instead.</li>
  <li>Changing <code>STRETCH_ROUNDS</code> or the cipher constants makes existing vaults unreadable.</li>
</ul>

<hr>

<div align="center">
  <sub>Built with Python and MySQL.</sub>
  <br><br>
  <a href="#top">Back to top</a>
</div>
