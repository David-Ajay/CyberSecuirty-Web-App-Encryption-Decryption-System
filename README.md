
README.md 
# CyberSecuirty-Web-App-Encryption-Decryption-System

A cybersecurity-focused web application built using **Flask** that provides secure encryption and decryption for text and files.  
The app supports multiple cryptographic algorithms including **Fernet (symmetric)**, **RSA (asymmetric)**, and **AES (block cipher)**.  
Users can upload files or enter text, encrypt or decrypt the content, auto-generate cryptographic keys, and download the results in text or PNG format.

---

## 🚀 Features

- 🔐 **Text Encryption/Decryption** using AES, RSA, or Fernet  
- 📁 **File Encryption/Decryption** for `.txt`, `.csv`, `.json`, `.py`, and more  
- 🗝️ **Auto-generation of cryptographic keys** (RSA key pair, Fernet key, AES key)  
- 📤 **Export encrypted output as text or PNG image**  
- 🌐 User-friendly **web interface** built with Flask templates  
- 🔒 Demonstrates real cybersecurity concepts such as confidentiality and secure key handling  

---

## 🧪 Cryptographic Algorithms Used

- **Fernet** – Symmetric encryption with built-in authentication  
- **RSA** – Asymmetric public/private key encryption  
- **AES** – Block cipher encryption for secure data handling  

---

## 🛠️ Technology Stack

- **Python 3.x**  
- **Flask** (web framework)  
- **Cryptography library**  
- **Pillow** (for PNG export)  
- **HTML, CSS** (frontend templates)

---

## 📁 Project Structure



app.py
requirements.txt
templates/
static/
keys/ # auto-generated (ignored in .gitignore)
uploads/ # uploaded files (ignored in .gitignore)


---

## ⚙️ Installation & Usage

Clone the repository:

```bash
git clone https://github.com/<your-username>/securecrypt-webapp.git
cd securecrypt-webapp


Create a virtual environment:

python -m venv venv
source venv/bin/activate      # macOS / Linux
venv\Scripts\activate         # Windows


Install dependencies:

pip install -r requirements.txt


Run the application:

python app.py


Open in browser:

http://127.0.0.1:5000/

🔐 Security Notes

All cryptographic keys are stored in the keys/ directory, which is ignored by Git for safety.

Uploaded files are handled securely and stored only temporarily.

This project is intended for learning and demonstration purposes, not production deployment.

For real-world use, implement HTTPS, proper secret key handling, and secure deployment practices.

📄 License

This project is licensed under the MIT License.
See the LICENSE file for more details.

👨‍💻 Author

Nalla D Ajay
Data Science & Cybersecurity Enthusiast
