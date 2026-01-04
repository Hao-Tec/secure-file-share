# 🔐 Secure File Share

A beautiful, secure file sharing application with AES-256 encryption. Upload files with password protection and share them safely.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

### Core Security

- **🔒 AES-256 Encryption** - Military-grade encryption (AES-EAX mode) for your files
- **🔑 Password Protection** - PBKDF2 key derivation with 100,000 iterations
- **🛡️ Advanced Security Headers** - HSTS, CSP, X-Frame-Options, & X-Content-Type-Options
- **⚡ Strict Rate Limiting** - Prevents abuse (5 uploads/hr, 20 downloads/hr)

### File Management

- **📁 File Listing** - View all encrypted files with metadata
- **⏰ Auto-Expiration** - Files auto-delete after 7 days
- **📊 Download Counter** - Track how many times files are downloaded
- **🔗 Shareable Links** - Generate unique, secure share links
- **📧 Email Package** - Download self-decrypting HTML files for offline sharing

### User Experience

- **🎨 Modern Glassmorphism UI** - Beautiful dark/light mode with smooth animations
- **📁 Smart Drag & Drop** - Drop files anywhere with visual feedback
- **📱 Fully Responsive** - Optimized for desktop, tablet, and mobile
- **📊 Real-time Progress** - Upload progress bar and status feedback
- **📋 One-Click Copy** - Copy share links with visual feedback
- **💪 Password Strength** - Visual indicator for password complexity

## 🚀 Live Demo

**[🔗 Try it live on Render](https://cipher-vault-rke7.onrender.com)**

## 📸 Screenshots

### Main Interface

<p align="center">
  <img src="screenshots/main-interface.png" alt="Main Interface" width="700">
</p>
<p align="center"><em>Modern dark-themed interface with drag & drop upload</em></p>

### File Management

<p align="center">
  <img src="screenshots/file-list.png" alt="File List" width="700">
</p>
<p align="center"><em>Manage your encrypted files and download securely</em></p>

## 🛠️ Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Local Development

1. **Clone the repository**

   ```bash
   git clone https://github.com/Hao-Tec/secure-file-share.git
   cd secure-file-share
   ```

2. **Create virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**

   ```bash
   # Create a .env file (or rename .env.example)
   cp .env.example .env
   ```

5. **Run the application**

   ```bash
   python app.py
   ```

6. **Open in browser**
   ```
   http://127.0.0.1:5000
   ```

## 🔒 Security Architecture

| Feature               | Description                                                                       |
| --------------------- | --------------------------------------------------------------------------------- |
| **Encryption**        | AES-256 in EAX mode (Authenticated Encryption)                                    |
| **Key Derivation**    | PBKDF2-HMAC-SHA256 with 100,000 rounds and random salt                            |
| **Security Headers**  | HSTS (Strict Transport Security), CSP (Content Security Policy), NoSniff, NoFrame |
| **Rate Limiting**     | Per-IP limiting for uploads (2/min, 5/hr) and downloads (5/min, 20/hr)            |
| **CSRF Protection**   | Flask-WTF CSRF tokens on all forms                                                |
| **Input Validation**  | Secure filename sanitization and path traversal prevention                        |
| **IDOR Protection**   | Deletion requires "proof of knowledge" (password verification)                    |
| **Brute-Force Guard** | Offline files: 10 attempts max, progressive delays, then permanent lockout        |
| **Tamper Detection**  | SHA-256 integrity hash detects if offline HTML file was modified                  |
| **Lockout Persist**   | Brute-force protection survives page reload via localStorage                      |
| **XSS Protection**    | Filename sanitization prevents script injection in email packages                 |

## ⚡ Performance

- **In-Memory Caching**: Cache metadata to reduce disk I/O by ~85%
- **O(1) Token Lookup**: Instant share link resolution via hash map optimization

## 🚀 Deployment on Render (1-Click)

We use Render "Blueprints" to automatically create both the database and web service for you.

### 1. Push to GitHub

Make sure your code is pushed to your GitHub repository.

### 2. Create Blueprint

1. Go to your **Render Dashboard**
2. Click **New +** -> **Blueprint Instance**
3. Connect your repository (`secure-file-share`)
4. Click **Apply**

### 3. That's it! 🎉

Render will automatically:

- ✅ Create a free PostgreSQL database
- ✅ Create the web service (`cipher-vault`)
- ✅ Link them securely (setting `DATABASE_URL` automatically)
- ✅ Deploy the app

Once finished, your app will be live and your files will persist forever!

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**AbdulWaheed Habeeb** - [GitHub Profile](https://github.com/Hao-Tec)

---

<p align="center">
  Made with ❤️ and 🔐 security in mind
</p>
