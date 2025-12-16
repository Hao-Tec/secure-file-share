# 🔐 Secure File Share

A beautiful, secure file sharing application with AES-256 encryption. Upload files with password protection and share them safely.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **🔒 AES-256 Encryption** - Military-grade encryption for your files
- **🔑 Password Protection** - Each file encrypted with a unique password
- **🎨 Modern UI** - Glassmorphism design with smooth animations
- **📱 Responsive** - Works on desktop, tablet, and mobile
- **📊 Progress Tracking** - Real-time upload progress bar
- **💪 Password Strength** - Visual indicator for password security
- **📁 File Management** - List, download, and delete encrypted files
- **🛡️ CSRF Protected** - Secure against cross-site request forgery

## 🚀 Live Demo

**[Try it live on Render](https://secure-file-share.onrender.com)** *(Update this URL after deployment)*

## 📸 Screenshots

<details>
<summary>Click to view screenshots</summary>

### Main Interface
The modern dark-themed interface with upload and download sections.

### File List
View all your encrypted files with sizes and quick actions.

### Password Strength Indicator
Real-time feedback on password security.

</details>

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
   cp .env.example .env
   # Edit .env and set a strong SECRET_KEY
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Open in browser**
   ```
   http://127.0.0.1:5000
   ```

## 🔧 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret (required in production) | `dev-fallback-key` |
| `FLASK_ENV` | Environment: `development` or `production` | `development` |

### Generate a secure secret key:
```python
python -c "import secrets; print(secrets.token_hex(32))"
```

## 🏗️ Project Structure

```
secure-file-share/
├── app.py              # Main Flask application
├── config.py           # Configuration settings
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template
├── templates/
│   └── index.html      # Main HTML template
├── static/
│   ├── css/
│   │   └── styles.css  # Custom styles
│   └── js/
│       └── script.js   # Frontend JavaScript
└── uploads/            # Encrypted files (gitignored)
```

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **Unique Salt Per File** | Each file has its own 16-byte random salt |
| **PBKDF2 Key Derivation** | 100,000 iterations for key stretching |
| **AES-EAX Mode** | Authenticated encryption with integrity verification |
| **CSRF Tokens** | Protection against cross-site request forgery |
| **Password Validation** | Minimum 8 chars, mixed case, digits required |
| **Path Traversal Prevention** | All filenames sanitized |
| **File Size Limits** | Maximum 16MB uploads |

## 🚀 Deployment on Render

1. **Push to GitHub** (see below)

2. **Create Render account** at [render.com](https://render.com)

3. **Create New Web Service**
   - Connect your GitHub repository
   - Environment: `Python 3`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

4. **Set Environment Variables**
   - `SECRET_KEY`: Generate a strong random key
   - `FLASK_ENV`: `production`
   - `PYTHON_VERSION`: `3.11.0`

5. **Deploy!** 🎉

## 📝 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main page |
| `POST` | `/upload` | Upload and encrypt file |
| `POST` | `/download` | Download and decrypt file |
| `GET` | `/api/files` | List all encrypted files |
| `DELETE` | `/api/files/<filename>` | Delete encrypted file |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Habeeb** - [GitHub Profile](https://github.com/Hao-Tec)

---

<p align="center">
  Made with ❤️ and 🔐 security in mind
</p>
