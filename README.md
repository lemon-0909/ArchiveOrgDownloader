# 📚 ArchiveOrgDownloader

> ⚡ **Easily download borrowable books from Archive.org**  
> 🎓 **Intended for educational purposes only**

---

## 🚀 Features
✅ Download any borrowable book’s pages  
✅ Supports decryption of obfuscated pages  
✅ Auto token refresh for long downloads  
✅ Saves pages neatly organized in `pages/`  

---

## 📝 Setup

1️⃣ Create a file named `cookies.txt` in the project directory.  
2️⃣ Inside, add:

loggedInSig=YOUR_LOGGED_IN_SIG
loggedInUser=YOUR_USERNAME

👉 *You can find these values in your browser’s **Network** tab when logged into archive.org.*

3️⃣ Install Python 3 (if you haven't already)
👉 Download from [https://www.python.org/downloads/](https://www.python.org/downloads/)

4️⃣ Create a virtual environment
```bash
python -m venv venv
```

5️⃣ Activate the virtual environment
- **Windows:**  
```bash
venv\Scripts\activate
```

- **macOS / Linux:**  
```bash
source venv/bin/activate
```

6️⃣ Install dependencies (inside venv)
```bash
pip install -r requirements.txt
```

## 📌 Usage

```bash
python downloader.py --book-id <BOOK_ID> --page-start <START_PAGE> --page-end <END_PAGE> --cookies cookies.txt
```

