import requests
import argparse
import sys
from urllib.parse import urlparse
import hashlib
from Crypto.Cipher import AES
import base64
import os
import time
import threading
from tqdm import tqdm

loanUrl = "https://archive.org/services/loans/loan"

bookId = None
page_start = None
page_end = None
loanToken = ""
cookies = {}

def build_book_reader_url(page_num):
    return (
        f"https://ia800502.us.archive.org/BookReader/BookReaderImages.php"
        f"?zip=/16/items/{bookId}/{bookId}_jp2.zip"
        f"&file={bookId}_jp2/{bookId}_{page_num:04}.jp2"
        f"&id={bookId}"
        f"&scale=4"
        f"&rotate=0"
    )

def payload(action):
     return {
        "action": action,
        "identifier": bookId
     }

def get_cookies(include_loan_token=False):

    if not cookies.get("loggedInSig") or not cookies.get("loggedInUser"):
        handle_error("Missing auth cookies in files")

    cookie_data = {
        "logged-in-sig": cookies["loggedInSig"],
        "logged-in-user": cookies["loggedInUser"]
    }
    
    if include_loan_token:
        if not loanToken or not bookId:
            handle_error("Missing loanToken or bookId for loan cookie")
        cookie_data[f"loan-{bookId}"] = loanToken

    return cookie_data

def handle_error(msg, e=None):
    print(f"[ERROR] {msg}")
    if e:
        print(f"Details: {e}")
    sys.exit(1)

def decrypt(data, aesKey, counter):
    aes_key_bytes = aesKey.encode('utf-8')
    sha1_digest = hashlib.sha1(aes_key_bytes).digest()

    key = sha1_digest[:16]
    try:
        counter_bytes = base64.b64decode(counter)
    except Exception as e:
        handle_error("Invalid base64 counter", e)

    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(counter_bytes, 'big'))

    return cipher.decrypt(data)

def headers(page_num):
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Referer": f"https://archive.org/details/{bookId}/page/{page_num}/mode/2up",
        "Origin": "https://archive.org",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
    }

def refresh_loan_token():
    global loanToken
    while True:
        # Wait 2 minutes
        time.sleep(120)

        try:
            response = requests.post(loanUrl, data=payload("create_token"), cookies=get_cookies())
            print("[Token Refresh] Status Code:", response.status_code)
            print("[Token Refresh] Response Body:", response.text)

            data = response.json()
            if data.get("success") == True:
                loanToken = data.get("token")
                print("[Token Refresh] New token obtained.")
            else:
                print("[Token Refresh] Failed to obtain new token.")
        except Exception as e:
            handle_error("[Token Refresh] Error: ", e)

	

def parse_args():
    parser = argparse.ArgumentParser(description="Download and decrypt Archive.org book pages.")

    parser.add_argument("--book-id", required=True, help="The ID of the book on Archive.org")
    parser.add_argument("--page-start", type=int, required=True, help="The starting page number")
    parser.add_argument("--page-end", type=int, required=True, help="The ending page number")
    parser.add_argument("--cookies", required=True, help="Path to cookies file or raw token string")

    return parser.parse_args()

def main():
    global bookId
    global page_start
    global page_end
    global loanToken
    global cookies

    args = parse_args()
    bookId = args.book_id
    page_start = args.page_start
    page_end = args.page_end
    cookies_file = args.cookies

    if page_start <= 0 or page_end < page_start:
        handle_error("Invalid page range")

    # Create pages folder if it doesn't exist in project directory
    folder_root = "pages"
    os.makedirs(folder_root, exist_ok=True)

    # Create folder to store all the book pages, and nest it to root folder
    folder_name = os.path.join(folder_root, bookId)
    os.makedirs(folder_name, exist_ok=True)
    
    # Extract the authentication cookies from file
    with open(cookies_file) as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                cookies[key] = value


    # Initiate borrowing the book
    response = requests.post(loanUrl, data=payload("browse_book"), cookies=get_cookies())

    print("Status Code:", response.status_code)
    print("Response Body:")
    print(response.text)

    # Initial loan token request
    response = requests.post(loanUrl, data=payload("create_token"), cookies=get_cookies())

    print("Status Code:", response.status_code)
    print("Response Body:")
    print(response.text)

    data = response.json()
    if data.get("success") == True:
        loanToken = data.get("token")

        # Start background thread to refresh loan token every 2 mins
        token_thread = threading.Thread(target=refresh_loan_token, daemon=True)
        token_thread.start()

        # Loop through each page and download it

        for page_num in tqdm(range(page_start, page_end + 1), desc="Downloading pages", unit="page"):
            response = requests.get(build_book_reader_url(page_num), headers=headers(page_num), cookies=get_cookies(True))
            #print("Status Code:", response.status_code)

            if response.status_code != 200:
                handle_error("Failed to get book reader image", response.text)

            x_obfuscate = response.headers.get("X-Obfuscate")
            #print("X-Obfuscate:", x_obfuscate)

            contentType = response.headers.get('content-type')
            #print("Content Type:", contentType)

            final_image = response.content

            if x_obfuscate: # We need to decrypt the first 1024 bytes
                parts = x_obfuscate.split('|')
                if not (len(parts) == 2 and parts[0] and parts[1]):
                    handle_error("Malformed X-Obfuscate header")

                version, counter = parts

                if version != '1':
                    handle_error("Unsupported X-Obfuscate version")

                parsed = urlparse(build_book_reader_url(page_num))
                aesKey = parsed.path + ('?' + parsed.query if parsed.query else '')
                #print("AES Key:", aesKey)

                decryptedBuffer = decrypt(response.content[:1024], aesKey, counter)
                final_image = decryptedBuffer + response.content[1024:]

            parsedFileExtension = contentType.partition(';')[0].split('/')[1].strip()
            file_path = os.path.join(folder_name, f"{page_num}.{parsedFileExtension}")

            with open(file_path, "wb") as f:
                f.write(final_image)

            time.sleep(0.5) # Rate-limit
    else:
        handle_error("Failed to create initial loan token")

    
if __name__ == "__main__":
    main()