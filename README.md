# 🔐 Chat Application with TLS Encryption (C++ & OpenSSL)

This is a simple yet powerful **C++ client-server chat application** that demonstrates **secure encrypted communication** using **TLS (SSL) via OpenSSL**. It helps visualize **plaintext messages vs encrypted data** to understand how encryption works under the hood.

---

## 💡 Features

- 🔒 TLS/SSL encrypted communication using OpenSSL  
- 💬 Bidirectional chat between client and server  
- 🛡️ Encrypted transmission with visible ciphertext  
- ⚙️ Structured for learning and extendability

---

## 📁 Project Structure

```
Chat_Application_OpenSSL_TLS_Encrypted/
├── client.cpp        # Client logic with SSL connection
├── server.cpp        # Server logic with SSL listener
├── common.h          # Shared utilities or constants (optional)
├── README.md         # You're reading it 🙂
├── .gitignore        # Ignores build artifacts
```

---

## 🧰 Prerequisites

- C++ compiler (e.g., MSVC, g++, clang++)
- [OpenSSL](https://www.openssl.org/) installed
- Visual Studio or any C++ IDE (if you're not using terminal)

---

## 🛠️ Build Instructions (Visual Studio or IDE method)

### ⚙️ Steps to link OpenSSL in Visual Studio:

1. **Install OpenSSL**: Download prebuilt binaries or build manually.  
   Example for Windows: [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)

2. **Set C/C++ Include Directories:**
   - Go to **Project Properties > C/C++ > General > Additional Include Directories**
   - Add path to OpenSSL `include/` directory

3. **Set Linker > General > Additional Library Directories:**
   - Add path to OpenSSL `lib/` directory (e.g., `lib/VC`)

4. **Set Linker > Input > Additional Dependencies:**
   - Add:
     ```
     libssl.lib
     libcrypto.lib
     ```

5. **Ensure DLLs are accessible**:
   - At runtime, copy `libssl-*.dll` and `libcrypto-*.dll` into your build or executable directory.

---

## 🧪 Build Instructions (Linux terminal version)

```bash
# Compile server
g++ server.cpp -o server -lssl -lcrypto

# Compile client
g++ client.cpp -o client -lssl -lcrypto
```

---

## 🚀 Running the Application

1. **Start the Server**:
   ```bash
   ./server
   ```

2. **Start the Client**:
   ```bash
   ./client
   ```

3. Enter messages from both sides — observe the **plaintext and encrypted output** in console.

---

## 📸 Screenshots (Optional)

_Add screenshots showing encrypted vs plaintext message exchange._

---

## 📝 License

This project is licensed under the MIT License. Feel free to use and modify it for educational or personal purposes.

---

## 🙋‍♂️ Author

**Aman Tripathi**  
💻 [github.com/amanntripathii](https://github.com/amanntripathii)

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.
