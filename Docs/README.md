# GIE - Go-based Information Encryptor

GIE is a desktop application built with Wails, combining the power of Go for backend logic (including robust encryption/decryption) and React/TypeScript for a modern, responsive frontend. It provides a secure way to encrypt and decrypt individual files and entire directories.

## Features

*   **File Encryption/Decryption:** Securely encrypt and decrypt individual files using AES-CTR and HMAC-SHA256.
*   **Directory Encryption/Decryption:** Process entire folders, encrypting or decrypting all contained files recursively.
*   **Password-Based Key Derivation:** Utilizes PBKDF2 for strong key derivation from user passwords, with configurable encryption strength levels (Low, Normal, High).
*   **Hint Support:** Allows users to add a hint to encrypted files, which can be retrieved without full decryption.
*   **File Association (Windows):** The application is designed to handle `.gie` file associations, allowing users to open encrypted files directly with the application (requires system-level association setup).
*   **Cross-Platform:** Built with Wails, ensuring compatibility across Windows, Linux, and macOS.

## Technologies Used

*   **Backend:** Go
    *   Cryptography: `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `golang.org/x/crypto/pbkdf2`
    *   File System Operations: `os`, `path/filepath`
*   **Frontend:** React with TypeScript
    *   Build Tool: Vite
*   **Framework:** Wails v2 (Go & Web Technologies Integration)

## Getting Started

### Prerequisites

*   Go (1.18 or higher)
*   Node.js (LTS version)
*   Wails CLI: Install with `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

### Development

To run the application in development mode (with hot-reloading for frontend changes):

```bash
wails dev
```

### Building for Production

To build a production-ready executable:

```bash
wails build
```

This will generate the executable in the `build/bin` directory.

## File Format (`.gie`)

Encrypted files (`.gie`) contain metadata (hint, channel, encryption level, salts, IV) followed by the AES-CTR encrypted ciphertext and an HMAC-SHA256 tag for integrity verification.

## Contribution

(Add contribution guidelines if applicable)

## License

(Add license information if applicable)
