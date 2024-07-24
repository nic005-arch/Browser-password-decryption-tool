# Browser-password-decryption-tool


A Python script designed to extract and decrypt saved passwords from popular web browsers, including Chrome, Firefox, Brave, and Edge. This tool supports various data formats and provides a convenient way to recover stored credentials.

## Features

- **Extracts passwords** from Chrome, Brave, Edge, and Firefox browsers.
- **Supports decryption** of encrypted password databases.
- Handles both **JSON** and **SQLite** database formats.
- Saves extracted credentials to a user-specified file.

  ## Directory Structure
  ```sql

  main_directory/
  │
  ├── Chrome/
  │   ├── Login Data
  │   └── Local State
  │
  ├── Brave/
  │   ├── Login Data
  │   └── Local State
  │
  ├── Edge/
  │   ├── Login Data
  │   └── Local State
  │
  └── Firefox/
      ├── logins.json
      └── key4.db



