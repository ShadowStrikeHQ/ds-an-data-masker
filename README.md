# ds-an-data-masker
A command-line tool that masks sensitive data fields (e.g., credit card numbers, phone numbers) in structured data formats (CSV, JSON) with consistent, reversible tokens using format-preserving encryption (FPE). - Focused on Tools for removing or obfuscating sensitive information from data sets. This includes generating synthetic data to replace real data, redacting specific data fields, and scrambling/masking PII to enable safe sharing and analysis of sensitive data. Intended for use cases like testing and debugging.

## Install
`git clone https://github.com/ShadowStrikeHQ/ds-an-data-masker`

## Usage
`./ds-an-data-masker [params]`

## Parameters
- `-h`: Show help message and exit
- `--unmask`: Unmask data instead of masking.
- `--key`: Encryption key. If not provided, a new key will be generated and printed.
- `--keyfile`: Path to a file containing the encryption key. Overrides --key.

## License
Copyright (c) ShadowStrikeHQ
