import argparse
import csv
import json
import logging
import sys
from typing import Dict, Any

from faker import Faker
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataMasker:
    """
    A class for masking sensitive data fields in structured data formats.
    """

    def __init__(self, key: bytes):
        """
        Initializes the DataMasker with a key.

        Args:
            key (bytes): The encryption key.
        """
        self.key = key
        self.fake = Faker()

    def format_preserving_encrypt(self, data: str) -> str:
        """
        Encrypts data using format-preserving encryption (FPE).
        Uses AES in counter mode for encryption.

        Args:
            data (str): The data to be encrypted.

        Returns:
            str: The encrypted data.
        """
        # Generate a random initialization vector (IV)
        iv = os.urandom(16)

        # Create a cipher object using AES in counter mode
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the data to be a multiple of the block size
        padding_length = 16 - (len(data) % 16)
        data += chr(padding_length) * padding_length

        # Encrypt the padded data
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()

        # Concatenate IV and encrypted data, then encode to base64
        return base64.b64encode(iv + encrypted_data).decode('utf-8')

    def format_preserving_decrypt(self, encrypted_data: str) -> str:
        """
        Decrypts data that was encrypted using format-preserving encryption (FPE).
        Uses AES in counter mode for decryption.

        Args:
            encrypted_data (str): The encrypted data to be decrypted.

        Returns:
            str: The decrypted data.
        """
        try:
            # Decode the base64 encoded data
            decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))

            # Extract the IV from the beginning of the decoded data
            iv = decoded_data[:16]
            encrypted_data_without_iv = decoded_data[16:]

            # Create a cipher object using AES in counter mode
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt the data
            decrypted_data = decryptor.update(encrypted_data_without_iv) + decryptor.finalize()

            # Remove padding
            padding_length = decrypted_data[-1]
            if padding_length > 0 and padding_length <= 16:
                decrypted_data = decrypted_data[:-padding_length]

            return decrypted_data.decode('utf-8')
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            return None

    def mask_data(self, data: Any, fields_to_mask: list) -> Any:
        """
        Masks specified fields in the given data.

        Args:
            data (Any): The data to be masked (dict or list of dicts).
            fields_to_mask (list): A list of field names to mask.

        Returns:
            Any: The masked data.
        """

        if isinstance(data, list):
            return [self.mask_data(item, fields_to_mask) for item in data]
        elif isinstance(data, dict):
            masked_data = {}
            for key, value in data.items():
                if key in fields_to_mask:
                    if isinstance(value, str):
                        masked_data[key] = self.format_preserving_encrypt(value)
                    else:
                        masked_data[key] = self.format_preserving_encrypt(str(value))
                else:
                    masked_data[key] = value
            return masked_data
        else:
            return data

    def unmask_data(self, data: Any, fields_to_unmask: list) -> Any:
      """
      Unmasks specified fields in the given data.

      Args:
          data (Any): The data to be unmasked (dict or list of dicts).
          fields_to_unmask (list): A list of field names to unmask.

      Returns:
          Any: The unmasked data.
      """
      if isinstance(data, list):
          return [self.unmask_data(item, fields_to_unmask) for item in data]
      elif isinstance(data, dict):
          unmasked_data = {}
          for key, value in data.items():
              if key in fields_to_unmask:
                  if isinstance(value, str):
                      unmasked_data[key] = self.format_preserving_decrypt(value)
                  else:
                      unmasked_data[key] = self.format_preserving_decrypt(str(value))
              else:
                  unmasked_data[key] = value
          return unmasked_data
      else:
          return data


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Mask sensitive data in CSV or JSON files.")
    parser.add_argument("input_file", help="The input file (CSV or JSON).")
    parser.add_argument("output_file", help="The output file (CSV or JSON).")
    parser.add_argument("fields_to_mask", nargs='+', help="List of fields to mask.")
    parser.add_argument("--unmask", action='store_true', help="Unmask data instead of masking.")
    parser.add_argument("--key", help="Encryption key. If not provided, a new key will be generated and printed.", required=False)
    parser.add_argument("--keyfile", help="Path to a file containing the encryption key. Overrides --key.", required=False)
    return parser


def read_data(input_file: str) -> Any:
    """
    Reads data from a CSV or JSON file.

    Args:
        input_file (str): The path to the input file.

    Returns:
        Any: The data read from the file.
    """
    try:
        if input_file.endswith(".csv"):
            with open(input_file, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                data = list(reader)
            return data
        elif input_file.endswith(".json"):
            with open(input_file, 'r') as jsonfile:
                data = json.load(jsonfile)
            return data
        else:
            raise ValueError("Unsupported file format. Only CSV and JSON are supported.")
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in file: {input_file}")
        raise
    except csv.Error as e:
        logging.error(f"CSV error: {e}")
        raise
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        raise


def write_data(data: Any, output_file: str):
    """
    Writes data to a CSV or JSON file.

    Args:
        data (Any): The data to be written.
        output_file (str): The path to the output file.
    """
    try:
        if output_file.endswith(".csv"):
            if not data:
                logging.warning("No data to write to CSV file.")
                return

            if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                raise ValueError("Data must be a list of dictionaries for CSV output.")

            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = data[0].keys() if data else [] # Get fieldnames from the first dict
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)

        elif output_file.endswith(".json"):
            with open(output_file, 'w') as jsonfile:
                json.dump(data, jsonfile, indent=4)
        else:
            raise ValueError("Unsupported file format. Only CSV and JSON are supported.")
    except Exception as e:
        logging.error(f"Error writing to file: {e}")
        raise


def generate_key() -> bytes:
    """
    Generates a new encryption key using PBKDF2HMAC.

    Returns:
        bytes: The generated encryption key.
    """
    password_provided = "default_password"  # Replace with a more secure method
    password = password_provided.encode()
    salt = os.urandom(16)  # Generate a unique salt for each key generation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=salt,
        iterations=390000,  # Recommended number of iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def main():
    """
    Main function to execute the data masking/unmasking process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # Determine the encryption key source (file, CLI, or generate new)
        if args.keyfile:
            try:
                with open(args.keyfile, 'r') as f:
                    key_str = f.read().strip()
                    key = base64.urlsafe_b64decode(key_str)
            except FileNotFoundError:
                logging.error(f"Key file not found: {args.keyfile}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Error reading key from file: {e}")
                sys.exit(1)

        elif args.key:
            try:
                key = base64.urlsafe_b64decode(args.key)
            except Exception as e:
                logging.error(f"Invalid key provided: {e}")
                sys.exit(1)
        else:
            key = generate_key()
            print(f"Generated key: {base64.urlsafe_b64encode(key).decode()}") # Print key for the user to store
            logging.warning("Generated a new key. Ensure to store it securely for decryption.")


        # Read data from the input file
        data = read_data(args.input_file)

        # Initialize DataMasker with the encryption key
        masker = DataMasker(key)

        # Perform masking or unmasking based on the --unmask flag
        if args.unmask:
            masked_data = masker.unmask_data(data, args.fields_to_mask)
        else:
            masked_data = masker.mask_data(data, args.fields_to_mask)

        # Write the masked/unmasked data to the output file
        write_data(masked_data, args.output_file)

        logging.info(f"Data processing complete. Output written to: {args.output_file}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()