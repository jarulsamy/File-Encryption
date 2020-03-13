# -*- coding: utf-8 -*-
import glob
from pathlib import Path

from cryptography.fernet import Fernet
from PyInquirer import prompt
from PyInquirer import style_from_dict
from PyInquirer import Token
from PyInquirer import ValidationError
from PyInquirer import Validator


class FolderValidator(Validator):
    def validate(self, document):
        """
        Ensure a path is valid pointing to a folder.
        """
        f = Path(document.text)
        if not f.is_dir():
            raise ValidationError(
                message="Please enter a valid folder path.",
                cursor_position=len(document.text),
            )


class FileValidator(Validator):
    def validate(self, document):
        """
        Ensure a path is valid and pointing to a file.
        """
        f = Path(document.text)
        if document.text == "":
            return
        elif not f.is_file():
            raise ValidationError(
                message="Please enter a valid key file path.",
                cursor_position=len(document.text),
            )


def generate_key(save_filename="key.txt"):
    """
    Generate and return a new encryption key.

    Args:
        param1: Filename to save key as

    Returns:
        A Fernet key object.
    """
    print("Generating key... ", end="")
    key = Fernet.generate_key()
    with open(save_filename, "w+") as f:
        f.writelines(key.decode("utf-8"))
    print(f"Done, saved key as '{save_filename}'")
    return key


def read_key(filename):
    """
    Read a Fernet key from disk.

    Args:
        param1: Filename to key.

    Returns:
        A Fernet key object.
    """
    with open(filename, "r") as f:
        key = f.read()
    return Fernet(key)


def encrypt(folder, key, ext=".txt"):
    """
    Recurisively encrypts all files matching the ext in a directory.

    Args:
        param1: Path to folder to encrypt.
        param2: Fernet key object to use for encryption.
        param3: Extension of files to match against.
    """
    glob_pattern = str(Path(folder, "*" + ext))
    files = glob.glob(glob_pattern, recursive=True)
    for filename in files:
        try:
            with open(filename, "rb") as f:
                data = f.read()
                encrypted_data = key.encrypt(data)
            with open(filename, "wb") as f:
                f.write(encrypted_data)
            print(f"Encrypted '{filename}'")
        except OSError:
            print(f"Couldn't encrypt {filename}")


def decrypt(folder, key, ext=".txt"):
    """
    Recurisively decrypts all files matching the ext in a directory.

    Args:
        param1: Path to folder to decrypt.
        param2: Fernet key object to use for decryption.
        param3: Extension of files to match against.
    """
    glob_pattern = str(Path(folder, "*" + ext))
    files = glob.glob(glob_pattern, recursive=True)
    for filename in files:
        try:
            with open(filename, "rb") as f:
                data = f.read()
                decrypted_data = key.decrypt(data)
            with open(filename, "wb") as f:
                f.write(decrypted_data)
            print(f"Decrypted '{filename}'")
        except OSError:
            print(f"Couldn't decrypt {filename}")


def main():
    """
    Prompt the user to enter all the necessary
    attributes to encrypt/decrypt a directory.
    """

    # Set a custom style of the UI.
    # This is just settings visual color parameters
    # using html color codes.
    style = style_from_dict(
        {
            Token.Separator: "#cc5454",
            Token.QuestionMark: "#673ab7 bold",
            Token.Selected: "#cc5454",
            Token.Pointer: "#673ab7 bold",
            Token.Instruction: "",
            Token.Answer: "#ff6600 bold",
            Token.Question: "",
        }
    )

    # File extensions to use as options to the user.
    file_exts = [".txt", ".pdf", ".docx", ".png"]
    # Format each items to be compatible with PyInquirer, dict-comprehension.
    file_exts = [{"name": i} for i in file_exts]
    # Select the first entry as a default.
    file_exts[0]["checked"] = True

    # dict translating answers to functions.
    operations = {"Encrypt": encrypt, "Decrypt": decrypt}

    # Create and format the questions.
    questions = [
        {
            "type": "input",
            "name": "key_filename",
            "message": "Enter key filename (Blank to generate a new one):",
            "validate": FileValidator,
        },
        {
            "type": "input",
            "name": "folder",
            "message": "Enter folder to encrypt/decrypt:",
            "validate": FolderValidator,
        },
        {
            "type": "list",
            "name": "operation",
            "message": "What do you want to do?",
            "choices": ["Encrypt", "Decrypt"],
        },
        {
            "type": "checkbox",
            "name": "file_ext",
            "message": "Which file's do you want to encrypt/decrypt?",
            "choices": file_exts,
        },
    ]

    print("This script encrypts and decrypts files in bulk based on extension.")
    print("Use the same key to decrypt as you use to encrypt.")

    # Prompt the user to answer the previously created questions.
    answers = prompt(questions, style=style)

    # Gen a new key if one is not specified
    if not answers["key_filename"]:
        key = generate_key()
    else:
        key = read_key(answers["key_filename"])

    # Grab the right function based on the user input.
    func = operations[answers["operation"]]
    for i in answers["file_ext"]:
        # Call the appropiate function.
        func(answers["folder"], key, i)

    print("Done.")


if __name__ == "__main__":
    main()
