import hashlib
import os
import mimetypes


def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def analyze_file(file_path):
    if not os.path.isfile(file_path):
        return None

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    md5, sha256 = calculate_hashes(file_path)

    file_type, _ = mimetypes.guess_type(file_path)

    return {
        "file_name": file_name,
        "file_size": file_size,
        "file_type": file_type or "Unknown",
        "md5": md5,
        "sha256": sha256
    }
