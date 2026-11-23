import hashlib
import os
import string
import random


def compute_sha256(file_data):
    return hashlib.sha256(file_data).hexdigest()


def validate_mz_header(file_data):
    return len(file_data) >= 2 and file_data[0:2] == b"\x4d\x5a"


def generate_job_id(length=12):
    charset = string.ascii_letters + string.digits
    return "".join(random.choices(charset, k=length))


def save_sample(file_data, sha256, upload_folder):
    file_path = os.path.join(upload_folder, sha256)
    with open(file_path, "wb") as f:
        f.write(file_data)
    return file_path
