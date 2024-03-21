import hashlib
import os
import shutil
import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from glob import glob
from tqdm import tqdm
from collections import Counter
from androguard.core.bytecodes import apk

def get_file_list(path):
    return glob(os.path.join(path, "**/*.apk"), recursive=True)

def get_apk_info(path):
    aapt_command = f'aapt2 dump badging "{path}"'
    try:
        output = subprocess.check_output(aapt_command, shell=True, stderr=subprocess.STDOUT, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        print("Error while getting APK info:", path)
        print(e.output)  # Print the error output from aapt2 command
        return None

    # 计算文件的 MD5 值
    def calculate_md5(filename):
        with open(filename, "rb") as f:
            md5 = hashlib.md5()
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
            return md5.hexdigest()

    apkf = apk.APK(path)
    apk_data = {
        'filename': os.path.basename(path),
        'filesize': os.path.getsize(path),  # 使用os模块获取文件大小
        'file_md5': calculate_md5(path),
        'cert_md5': apkf.get_signature_names()[0][1].replace(":", "").lower(),
        'cert_sha1': apkf.get_signature_names()[0][2].lower(),
        'cert_sha256': apkf.get_signature_names()[0][3].lower(),
        'cert_sha512': apkf.get_signature_names()[0][4].lower(),
        'android_version': output.splitlines()[0].split(':')[-1].strip(),
        'package': apkf.get_package(),
        'app_name': apkf.get_app_name(),
        # 'app_name_zh': apkf.get_app_name('zh'),
        'is_valid': apkf.is_valid_APK(),
        'version_code': apkf.get_androidversion_code(),
        'version_name': apkf.get_androidversion_name(),
        'max_sdk': apkf.get_max_sdk_version(),
        'min_sdk': apkf.get_min_sdk_version(),
        'target_sdk': apkf.get_target_sdk_version(),
        'main_activity': apkf.get_main_activity(),
        'signature_name': apkf.get_signature_name(),
        'signature_names': apkf.get_signature_names()
    }

    return apk_data

def main():
    apk_folder = r"D:\GitProject\Fakeapp\apps\testapp"
    output_file = "apk_info.json"

    apk_info_list = []
    for apk_file in os.listdir(apk_folder):
        if apk_file.endswith(".apk"):
            apk_path = os.path.join(apk_folder, apk_file)
            apk_info = get_apk_info(apk_path)
            if apk_info:
                apk_info_list.append(apk_info)

    with open(output_file, 'w') as f:
        json.dump(apk_info_list, f, indent=4)

    print("APK info saved to", output_file)

if __name__ == "__main__":
    main()
