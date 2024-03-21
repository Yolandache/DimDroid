import hashlib
import os
import shutil
import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from glob import glob

import requests
from tqdm import tqdm
from collections import Counter
from androguard.core.bytecodes import apk
import os
import shutil
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from glob import glob
from tqdm import tqdm
from collections import Counter
import traceback

def get_file_list(path):
    return glob(os.path.join(path, "**/*.apk"), recursive=True)

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

def get_apk_info(path):
    try:
        apkf = apk.APK(path)
        apk_data = {
            'filename': os.path.basename(path),
            'filesize': os.path.getsize(path),  # 使用os模块获取文件大小
            'file_md5': calculate_md5(path),
            'package': apkf.get_package(),
            'app_name': apkf.get_app_name(),
            'main_activity': apkf.get_main_activity(),
            'is_valid': str(apkf.is_valid_APK()),
            # 'app_name_zh': apkf.get_app_name('zh'),
            # 'version_code': apkf.get_androidversion_code(),
            # 'version_name': apkf.get_androidversion_name(),
            # 'max_sdk': apkf.get_max_sdk_version(),
            # 'min_sdk': apkf.get_min_sdk_version(),
            # 'target_sdk': apkf.get_target_sdk_version(),
            # 'cert_md5': apkf.get_signature_names()[0][1].replace(":", "").lower(),
            # 'cert_sha1': apkf.get_signature_names()[0][2].lower(),
            # 'cert_sha256': apkf.get_signature_names()[0][3].lower(),
            # 'cert_sha512': apkf.get_signature_names()[0][4].lower(),
            # 'signature_name': apkf.get_signature_name(),
            # 'signature_names': apkf.get_signature_names()
            # 'android_version': output.splitlines()[0].split(':')[-1].strip(),
        }
        return apk_data
    except Exception as e:
        print("Error while getting APK info:", path)
        return None
    # aapt_command = f'aapt dump badging "{path}"'
    # try:
    #     output = subprocess.check_output(aapt_command, shell=True, stderr=subprocess.STDOUT, encoding='utf-8')
    # except subprocess.CalledProcessError as e:
    #     print("Error while getting APK info:", path)
    #     print(e.output)  # Print the error output from aapt2 command
    #     return None

def info_extract(apk_file):
    # print("Extracting info from APK:", apk_file)
    apktool_command = 'apktool -q d -s -f {path_apk} -o {path_save_file}'
    temp_folder = apk_file['apk_path'].replace('.apk', '') + '_temp'
    # print(temp_folder)
    apktool_command = apktool_command.format(path_apk=apk_file['apk_path'], path_save_file=temp_folder)
    permissions = get_permission(apk_file['apk_path'])
    apk = apk_file
    apk['dependencies'] = []
    apk['permissions'] =[]
    apk['permissions'].extend(permissions)
    try:
        os.system(apktool_command + '\n')
    except Exception as e:
        print("Error",e)
        return apk
    try:
        if os.path.exists(temp_folder):
            lib_folder = os.path.join(temp_folder, "lib")
            for root, dirs, files in os.walk(lib_folder):
                for file in files:
                    if file.endswith(".so"):
                        apk['dependencies'].append(file)
            shutil.rmtree(temp_folder, ignore_errors=True)
            # so_details = []
            # for sofile in apk['dependencies']:
            #     url = 'https://gitlab.com/zhaobozhen/LibChecker-Rules/-/raw/master/native-libs/%s.json' % sofile
            #     resp = requests.get(url, proxies={'http': 'http://127.0.0.1:7890', 'https': 'http://127.0.0.1:7890'})
            #     if resp.status_code == 200:
            #         so_details.append(resp.json())
            # apk['soDetails'] = so_details

        return apk
    except Exception as e:
        return apk

def get_permission(apk_path):
    # 构造命令行参数
    aapt_cmd = ['aapt', 'd', 'permissions', apk_path]

    # 调用aapt命令，并捕获输出结果
    output = subprocess.check_output(aapt_cmd, universal_newlines=True).splitlines()

    # 解析输出结果，获取权限列表
    package = output[0].split(': ')[1]
    permissions = []
    for line in output[1:]:
        permission = line.split(': ')[1]
        if permission not in permissions:
            permissions.append(permission)
    return permissions

def process_apk(apk_file):
    try:
        apk_data = info_extract(apk_file)
        # 输出正在处理的apk文件名
        print("Processing APK:", apk_file['apk_path'])
        # print("apk_data",apk_data)
        # apk_file['apk_path'] 获得apk的父目录
        path = os.path.dirname(apk_file['apk_path'])
        json_path = os.path.join(path, 'app_info.json')
        with open(json_path, 'w') as f:
            json.dump(apk_data, f, indent=4)
        return apk_data
    except Exception as e:
        print(e)
        traceback.print_exc()
        return None

if __name__ == '__main__':
    root_path = r'D:\GitProject\Fakeapp\realtest'
    # apps_folder = os.path.join(root_path, 'fakeapp')
    # output_folder = os.path.join(root_path, 'output')
    output_file = "app_total_info.json"
    apk_info_list = []
    app_list = []
    for apk_file in os.listdir(root_path):
        category = apk_file
        category_apk = os.path.join(root_path, category)
        for simdir in os.listdir(category_apk):
            simapp_path = os.path.join(category_apk, simdir)
            for simapp in os.listdir(simapp_path):
                if simapp.endswith(".apk"):
                    apk_path = os.path.join(simapp_path, simapp)
                    app_list.append(apk_path)
    print(len(app_list))
    # 改为多进程，保存到json文件，错误文件保存到error.txt
    results = []
    errors = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for apk_data in tqdm(executor.map(get_apk_info, app_list), total=len(app_list)):
            if apk_data:
                results.append(apk_data)
            else:
                errors.append(apk_data)

    with open('process-v1.json', 'w') as f:
        json.dump(results, f, indent=4)
    with open("error.txt", 'w') as f:
        json.dump(errors, f, indent=4)