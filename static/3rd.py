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

if __name__ == '__main__':
    root_path = r'D:\GitProject\Fakeapp\top10fake'
    # apps_folder = os.path.join(root_path, 'fakeapp')
    # output_folder = os.path.join(root_path, 'output')
    # output_file = "3rd.json"
    apk_info_list = []
    app_list = []
    for apk_file in os.listdir(root_path):
        category = apk_file
        category_apk = os.path.join(root_path, category)
        for simdir in os.listdir(category_apk):
            simapp_path = os.path.join(category_apk, simdir)
            if simdir.endswith(".json"):
                continue
            for simapp in os.listdir(simapp_path):
                # 如果是app_info.json
                if simapp == "app_info.json":
                    apk_path = os.path.join(simapp_path, simapp)
                    app_list.append(apk_path)
                    with open(apk_path, 'r', encoding='utf-8') as file:
                        data = json.load(file)
                    dependencies = data['dependencies']
                    so_details = []
                    for sofile in dependencies:
                        url = 'https://gitlab.com/zhaobozhen/LibChecker-Rules/-/raw/master/native-libs/%s.json' % sofile
                        resp = requests.get(url, proxies={'http': 'http://127.0.0.1:7890', 'https': 'http://127.0.0.1:7890'})
                        if resp.status_code == 200:
                            so_details.append(resp.json())
                    data['soDetails'] = so_details
                    print(apk_path)
                    print(data['soDetails'])
                    # 存入app_info.json并打印出来
                    with open(apk_path, 'w', encoding='utf-8') as file:
                        json.dump(data, file, indent=4)