import traceback
from concurrent.futures import ThreadPoolExecutor
import requests
import os
import json
from tqdm import tqdm

if __name__ == '__main__':
    root_path = r'D:\GitProject\Fakeapp'
    apps_folder = os.path.join(root_path, 'test')
    for app in os.listdir(apps_folder):
        app_dir = os.path.join(apps_folder, app)
        for simapp in os.listdir(app_dir):
            simapp_dir = os.path.join(app_dir, simapp)
            json_name = simapp_dir.split('\\')[-1].replace('-', '.') + '.json'
            print("Processing json_name:",json_name)
            json_path = os.path.join(simapp_dir, json_name)
            # print(json_path)
            with open(json_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            icon_url = data['icon']
            resp = requests.get(icon_url)
            # 存取图片
            with open(os.path.join(simapp_dir, 'icon.jpg'), 'wb') as f:
                f.write(resp.content)