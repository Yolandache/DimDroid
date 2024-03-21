import os
import json
import requests

if __name__ == '__main__':
    root_path = r'D:\GitProject\Fakeapp'
    apps_folder = os.path.join(root_path, 'apps')
    so_details = []
    for app in os.listdir(apps_folder):
        app_dir = os.path.join(apps_folder, app)
        for simapp in os.listdir(app_dir):
            simapp_dir = os.path.join(app_dir, simapp)
            print("Processing:",simapp_dir)
            json_name = os.path.join(simapp_dir, 'app_info.json')
            with open(json_name, 'r', encoding='utf-8') as file:
                data = json.load(file)
            #获取appinfo.json里面的dependencies列表
            dependencies = data['dependencies']
            for sofile in dependencies:
                url = 'https://gitlab.com/zhaobozhen/LibChecker-Rules/-/raw/master/native-libs/%s.json' % sofile
                resp = requests.get(url, proxies={'http': 'http://127.0.0.1:7890', 'https': 'http://127.0.0.1:7890'})
                if resp.status_code == 200:
                    so_details.append(resp.json())
            data['soDetails'] = so_details
            #将soDetails写入appinfo.json
            with open(json_name, 'w') as f:
                json.dump(data, f, indent=4)