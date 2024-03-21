import requests
import json
import os

def scan_file(json_folder):
    # 取json_folder的最后一个文件夹名字再加上.apk
    apk_name = os.path.basename(json_folder) + '.apk'
    api = "https://www.virustotal.com/api/v3/files/upload_url"
    # No such file or directory: 'apk_name'
    if not os.path.exists(apk_name):
        print(f"{apk_name} is not found")
        #设定为'error' in content and content['error']['code'] == 'NotFoundError'
        return

    params = {
        'file': ('apk_name', open('apk_name', 'rb')),
    }

    headers = {
        "x-apikey": "8cc19f4b1fdd0abc9da632b5cb13239a9a13a4f7875f6ecfbd9b67f7b6e21e8e"
    }
    proxy = {
        "http": "http://127.0.0.1:7890",
        "https": "http://127.0.0.1:7890"
    }
    uploadUrl_response = requests.get(api, headers=headers, proxies=proxy)
    uploadUrl = uploadUrl_response.json()['data']
    response = requests.post(uploadUrl, files=params, headers=headers, proxies=proxy)
    # info
    response = requests.get(response.json()['data']['links']['self'], headers=headers, proxies=proxy)
    return response.json()

def scan_md5(file_md5, json_folder):
    url = "https://www.virustotal.com/api/v3/files/" + file_md5
    res = requests.get(url=url, headers=headers)
    content = res.json()
    print(res.json)
    if 'error' in content and content['error']['code'] == 'NotFoundError':
        content = scan_file(json_folder)
        if 'error' in content and content['error']['code'] == 'NotFoundError':
            print(f"{file_md5} is not found in VirusTotal")
            return
    b = json.dumps(content, indent=4)
    json_path = os.path.join(json_folder, 'virustotal.json')
    with open(json_path, 'w') as f:
        f.write(b)
    with open(json_path, 'r') as f:
        data = json.load(f)
    malicious_app = data['data']['attributes']['total_votes']['malicious']
    if malicious_app > 0:
        print("malicious_app:", malicious_app)

    androguard_data = data['data']['attributes'].get('androguard')

    if androguard_data is not None and isinstance(androguard_data, dict):
        permission_details = androguard_data.get('permission_details')

        if permission_details is not None and isinstance(permission_details, dict):
            status = []
            for k, v in permission_details.items():
                status.append(v.get("permission_type", ""))
                if v.get("permission_type", "") == "dangerous":
                    print(k, v.get("permission_type", ""))
            print("dangerous_permission:", status.count("dangerous"))
        else:
            print("Permission details not found or not a valid dictionary in the response.")
            return
    else:
        print("Androguard data not found or not a valid dictionary in the response.")
        return

    status = []
    for k, v in permission_details.items():
        status.append(v["permission_type"])
        if v["permission_type"] == "dangerous":
            print(k, v["permission_type"])

    print("dangerous_permission:", status.count("dangerous"))

if __name__ == '__main__':
    API = "8cc19f4b1fdd0abc9da632b5cb13239a9a13a4f7875f6ecfbd9b67f7b6e21e8e"
    headers = {
        'x-apikey': API,
        'Host': 'www.virustotal.com',
        'range': 'bytes=equest',
        'user-agent': 'curl/7.68.0',
        'accept': '*/*'
    }
    # count = 0
    root_path = r'D:\GitProject\Fakeapp'
    apps_folder = os.path.join(root_path, 'top10fake')
    for app in os.listdir(apps_folder):
        app_dir = os.path.join(apps_folder, app)
        for simapp in os.listdir(app_dir):
            if simapp.endswith('.json'):
                continue
            simapp_dir = os.path.join(app_dir, simapp)
            json_name = os.path.join(simapp_dir, 'app_info.json')
            # md5是读取appinfo.json里面的file_md5
            with open(json_name, 'r', encoding='utf-8') as file:
                data = json.load(file)
            file_md5 = data['file_md5']
            scan_md5(file_md5, simapp_dir)
            # count += 1
            # print("app_number:", count)
