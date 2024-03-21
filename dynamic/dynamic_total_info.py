import lxml
import time
import subprocess
import xml.etree.ElementTree as ET
import os
from appium import webdriver
from parsel import Selector
from xml.etree.ElementTree import fromstring, ElementTree, Element
import difflib
import frida
import sys
import json

# 定义函数获取页面的CSS类
def get_css_classes(xmlstring):
    tree = ET.ElementTree(ET.fromstring(xmlstring))
    root = tree.getroot()
    css_classes = set()
    # 遍历XML树
    for elem in root.iter():
        if 'class' in elem.attrib:
            classes = elem.attrib['class'].split()
            css_classes.update(classes)
    return css_classes

def get_tags(doc):
    tags = []
    for el in doc.getroot().iter():
        if isinstance(el, Element):
            tags.append(el.tag)
        else:
            # 如果遇到注释等其他类型的节点，可以根据需要处理
            # 这里抛出一个错误作为示例
            raise ValueError('Don\'t know what to do with element: {}'.format(el))
    return tags

def on_message(message, data):
    # print("message:",message)
    if message['type'] == 'send':
        if len(message['payload']) > 0:
            methods.append(message['payload'])
        # classes_list.append(message['payload']['className'])

def runApp(appPackage, appActivity, simapp_path, simapp):
    # Appium配置
    desired_caps = {
        "platformName": "android",  # 系统平台名称，大小写均可
        "platformVersion": "7",  # 系统版本，精确至大版本即可
        "deviceName": "127.0.0.1:52001",  # 设备名称，在windows中可任意，在Mac中须严格
        "appPackage": appPackage,  # 在打开时将从底层开启一个全新的应用，无登录状态
        "appActivity": appActivity,
        "noReset": True  # 不重置应用
    }
    # 安装应用程序
    app_path = os.path.join(simapp_path, simapp)
    print("app_path:", app_path)
    subprocess.call(['adb', 'install', app_path])
    # 变量名自定义
    # appium_server_url = 'http://127.0.0.1:4723/wd/hub'
    # driver = webdriver.Remote(appium_server_url, desired_caps)
    # driver = webdriver.Remote("http://localhost:4723/wd/hub", desired_caps)
    # driver.wait_activity(".MainActivity", 5)
    # 异常处理，如果应用程序安装失败，返回该失败日志，并继续执行下一个应用程序
    try:
        driver = webdriver.Remote("http://localhost:4723/wd/hub", desired_caps)
        driver.wait_activity(".MainActivity", 5)
    except Exception as e:
        print("Exception:", e)
        with open('app_start_error_log.txt', 'a') as log_file:
            log_file.write(f"Error starting {appPackage}: {str(e)}\n")
        return
    # 获取第一个应用的页面源代码
    html = driver.page_source
    info = ElementTree(fromstring(html))  # 从字符串中解析XML，返回根节点
    tags = get_tags(info)
    classes = get_css_classes(html)
    print("Processing appPackage:", appPackage)
    json_path = os.path.join(simapp_path, 'dynamic_info.json')
    # print("json_path:", json_path)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"tags": tags, "classes": list(classes)}, f, indent=4)
    # print(f"tags: {tags}")
    # print(f"classes:{classes}")
    # 关闭第一个应用
    driver.quit()
    # x = input('..')

    # 连接安卓机上的frida-server
    device = frida.get_usb_device()
    # pid = device.spawn(appPackage)
    pid = device.spawn(appPackage, timeout=10)
    device.resume(pid)
    time.sleep(1)
    session = device.attach(pid)
    # 加载js脚本
    with open("show-main-class-methods.js", "r", encoding="utf-8") as f:
        script_code = f.read()
    script_code = script_code.replace("MAIN_ACTIVITY", appActivity)
    script = session.create_script(script_code)
    # print(script_code)
    # 注册消息处理函数
    script.on('message', on_message)
    # time.sleep(4)
    # 检查脚本状态
    if script.is_destroyed:
        print("[*] Script is already destroyed. Cannot load script.")
    else:
        try:
            script.load()
            print("[*] Script loaded successfully.")
            # 延迟一段时间等待 Frida 脚本终止
            time.sleep(6)  # 10秒延迟
            # 终止脚本
            script.unload()
            # 输出
            print("[*] methods saved successfully.")
            # print(method_list)
            # 从json文件中读取数据
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # 将 "methods" 添加到读取的数据中
            data["methods"] = methods[0]
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            # with open("info.txt", "w", encoding="utf-8") as method_file:
            #     for _ in method_list:
            #         method_file.write("\n".join(_))
            # 等待一段时间确保脚本已经终止
            # time.sleep(2)
        except frida.InvalidOperationError as e:
            print("[*] Error loading script:", e)
        finally:
            # 卸载app
            subprocess.call(['adb', 'uninstall', appPackage])

if __name__ == '__main__':
    methods = []
    root_path = r'D:\GitProject\Fakeapp\top10'
    output_file = "dynamic_info.json"
    apk_info_list = []
    app_list = []
    for apk_file in os.listdir(root_path):
        category = apk_file
        category_apk = os.path.join(root_path, category)
        for simdir in os.listdir(category_apk):
            simapp_path = os.path.join(category_apk, simdir)
            # print(simapp_path)
            for simapp in os.listdir(simapp_path):
                # 如果存在dynamic_info.json文件，则跳过
                if simapp.endswith(".apk"):
                    #取出appinfo.json里面的package和main_activity
                    if os.path.exists(os.path.join(simapp_path, "dynamic_info.json")):
                        print("dynamic_info.json exists, skip", simapp_path)
                        continue
                    else:
                        with open(os.path.join(simapp_path, "app_info.json"), 'r', encoding='utf-8') as f:
                            app_info = json.load(f)
                            appPackage = app_info['package']
                            appActivity = app_info['main_activity']
                            runApp(appPackage, appActivity, simapp_path, simapp)