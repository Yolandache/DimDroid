import time
import frida
import sys

packageName = "com.mezanthanah.app6"  # 请替换为目标应用程序的包名

# 连接安卓机上的frida-server
device = frida.get_usb_device()
pid = device.spawn(packageName)
device.resume(pid)
time.sleep(1)
session = device.attach(pid)

# 加载s1.js脚本
with open("show-specific-class-methods.js", "r", encoding="utf-8") as f:
    script_code = f.read()
script_code = script_code.replace("PACKAGE_NAME", packageName)
# print(script_code)

script = session.create_script(script_code)

# 定义存储方法信息的列表
method_list = []
classes_list = []

def on_message(message, data):
    print(message)
    if message['type'] == 'send':
        method_list.append(message['payload']['methods'])
        classes_list.append(message['payload']['className'])

# 注册消息处理函数
script.on('message', on_message)

# 检查脚本状态
if script.is_destroyed:
    print("[*] Script is already destroyed. Cannot load script.")
else:
    try:
        script.load()
        print("[*] Script loaded successfully.")

        # 延迟一段时间等待 Frida 脚本终止
        time.sleep(10)  # 10秒延迟

        # 终止脚本
        script.unload()
        # 输出
        print("[*] className:")
        print(classes_list)
        print("[*] methods:")
        print(method_list)
        with open("method_list.txt", "w", encoding="utf-8") as method_file:
            for _ in method_list:
                method_file.write("\n".join(_))

        # 等待一段时间确保脚本已经终止
        time.sleep(2)
    except frida.InvalidOperationError as e:
        print("[*] Error loading script:", e)
