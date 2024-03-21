import os

def apk_decompile(apk):
    apk_path = apk['apkpath']
    apktool_command = 'apktool -q d -s -f {path_apk} -o {path_save_file}'
    apk_dir = apk['output']
    apktool_command = apktool_command.format(path_apk=apk_path, path_save_file=apk_dir)
    # print(apk['title'],apk['apkpure_url'],apk_path,apktool_command)
    try:
        os.system(apktool_command + '\n')
    except Exception as e:
        print(e,apktool_command)
    # subprocess.check_output(apktool_command+' \n',shell=True)
    if os.path.exists(apk_dir):
        return apk_dir
    else:
        return 'error'

# 指定输入APK文件夹和输出目录
input_apk_folder = "D:\\fakeapp\\apps\\testapp"  # 存放需要反编译的APK文件的文件夹
output_apk_folder = r"D:\fakeapp\apps\output"
# 获取输入APK文件夹中的所有APK文件
apk_files = [os.path.join(input_apk_folder,f) for f in os.listdir(input_apk_folder) if f.endswith(".apk")]
finish_apk = [os.path.join(output_apk_folder,f) for f in os.listdir(output_apk_folder)]
print(apk_files)

# 避免访问空列表导致的错误
if finish_apk:
    print("Finished!")
else:
    print("finish_apk is empty")

# 循环处理每个APK文件
for apk_file in apk_files:
    file_name = apk_file.split('\\')[-1]
    print(file_name)
    output = os.path.join(output_apk_folder,file_name.replace('.apk',''))
    if output in finish_apk:
        print('Saved!')
        continue
    # apk_dir = apk_path.replace('.apk', '')
    # 构建APK文件的完整路径
    apk = {
        'apkpath':apk_file,
        'output':output
    }
    apk_decompile(apk)


