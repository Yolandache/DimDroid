import os
import shutil
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from glob import glob
from tqdm import tqdm
from collections import Counter

def get_file_list(path):
    return glob(os.path.join(path, "**/*.apk"), recursive=True)

def extract_dependencies(apk_file):
    apktool_command = 'apktool -q d -s -f {path_apk} -o {path_save_file}'
    temp_folder = 'temp_' + os.path.basename(apk_file)
    apktool_command = apktool_command.format(path_apk=apk_file, path_save_file=temp_folder)
    apk = {
        'file_path': apk_file,
        'dependencies': []
    }
    try:
        os.system(apktool_command + '\n')
    except Exception as e:
        return apk
    try:
        if os.path.exists(temp_folder):
            lib_folder = os.path.join(temp_folder, "lib")
            for root, dirs, files in os.walk(lib_folder):
                for file in files:
                    if file.endswith(".so"):
                        apk['dependencies'].append(file)
            shutil.rmtree(temp_folder, ignore_errors=True)
        return apk
    except:
        return apk

def process_apk(apk_file):
    try:
        apk_data = extract_dependencies(apk_file)
        return apk_data
    except Exception as e:
        print("Error while processing:", apk_file)
        print(e)  # Print the exception message
        return None

def read_json_file(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data

def count_occurrences(lst):
    count_dict = Counter(lst)
    return count_dict
if __name__ == '__main__':
    output_file = "normal_data.json"
    path = r"D:\fakeapp\apps"
    file_list = get_file_list(path)
    # Filter APKs based on file size
    file_list = [apk for apk in file_list if os.path.getsize(apk) >= 1024 * 1024]
    print(len(file_list))
    # Process APKs using ThreadPoolExecutor for better I/O performance
    with ThreadPoolExecutor(max_workers=1) as executor:
        results = []
        # Use tqdm to create a progress bar
        with tqdm(total=len(file_list), desc="Processing APKs") as pbar:
            for result in executor.map(process_apk, file_list):
                if result is not None:  # Filter out None results (failed APK processing)
                    results.append(result)
                pbar.update()

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)

    print("Process completed. Results written to", output_file)


    output_file = "normal_data.json"
    data = read_json_file(output_file)
    so_data = []
    for _ in data:
        if len(_['dependencies']) != 0:
            so_data.append(_)
    all_list = []
    for _ in so_data:
        all_list.append(_['dependencies'])
    print(len(all_list))
    all_list = [item for sublist in all_list for item in sublist]
    total_count = len(all_list)
    result = count_occurrences(all_list)
    # print(result)
    # 输出出现次数最高的前10个
    most_common_items = result.most_common(20)
    print("出现次数最高的前20个:")
    # 输出结果
    for item, count in most_common_items:
        percentage = (count / total_count) * 100
        print(f"{item}: {count} times ({percentage:.2f}%)")
