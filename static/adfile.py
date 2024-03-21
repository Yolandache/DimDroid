import os
import shutil
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from glob import glob
from tqdm import tqdm
from collections import Counter
import openpyxl

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

def process_apk(apk_file, tracker_info):
    try:
        apk_data = extract_dependencies(apk_file)

        # Count of types found in the APK
        type_count = {'Advertising': 0, 'Analytics': 0, 'Utilities': 0}

        for tracker_row in tracker_info:
            tracker_name = tracker_row['Tracker']
            apk_name = os.path.basename(apk_file)

            if tracker_name.lower() in apk_name.lower():
                tracker_type = tracker_row['Type']
                if tracker_type == 'Advertising':
                    type_count['Advertising'] += 1
                elif tracker_type == 'Analytics':
                    type_count['Analytics'] += 1
                elif tracker_type == 'Utilities':
                    type_count['Utilities'] += 1

        # Add type count to the result
        apk_data['type_count'] = type_count

        return apk_data
    except Exception as e:
        print("Error while processing:", apk_file)
        print(e)  # Print the exception message
        return None

def read_json_file(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data

def read_tracker_list(tracker_list_file):
    # Read tracker list from Excel file using openpyxl
    wb = openpyxl.load_workbook(tracker_list_file)
    ws = wb.active
    tracker_info = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        tracker_info.append({
            'ID': row[0],
            'Tracker': row[1],
            'Company name': row[2],
            'Website': row[3],
            'Type': row[4]
        })
    return tracker_info

if __name__ == '__main__':
    tracker_list_file = r"D:\GitProject\Fakeapp\Tracker_List.xlsx"
    tracker_info = read_tracker_list(tracker_list_file)

    output_file = "apk_types_count.json"
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
            for result in executor.map(process_apk, file_list, [tracker_info] * len(file_list)):
                if result is not None:  # Filter out None results (failed APK processing)
                    results.append(result)
                pbar.update()

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)

    print("Process completed. Results written to", output_file)

    # Output each APK's type count
    print("APK Type Counts:")
    for apk_data in results:
        apk_name = os.path.basename(apk_data['file_path'])
        type_count = apk_data['type_count']
        print(f"APK: {apk_name}")
        print(f"Advertising: {type_count['Advertising']}")
        print(f"Analytics: {type_count['Analytics']}")
        print(f"Utilities: {type_count['Utilities']}")
        print("------------------------------")