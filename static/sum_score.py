import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim
import traceback
from concurrent.futures import ThreadPoolExecutor
import requests
import os
import json
from tqdm import tqdm
import Levenshtein
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import difflib

def compare_images(image1_path, image2_path):
    # 读取图像
    image1 = cv2.imread(image1_path)
    image2 = cv2.imread(image2_path)
    # 将图像调整为相同大小
    target_shape = (300, 300)  # 根据需要修改大小
    image1_resized = cv2.resize(image1, target_shape)
    image2_resized = cv2.resize(image2, target_shape)
    # 将图像转换为灰度图
    gray1 = cv2.cvtColor(image1_resized, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(image2_resized, cv2.COLOR_BGR2GRAY)
    # 计算图像的结构相似性指数（SSIM）
    ssim_index, _ = ssim(gray1, gray2, full=True)
    return (ssim_index+0.2)

def compare_strings(string1, string2):
    # 计算两个名称之间的 Levenshtein 距离
    distance = Levenshtein.distance(string1.lower(), string2.lower())
    # 使用距离计算相似度分数,使用最大长度减去距离来得到相似度分数
    max_length = max(len(string1), len(string2))
    similarity_score = 1.0 - (distance / max_length)
    return similarity_score

def compare_filesize(size1, size2):
    absolute_difference = abs(size1 - size2)
    # 根据最大包大小进行标准化
    max_size = max(size1, size2)
    similarity_score = 1.0 - (absolute_difference / max_size)
    return similarity_score

def jaccard_similarity(set1, set2):
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union != 0 else 0

def compare_text(description1, description2):
    # 使用 TF-IDF 向量化文本
    vectorizer = TfidfVectorizer()
    tfidf_matrix = vectorizer.fit_transform([description1, description2])
    # 计算余弦相似度
    cosine_sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])
    return cosine_sim[0][0]

def compare_html(tags1, tags2):
    # 计算页面的结构相似度
    diff = difflib.SequenceMatcher()
    diff.set_seq1(tags1)
    diff.set_seq2(tags2)
    html_similarity = diff.ratio()
    return html_similarity

def process_methods(methods):
    for i in range(0,len(methods)):
        methods[i] = methods[i].split('(')[0].split('.')[-1]
    return methods

def calculate_static_similarity(similarity1, similarity2, similarity3, similarity4, similarity5, similarity6):
    # 先设置比例为9.9：0.06：0.01：0.01：0.01：0.01
    static_sim = (9.9 * similarity1 + 0.06 * similarity2 + 0.01 * similarity3 + 0.01 * similarity4 + 0.01 * similarity5 + 0.01 * similarity6) / (10)
    return static_sim

def calculate_dynamic_similarity(similarity1, similarity2, similarity3):
    # 先设置比例为4.5:4.5:1
    dynamic_sim = (4.5 * similarity1 + 4.5 * similarity2 + 1 * similarity3) / (10)
    return dynamic_sim

def calculate_sum_similarity(similarity1, similarity2):
    # 先设置比例为9.8:0.2
    sum_sim = (9.8 * similarity1 + 0.2 * similarity2) / (10)
    return sum_sim

if __name__ == '__main__':
    root_path = r'D:\GitProject\Fakeapp'
    apps_folder = os.path.join(root_path, 'realtest')
    for app in os.listdir(apps_folder):
        app_dir = os.path.join(apps_folder, app)
        for simapp in os.listdir(app_dir):
            simapp_dir = os.path.join(app_dir, simapp)
            # 如果不是文件而是json后缀就跳过
            if simapp.endswith('.json'):
                continue
            # 如果相似应用文件夹名和应用文件夹名相同，则icon1_path为simapp_dir下的icon.jpg，若不同则icon2_path
            if simapp == app:
                # ————————————————————图标
                icon1_path = os.path.join(simapp_dir, 'icon.jpg')
                # ————————————————————应用程序名称+包名+包大小+依赖库
                static_json_name = os.path.join(simapp_dir, 'app_info.json')
                with open(static_json_name, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                name1 = data['app_name']
                package1 = data['package']
                size1 = data['filesize']
                dependencies1 = data['dependencies']
                # ————————————————————文本描述，文本描述在”package“.json中的description，其中“package”都是刚读取的package的具体的数值
                des1_path = os.path.join(simapp_dir, package1+'.json')
                with open(des1_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                des1 = data['description']
                # ————————————————————HTML+CSS+函数
                dynamic_json_name = os.path.join(simapp_dir, 'dynamic_info.json')
                if not os.path.exists(dynamic_json_name):
                    html_similarity = None
                    css_similarity = None
                    method_similarity = None
                else:
                    with open(dynamic_json_name, 'r', encoding='utf-8') as file:
                        data = json.load(file)
                    tags1 = data['tags']
                    classes1 = data['classes']
                    #methods可能不存在，设为空
                    if 'methods' not in data.keys():
                        methods1 = []
                    else:
                        methods1 = process_methods(data['methods'])
                        methods = []
                        # 去除长度为2的方法
                        for method in methods1:
                            if len(method) > 2:
                                methods.append(method)
                        methods1 = methods
                        # print(methods1)
        for simapp in os.listdir(app_dir):
            simapp_dir = os.path.join(app_dir, simapp)
            # 如果不是文件而是json后缀就跳过
            if simapp.endswith('.json'):
                continue
            if simapp != app:
                # ————————————————————图标
                icon2_path = os.path.join(simapp_dir, 'icon.jpg')
                if not os.path.exists(icon2_path):
                    icon_similarity = None
                else:
                    icon_similarity = compare_images(icon1_path, icon2_path)
                # #创建一个app_dir下的json文件，json_name为icon_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # icon_json_path = os.path.join(app_dir, 'icon_score.json')
                # if os.path.exists(icon_json_path):
                #     with open(icon_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = icon_similarity
                # with open(icon_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed icon similarity for {app} vs {simapp}: {icon_similarity}")
                # ————————————————————应用程序名称+包名+包大小+依赖库
                static_json_name = os.path.join(simapp_dir, 'app_info.json')
                # 如果app_info.json文件不存在，设置name_similarity为Null
                if not os.path.exists(static_json_name):
                    name_similarity = None
                    package_similarity = None
                    size_similarity = None
                    depend_similarity = None
                else:
                    with open(static_json_name, 'r', encoding='utf-8') as file:
                        data = json.load(file)
                    name2 = data['app_name']
                    name_similarity = compare_strings(name1, name2)
                    package2 = data['package']
                    package_similarity = compare_strings(package1, package2)
                    size2 = data['filesize']
                    size_similarity = compare_filesize(size1, size2)
                    dependencies2 = data['dependencies']
                    depend_similarity = jaccard_similarity(set(dependencies1), set(dependencies2))
                # 创建一个app_dir下的json文件，json_name为name_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # name_json_path = os.path.join(app_dir, 'name_score.json')
                # if os.path.exists(name_json_path):
                #     with open(name_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = name_similarity
                # with open(name_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed name similarity for {app} vs {simapp}: {name_similarity}")
                # 创建一个app_dir下的json文件，json_name为package_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # package_json_path = os.path.join(app_dir, 'package_score.json')
                # if os.path.exists(package_json_path):
                #     with open(package_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = package_similarity
                # with open(package_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed package similarity for {app} vs {simapp}: {package_similarity}")
                # 创建一个app_dir下的json文件，json_name为size_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # size_json_path = os.path.join(app_dir, 'size_score.json')
                # if os.path.exists(size_json_path):
                #     with open(size_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = size_similarity
                # with open(size_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed size similarity for {app} vs {simapp}: {size_similarity}")
                # 创建一个app_dir下的json文件，json_name为depend_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # depend_json_path = os.path.join(app_dir, 'depend_score.json')
                # if os.path.exists(depend_json_path):
                #     with open(depend_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = depend_similarity
                # with open(depend_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed depend similarity for {app} vs {simapp}: {depend_similarity}")
                # ————————————————————文本描述，文本描述在”package“.json中的description，其中“package”都是刚读取的package的具体的数值
                des2_path = os.path.join(simapp_dir, package2 + '.json')
                if not os.path.exists(des2_path):
                    des_similarity = None
                else:
                    with open(des2_path, 'r', encoding='utf-8') as file:
                        data = json.load(file)
                    des2 = data['description']
                    des_similarity = compare_text(des1, des2)
                # 创建一个app_dir下的json文件，json_name为des_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # des_json_path = os.path.join(app_dir, 'des_score.json')
                # if os.path.exists(des_json_path):
                #     with open(des_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = des_similarity
                # with open(des_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed des similarity for {app} vs {simapp}: {des_similarity}")
                # ————————————————————HTML+CSS+函数
                dynamic_json_name = os.path.join(simapp_dir, 'dynamic_info.json')
                if not os.path.exists(dynamic_json_name):
                    html_similarity = None
                    css_similarity = None
                    method_similarity = None
                else:
                    with open(dynamic_json_name, 'r', encoding='utf-8') as file:
                        data = json.load(file)
                    tags2 = data['tags']
                    html_similarity = compare_html(tags1, tags2)
                    classes2 = data['classes']
                    css_similarity = jaccard_similarity(set(classes1), set(classes2))
                    # methods可能不存在，设为空
                    if 'methods' not in data.keys():
                        methods2 = []
                    else:
                        methods2 = process_methods(data['methods'])
                        methods = []
                        # 去除长度为2的方法
                        for method in methods2:
                            if len(method) > 2:
                                methods.append(method)
                        methods2 = methods
                        # print(methods1)
                    method_similarity = jaccard_similarity(set(methods1), set(methods2))
                # # 创建一个app_dir下的json文件，json_name为html_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # html_json_path = os.path.join(app_dir, 'html_score.json')
                # if os.path.exists(html_json_path):
                #     with open(html_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = html_similarity
                # with open(html_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed html similarity for {app} vs {simapp}: {html_similarity}")
                # 创建一个app_dir下的json文件，json_name为css_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # css_json_path = os.path.join(app_dir, 'css_score.json')
                # if os.path.exists(css_json_path):
                #     with open(css_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = css_similarity
                # with open(css_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed css similarity for {app} vs {simapp}: {css_similarity}")
                # 创建一个app_dir下的json文件，json_name为method_score，将相似度写入，保存为字典，key为simapp，value为相似度
                # method_json_path = os.path.join(app_dir, 'method_score.json')
                # if os.path.exists(method_json_path):
                #     with open(method_json_path, 'r', encoding='utf-8') as file:
                #         data = json.load(file)
                # else:
                #     data = {
                #         app: {}
                #     }
                # data[app][simapp] = method_similarity
                # with open(method_json_path, 'w', encoding='utf-8') as file:
                #     json.dump(data, file, indent=4)
                # print(f"Processed method similarity for {app} vs {simapp}: {method_similarity}")
                # 创建一个app_dir下的json文件，json_name为sum_score，分别计算static_score,dynamic_score,sum_score并写入，保存为字典，key为simapp，value为static_score,dynamic_score,sum_score
                sum_json_path = os.path.join(app_dir, 'sum_score.json')
                if os.path.exists(sum_json_path):
                    with open(sum_json_path, 'r', encoding='utf-8') as file:
                        alldata = json.load(file)
                else:
                    alldata = {
                        app: {
                            simapp: {
                                'static_score': 0.0,
                                'dynamic_score': 0.0,
                                'sum_score': 0.0
                            }
                        }
                    }
                # 要添加的新键值对
                new_data = {
                    simapp: {
                        'static_score': 0.0,
                        'dynamic_score': 0.0,
                        'sum_score': 0.0
                    }
                }
                alldata[app].update(new_data)
                # ————————————————————计算static_score，如果有其中一个值为Null，则static_score为Null
                if name_similarity == None or package_similarity == None or size_similarity == None or depend_similarity == None or des_similarity == None or icon_similarity == None:
                    static_score = None
                else:
                    static_score = calculate_static_similarity(icon_similarity, name_similarity, package_similarity, size_similarity, depend_similarity, des_similarity)
                alldata[app][simapp]['static_score'] = static_score
                # ————————————————————计算dynamic_score，如果有其中一个值为Null，则dynamic_score为Null
                if html_similarity == None or css_similarity == None or method_similarity == None:
                    dynamic_score = None
                else:
                    dynamic_score = calculate_dynamic_similarity(html_similarity, css_similarity, method_similarity)
                alldata[app][simapp]['dynamic_score'] = dynamic_score
                # ————————————————————计算sum_score，如果有其中一个值为Null，则sum_score为Null
                if static_score == None or dynamic_score == None:
                    sum_score = None
                else:
                    sum_score = calculate_sum_similarity(static_score, dynamic_score)
                alldata[app][simapp]['sum_score'] = sum_score
                with open(sum_json_path, 'w', encoding='utf-8') as file:
                    json.dump(alldata, file, indent=4)
                print(f"Processed sum similarity for {app} vs {simapp}: {sum_score}")

