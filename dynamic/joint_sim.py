import lxml
from appium import webdriver
import time
import subprocess
import xml.etree.ElementTree as ET
import os
from appium import webdriver
import xml.etree.ElementTree as ET
from parsel import Selector
from xml.etree.ElementTree import fromstring, ElementTree, Element
import difflib

def calculate_structure_similarity(tree1, tree2):
    if tree1.tag != tree2.tag:
        return 0

    similarity = 1

    for child1, child2 in zip(tree1, tree2):
        similarity *= calculate_structure_similarity(child1, child2)
    return similarity

# 定义函数获取页面的CSS类
def get_css_classes(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    css_classes = set()

    # 遍历XML树
    for elem in root.iter():
        if 'class' in elem.attrib:
            classes = elem.attrib['class'].split()
            css_classes.update(classes)

    return css_classes

# 定义计算Jaccard相似度的函数
def jaccard_similarity(set1, set2):
    set1 = set(set1)
    set2 = set(set2)
    intersection = len(set1 & set2)

    if len(set1) == 0 and len(set2) == 0:
        return 1.0

    denominator = len(set1) + len(set2) - intersection
    return intersection / max(denominator, 0.000001)

# 第一个应用的包名和活动
appPackage1 = 'com.fingersoft.hillclimb'
appActivity1 = 'com.fingersoft.game.MainActivity'

# 第二个应用的包名和活动
appPackage2 = 'com.mezanthanah.app6'
appActivity2 = 'com.mezanthanah.app6.Main'

desired_caps = {
    "platformName": "android",
    "platformVersion": "7",
    "deviceName": "127.0.0.1:62001",
    "noReset": True
}

# 启动第一个应用
desired_caps["appPackage"] = appPackage1
desired_caps["appActivity"] = appActivity1

driver1 = webdriver.Remote("http://localhost:4723/wd/hub", desired_caps)
driver1.wait_activity(".MainActivity", 5)

# 获取第一个应用的页面源代码
html_1 = driver1.page_source

# 保存为xml文件
with open('xml1.xml', 'w', encoding='utf-8') as f:
    f.write(html_1)

# 关闭第一个应用
driver1.quit()

# 启动第二个应用
desired_caps["appPackage"] = appPackage2
desired_caps["appActivity"] = appActivity2

driver2 = webdriver.Remote("http://localhost:4723/wd/hub", desired_caps)
driver2.wait_activity(".MainActivity", 5)

# 获取第二个应用的页面源代码
html_2 = driver2.page_source
with open('xml2.xml', 'w', encoding='utf-8') as f:
    f.write(html_2)
# 关闭第二个应用
driver2.quit()

xml1 = ElementTree(fromstring(html_1))
xml2 = ElementTree(fromstring(html_2))
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

# 获得标签序列
tags1 = get_tags(xml1)
tags2 = get_tags(xml2)
# print(tags1)
# print(tags2)
diff = difflib.SequenceMatcher()
diff.set_seq1(tags1)
diff.set_seq2(tags2)
html_similarity= diff.ratio()
print(f"页面的结构相似度: {html_similarity}")

# 提取并计算CSS类的Jaccard相似度
css_classes1 = get_css_classes('../xml1.xml')
css_classes2 = get_css_classes('../xml2.xml')
css_similarity = jaccard_similarity(css_classes1, css_classes2)
print(f"CSS类的Jaccard相似度: {css_similarity}")

k=0.5
joint_similarity = k * html_similarity + (1 - k) * css_similarity
print(f"综合相似度: {joint_similarity}")
