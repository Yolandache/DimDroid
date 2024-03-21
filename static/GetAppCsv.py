import os
import pandas as pd
import scraper
import glob
import config
import hashlib
## 从google play获得app列表csv文件
def GetAppCsv():
    categories = scraper.category
    print(categories)
    category_list = []
    for k,v in categories.items():
        # print(k,v)
        if 'GAME' not in k:
            category_list.append(v)
    print(len(category_list),len(category_list)*200)
    for category in category_list:
        print(category)
        result = scraper.list(
            collection=None,
            category=category,
            age=None,
            num=1000,
            lang='en',
            country='us',
            fullDetail=False,
            proxylink='http://127.0.0.1:4780'
        )
        for d in result:
            del d['summary']
        ## save to csv
        df = pd.DataFrame(result)
        df.to_csv(f'{config.DATA_PATH}/category/{category}.csv',index=False)

## 合并所有csv文件
def MergeCsv():
    # 获取所有 CSV 文件的文件名
    file_names = glob.glob(f'{config.DATA_PATH}/category/*.csv')

    # 读取所有 CSV 文件，并将它们存为一个 DataFrame
    dfs = []
    for filename in file_names:
        df = pd.read_csv(filename)
        # 添加数据来源列
        df['category'] = os.path.splitext(os.path.basename(filename))[0]
        # 计算sha256值
        df['sha256'] = df['appId'].apply(lambda x: hashlib.sha256(x.encode('utf-8')).hexdigest())
        dfs.append(df)
    merged_df = pd.concat(dfs, ignore_index=True)

    # 将合并后的 DataFrame 存为 CSV 文件
    merged_df.to_csv(f'{config.DATA_PATH}/data.csv', index=False)
    merged_df.to_excel(f'{config.DATA_PATH}/data.xlsx', index=False)
    print('All CSV files merged successfully.')


## 读取合并后的csv文件并返回字典列表
def ReadCsv(csvpath):
    df = pd.read_csv(csvpath)
    # 剔除空数据
    df = df[df['download_url'].notna()]
    return df.to_dict('records')
