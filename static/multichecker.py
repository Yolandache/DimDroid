from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import requests
import cloudscraper
from bs4 import BeautifulSoup
import re
from fake_useragent import UserAgent
from lxml import etree
from tqdm.auto import tqdm

ua = UserAgent()
BASE_URL = 'https://apkpure.com'
API_URL = 'https://apkpure.com/api/www/cmd-down'
DOWNLOADER_URL = 'https://apkpure.com/apk-downloader'


class Spider(object):
    def __init__(self):
        self.session = requests.session()
        self.session.headers = {
            'User-Agent': ua.chrome,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'authority': 'apkpure.com'
        }
        self.proxy = 'http://127.0.0.1:7890'
        self.session.proxies = {
            "http": self.proxy,
            "https": self.proxy,
        }
        self.scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'android',
                'desktop': False
            },
            sess=self.session,
            delay=10
        )

    def get_detail_link(self, app):
        package = app['appId']
        resp = self.scraper.get(DOWNLOADER_URL)
        soup = BeautifulSoup(resp.content, 'lxml')
        _csrf = soup.select('div.search-input')[1].get('data-csrf')
        data = {
            'package': package,
            '_csrf': _csrf,
            'region': 'US'
        }
        resp = self.scraper.post(API_URL, json=data)
        if 'url' in resp.json():
            return resp.json()['url']
        else:
            return None

    def crawl(self, app):
        try:
            app_end_url = self.get_detail_link(app)
            if app_end_url is None:
                return app
            app_url = BASE_URL + app_end_url + '/download'
            req = self.scraper.get(app_url)
            resp = etree.HTML(req.text)
            app_name = resp.xpath('//h1[@class="info-title"]//text()')[0]
            dev = resp.xpath('//span[@class="info-sdk"]//text()')
            dev = ' '.join(dev).strip()
            download_url = f'https://d.apkpure.com/b/APK/{app["appId"]}?version=latest'
            update = resp.xpath('//span[@class="info-other"]/span//text()')[0]
            req_android = resp.xpath('//div[@class="more-info"]/ul/li[3]/div[@class="info"]/div[2]//text()')
            req_android = ' '.join(req_android)
            size = resp.xpath('//span[@class="download-file-size"]//text()')[0].strip()
            match_size = re.search(r'\((.*?)\)', size).group(1)
            icon = resp.xpath('//img[@class="icon"]//@src')[0]
            data = {
                'app_name': app_name,
                'dev': dev,
                'download_url': download_url,
                'update': update,
                'req_android': req_android,
                'size': match_size,
                'icon': icon,
                'alive': True
            }
            app.update(data)
            return app
        except Exception as e:
            return app

if __name__ == '__main__':
    spider = Spider()
    chunksize = 10000
    for i, df_chunk in enumerate(pd.read_csv('apkdata.csv', chunksize=chunksize)):
        filename = f'data/apkdata_{i}.csv'
        apps = []
        for index, row in df_chunk.iterrows():
            app = {
                'appId': row['pkg_name'],
                'size': row['size'],
                'alive': False
            }
            apps.append(app)
        apps_details = []
        with ThreadPoolExecutor(max_workers=16) as executor:
            for app in tqdm(executor.map(spider.crawl, apps), total=len(apps)):
                if app is not None:
                    apps_details.append(app)
        df = pd.DataFrame(apps_details)
        df.to_csv(filename, index=False)
        print(f'Finish {filename}')
