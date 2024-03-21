import datetime
import time

# 美国3 gia
# from GetAppCsv import ReadCsv
import requests
import cloudscraper
from bs4 import BeautifulSoup
import re
from humanfriendly import format_size
import pathlib
import os
from tqdm.auto import tqdm
import config
from fake_useragent import UserAgent
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
        # 可以改为国外代理US
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

    def change_proxy(self,num):
        if num < 1:
            self.scraper.headers['User-Agent'] = ua.chrome
            # pass
        else:
            url = 'http://dev.qydailiip.com/api/?apikey=17d0f9137a9d44df6c848cd6809d102bb6a69643&num=1&type=text&line=win&proxy_type=putong&sort=1&model=all&protocol=http&address=美国&kill_address=&port=&kill_port=&today=false&abroad=2&isp=&anonymity=2'
            resp = requests.get(url)
            # 重新设置代理
            self.proxy = 'http://' + resp.text
            self.scraper = cloudscraper.create_scraper(
                browser={
                    'browser': 'chrome',
                    'platform': 'android',
                    'desktop': False
                },
                sess=self.session,
                delay=10,
                proxies={
                    "http": self.proxy,
                    "https": self.proxy,
                }
            )
            print('Change a new proxy',self.scraper.proxies,self.scraper.headers)

    # 获得每个apk的详情页面链接
    def get_detail_link(self,app):
        package = app['appId']
        resp = self.scraper.get(DOWNLOADER_URL)
        soup = BeautifulSoup(resp.content, 'lxml')
        # 找到div标签中的data-csrf属性
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


    # 爬取每个app的信息
    def parse_app_page(self, app):
        data = {
            'version': None,
            'update': None,
            'requirement': None,
            'size': None,
            'apkpure_url': None,
            'download_url': None,
        }
        # 构造detail链接
        app_end_url = self.get_detail_link(app)
        # 不存在该app
        if app_end_url is None:
            app.update(data)
            return app
        app_url = BASE_URL + app_end_url
        resp = self.scraper.get(app_url)
        soup = BeautifulSoup(resp.content, 'lxml')
        info = soup.select_one('div.additional')
        if info is None:
            return app
        version = info.find(string=re.compile('Latest Version')).find_next('p').text.strip()

        # 大小
        try:
            size = soup.select_one('div.ny-down')['data-dt-filesize']
        except:
            size = soup.select_one('a[data-dt-file_size]')['data-dt-file_size']
        # 字节数转换为易读的文件大小格式
        # size = format_size(int(size))
        update = info.find(string=re.compile('Updated on')).find_next('p').text.strip()
        req_android = info.find(string=re.compile('Requires Android')).find_next('p').text.strip()
        package_name = [i for i in resp.url.split('/') if i][-1]
        download_url = f'https://d.apkpure.com/b/APK/{package_name}?version=latest'
        data = {
            'version': version,
            'update': update,
            'requirement': req_android,
            'size': size,
            'apkpure_url': app_url,
            'download_url': download_url,
        }
        app.update(data)
        return app

    def page_to_csv(self,app):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                app = self.parse_app_page(app)
                print(app)
                return app
            except Exception as e:
                print(app['appId'],e)
                self.change_proxy(attempt)
                continue

    def download(self,app):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                r = self.scraper.get(app['download_url'], stream=True)
                fname = str(app['sha256']) + '.apk'
                path = pathlib.Path(f'{config.ROOT_PATH}/apks/apps/{app["category"]}/')
                # path = pathlib.Path(f'{config.ROOT_PATH}/apks/newapps/')
                # change!! dont delete
                # path = pathlib.Path(f'{config.ROOT_PATH}/apps/{app["category"]}/')
                path.mkdir(mode=os.O_WRONLY, parents=True, exist_ok=True)
                f = path / fname
                with tqdm.wrapattr(
                        f.open("wb"), "write",
                        desc=f"{app['title']} ({fname.split('.')[0]})",
                        unit='B', unit_scale=True, unit_divisor=1024, miniters=1,
                        total=int(r.headers.get('content-length', 0))
                ) as fout:
                    for chunk in r.iter_content(chunk_size=4096):
                        if not chunk:
                            break
                        fout.write(chunk)
                app['apkpath'] = f'{config.ROOT_PATH}/apps/{app["category"]}/{fname}'
                # app['apkpath'] = f'{config.ROOT_PATH}/apks/newapps/{fname}'
                return app
            except Exception as e:
                print(f"Error during crawl attempt {attempt + 1}: {e} {app['download_url']}")
                if attempt < max_retries - 1:
                    print("Retrying...")
                    time.sleep(3)
                    # self.change_proxy(attempt)
                else:
                    print("Failed after 3 attempts. Giving up.", app['download_url'])
                    # 错误文件记录
                    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    with open('error.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{now},{app['appId']},{app['download_url']}\n")
                    return None

    def crawl(self, app):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # 构造detail链接
                app_end_url = self.get_detail_link(app)
                # 不存在该app
                if app_end_url is None:
                    break
                app_url = BASE_URL + app_end_url
                # print(app_url)
                req = self.scraper.get(app_url)
                soup = BeautifulSoup(req.content, 'lxml')
                info = soup.select_one('div.additional')
                # try:
                #     app_name = soup.select_one('div.title-like').text.strip()
                # except AttributeError:
                #     app_name = soup.select_one('div.title_link').h1.text.strip()

                version = info.find(string=re.compile('Latest Version')).find_next('p').text.strip()
                print(app_url,version)
                print(soup.select_one('a[data-dt-file_size]')['data-dt-file_size'])
                try:
                    size = soup.select_one('div.ny-down')['data-dt-filesize']
                except:
                    size = soup.select_one('a[data-dt-file_size]')['data-dt-file_size']
                update = info.find(string=re.compile('Updated on')).find_next('p').text.strip()
                req_android = info.find(string=re.compile('Requires Android')).find_next('p').text.strip()
                package_name = [i for i in req.url.split('/') if i][-1]
                download_url = f'https://d.apkpure.com/b/APK/{package_name}?version=latest'
                data = {
                    'version': version,
                    'update': update,
                    'requirement': req_android,
                    'size': size,
                    'apkpure_url': req.url,
                    'download_url': download_url,
                }
                app.update(data)
                print(data['download_url'])
                r = self.scraper.get(data['download_url'], stream=True)
                fname = app['sha256'] + '.apk'
                path = pathlib.Path(f'{config.ROOT_PATH}/apps/{app["category"]}/')
                path.mkdir(mode=os.O_WRONLY, parents=True, exist_ok=True)
                f = path / fname
                with tqdm.wrapattr(
                        f.open("wb"), "write",
                        desc=f"{app['title']} ({fname.split('.')[0]})",
                        unit='B', unit_scale=True, unit_divisor=1024, miniters=1,
                        total=int(r.headers.get('content-length', 0))
                ) as fout:
                    for chunk in r.iter_content(chunk_size=4096):
                        if not chunk:
                            break
                        fout.write(chunk)

                app['apkpath'] = f'{config.ROOT_PATH}/apps/{app["category"]}/{fname}'
                # print(app)
                # for k,v in app.items():
                #     print(k,v)
                return app


            except Exception as e:
                print(f"Error during crawl attempt {attempt + 1}: {e} {app['apkpure_url']}")
                if attempt < max_retries-1:
                    print("Retrying...")
                    self.change_proxy(attempt)
                else:
                    print("Failed after 3 attempts. Giving up.",app['appId'])
                    # 错误文件记录
                    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    with open('error.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{now}: {app['appId']}\n")
                    return None

"""
app
{
'title': 'Spotify: Music, Podcasts, Lit',
'appId': 'com.spotify.music', 
'url': 'https://play.google.com/store/apps/details?id=com.spotify.music', 
'icon': 'https://play-lh.googleusercontent.com/P2VMEenhpIsubG2oWbvuLGrs0GyyzLiDosGTg8bi8htRXg9Uf0eUtHiUjC28p1jgHzo', 
'developer': 'Spotify AB', 
'currency': 'USD', 
'price': 0, 
'free': True, 
'scoreText': 4.4, 
'score': 4.379852, 
'category': 'ANDROID_WEAR', 
'sha256': 'be0ca287362158a5ad91beed9ebd92636eb6442e2e978de06cdd6fd57807ac75', 

'version': '8.8.22.510', 
'update': 'Mar 27, 2023', 
'requirement': 'Android 5.0+', 
'size': '74.71 MB', 
'apkpure_url': 'https://apkpure.com/spotify-music-i/com.spotify.music', 
'download_url': 'https://d.apkpure.com/b/APK/com.spotify.music?version=latest',
 apkpath': 'D:\\secComm/apps/ANDROID_WEAR/be0ca287362158a5ad91beed9ebd92636eb6442e2e978de06cdd6fd57807ac75.apk'}


"""
#
# if __name__ == '__main__':
#     apps = ReadCsv()
#     spider = Spider()
#     spider.crawl(apps[0])