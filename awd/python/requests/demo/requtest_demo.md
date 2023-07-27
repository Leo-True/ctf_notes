# python requests 模块示例

```python
# 导入相关库
import requests
import json

# 设置共用的URL
url = 'https://httpbin.org/'

# 设置全局头部信息
headers = {
    'User-Agent': 'My User Agent 1.0',
    'From': 'email@example.com'  # 伪造From头
}

# 使用session对象
s = requests.Session()
s.headers.update(headers)

# 演示GET请求
def get_request():
    # 构造查询参数
    payload = {'key1': 'value1', 'key2': 'value2'}
    
    # 使用session发送GET请求
    r = s.get(url + 'get', params=payload)

    # 打印响应内容
    print(r.text)

# 演示提交FORM数据的POST请求
def post_form_data():
    # 构造表单数据
    payload = {'key1': 'value1', 'key2': 'value2'}

    # 使用session发送POST请求
    r = s.post(url + 'post', data=payload)

    # 打印响应内容
    print(r.text)

# 演示文件上传
def post_file_upload():
    # 打开一个文件
    with open('test.txt', 'rb') as f:
        # 构造文件数据
        files = {'file': f}

        # 使用session发送POST请求
        r = s.post(url + 'post', files=files)

        # 打印响应内容
        print(r.text)

# 演示JSON数据的上传和处理
def post_json_data():
    # 构造JSON数据
    payload = {'key1': 'value1', 'key2': 'value2'}

    # 使用session发送POST请求
    r = s.post(url + 'post', json=payload)

    # 获取响应的JSON内容
    data = r.json()

    # 打印响应内容
    print(json.dumps(data, indent=4))

# 执行上述定义的函数
print("get_request:")
get_request()
print()
print("post_from_data:")
post_form_data()
print()
print("post_file_upload:")
post_file_upload()
print()
print("post_json_data:")
post_json_data()
```
