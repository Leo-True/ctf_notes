# base64 编解码

## python base64 编码

```python
import base64

def encode_base64(data):
    encoded_data = base64.b64encode(data.encode())
    return encoded_data.decode()

data = "the string to be encoded"
print(encode_base64(data))
```

## python base64 解码

```python
import base64

def decode_base64(encoded_data):
    decoded_data = base64.b64decode(encoded_data.encode())
    return decoded_data.decode()

encoded_data = "the base64 string to be decoded"
print(decode_base64(encoded_data))
```

---

## javascript base64 编码

```javascript
let data = "the string to be encoded";
let encodedData = btoa(data);
console.log(encodedData);
```

## javascript base64 解码

```javascript
let encodedData = "the base64 string to be decoded";
let decodedData = atob(encodedData);
console.log(decodedData);
```

---

## php base64 编码

```php
$data = "the string to be encoded";
$encodedData = base64_encode($data);
echo $encodedData;
```

## php base64 解码

```php
$encodedData = "the base64 string to be decoded";
$decodedData = base64_decode($encodedData);
echo $decodedData;
```
