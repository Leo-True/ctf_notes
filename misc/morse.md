# 摩斯密码解码

```python
# 定义摩斯密码字典
MORSE_CODE_DICT = { 'A' : '.-',      'B' : '-...',    'C' : '-.-.', 
                    'D' : '-..',     'E' : '.',       'F' : '..-.', 
                    'G' : '--.',     'H' : '....',    'I' : '..', 
                    'J' : '.---',    'K' : '-.-',     'L' : '.-..', 
                    'M' : '--',      'N' : '-.',      'O' : '---', 
                    'P' : '.--.',    'Q' : '--.-',    'R' : '.-.', 
                    'S' : '...',     'T' : '-',       'U' : '..-', 
                    'V' : '...-',    'W' : '.--',     'X' : '-..-', 
                    'Y' : '-.--',    'Z' : '--..', 
                    '1' : '.----',   '2' : '..---',   '3' : '...--',
                    '4' : '....-',   '5' : '.....',   '6' : '-....',
                    '7' : '--...',   '8' : '---..',   '9' : '----.',
                    '0' : '-----', 
                    ',' : '--..--',  '.' : '.-.-.-',  '?' : '..--..', 
                    '/' : '-..-.',   '-' : '-....-',  '_' : '..--.-',
                    '(' : '-.--.',   ')' : '-.--.-',  '!' : '-.-.--',
                    '{' : '----.--', '}' : '-----.-' }

# 反转字典，使得摩斯密码映射到字母
REVERSED_MORSE_CODE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

# 假设输入的摩斯密码使用空格来分隔字母，使用斜杠（/）来分隔单词
def decode_morse(morse_code):
    # 分割单词和字母
    words = morse_code.split(' / ')

    decoded_message = []
    for word in words:
        letters = word.split(' ')
        decoded_word = ''.join(REVERSED_MORSE_CODE_DICT.get(letter, '*') for letter in letters)
        decoded_message.append(decoded_word)

    return ' '.join(decoded_message)

# 测试
print(decode_morse('.- / -...'))
```
