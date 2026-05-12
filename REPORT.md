# BLACK COBRA PEPPER
## TỔNG QUAN

Đề bài cho 1 file chall.py chứa thuật toán mã hóa AES 1024 bit. File này sẽ mã hóa 2 ví dụ là 1 đoạn plaintext có giá trị `"72616e646f6d64617461313131313131"` và Flag. Kết quả mã hóa được lưu trong file output.txt.

chall.py:
```python
from pwn import xor

pt = ""
key = ""

def split(full_key):
    k = full_key
    k1 = ""
    k2 = ""
    k3 = ""
    k4 = ""
    sub_keys = [k1, k2, k3, k4]
    for i in range(len(k)):
        sub_keys[i%4] = str(sub_keys[i%4]) + str(k[0])
        k = k[1:]
    return sub_keys

def glue(parts):
    k = ""
    for i in range(32):
        k = str(k) + str(parts[i%4][0])
        parts[i%4] = str(parts[i%4][1:])
    return k

def rot_word(word):
    return str(word[2:]) + str(word[0:2])

def sub_word(word):
    return word

def rcon(word):
    return word

def gen_keys(master_key):
    keys = []
    rounds = 0
    k = master_key

    while (rounds < 11):
        keys.append(k)
        sub_keys = split(k)
        sub_keys[-1] = rot_word(sub_keys[-1])
        sub_keys[-1] = sub_word(sub_keys[-1])
        sub_keys[-1] = rcon(sub_keys[-1])
        sub_keys[0] = xor(bytes.fromhex(sub_keys[0]), bytes.fromhex(sub_keys[-1])).hex()
        sub_keys[1] = xor(bytes.fromhex(sub_keys[1]), bytes.fromhex(sub_keys[0])).hex()
        sub_keys[2] = xor(bytes.fromhex(sub_keys[2]), bytes.fromhex(sub_keys[1])).hex()
        sub_keys[3] = xor(bytes.fromhex(sub_keys[3]), bytes.fromhex(sub_keys[2])).hex()
        k = glue(sub_keys)
        rounds += 1
    
    return keys

def to_matrix(key):
    bytes_list = [int(key[i:i+2], 16) for i in range(0, 32, 2)]

    array = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        array[row][col] = hex(bytes_list[i])[2:]
    
    return array

def from_matrix(matrix):
    reconstructed = ""
    for col in range(4):
        for row in range(4):
            reconstructed += matrix[row][col].zfill(2)
    return reconstructed

def sub_bytes(state):
    return state

def shift_rows(state):
    placeholder = state[1][0]
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    return state

#adopted and insipred by the code from the wikipedia article Rijndael MixColumns. 
def gmul(a, b):
    b = int(b, 16)
    p = 0
    for c in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b>>=1
    return p

def mix_columns(s):
    ss = [[0] * 4 for _ in range(4)]

    for c in range(4):
        ss[0][c] = hex(gmul(0x02, s[0][c]) ^ gmul(0x03, s[1][c]) ^ int(s[2][c], 16) ^ int(s[3][c], 16))[2:].zfill(2)
        ss[1][c] = hex(int(s[0][c], 16) ^ gmul(0x02, s[1][c]) ^ gmul(0x03, s[2][c]) ^ int(s[3][c], 16))[2:].zfill(2)
        ss[2][c] = hex(int(s[0][c], 16) ^ int(s[1][c], 16) ^ gmul(0x02, s[2][c]) ^ gmul(0x03, s[3][c]))[2:].zfill(2)
        ss[3][c] = hex(gmul(0x03, s[0][c]) ^ int(s[1][c], 16) ^ int(s[2][c], 16) ^ gmul(0x02, s[3][c]))[2:].zfill(2)
    
    for i in range(4):
        for j in range(4):
            s[i][j] = ss[i][j]
    return s

def AES(plaintext, key):
    ciphertext = plaintext
    round_keys = gen_keys(key)
    ciphertext = xor(bytes.fromhex(round_keys[0]), bytes.fromhex(ciphertext)).hex()
    for i in range(1,10):
        ciphertext = to_matrix(ciphertext)
        sub_bytes(ciphertext)
        shift_rows(ciphertext)
        mix_columns(ciphertext)
        ciphertext = from_matrix(ciphertext)
        ciphertext = xor(bytes.fromhex(round_keys[i]), bytes.fromhex(ciphertext)).hex()
    ciphertext = to_matrix(ciphertext)
    sub_bytes(ciphertext)
    shift_rows(ciphertext)
    ciphertext = from_matrix(ciphertext)
    ciphertext = xor(bytes.fromhex(round_keys[10]), bytes.fromhex(ciphertext)).hex()
    return ciphertext

flag = [redacted]
key = [redacted]
pt1 = "72616e646f6d64617461313131313131"

print((AES(pt1, key)))
print(AES(flag, key))

```

output.txt:
```
d7481d89f1aaf5a857f56edd2ae8994c
8c7d66558130eb5796d131beb43c9934
```

## Phân tích

Thuật toán mã hóa AES đề cho thiếu nhiều bước quan trọng cho tính bảo mật:

* sub_word phải đi qua bảng S-box để thay thế giá trị, và rcon phải thực hiện XOR với một hằng số vòng. Ở đây, chúng chỉ trả về chính nó (`return word`), làm giảm đáng kể tính bảo mật.
* Hàm sub_bytes cũng chỉ trả về state đầu vào thay vì có bước Nghịch đảo nhân và Biến đổi Affine.

Vì đã bỏ sub_bytes, toàn bộ cipher trở thành tuyến tính:
$$E_k(P) = A(P) \oplus B(k)$$
Trong đó:
$A$: Ma trận tuyến tính
$B(k)$: Hằng phụ thuộc key (`def gen_keys(master_key)`)

Với đề bài cho biết 1 plaintext và 2 ciphertext, ta có biểu thức:
$$ E_k(P_1) \oplus E_k(P_2) $$
$$ = (A(P_1) \oplus B(k)) \oplus (A(P_2) \oplus B(k)) $$
$$ = A(P_1) \oplus A(P_2) $$
Vì tuyến tính:
$$ = A(P_1 \oplus P_2) $$
Suy ra:
$$ E_k(P_1) \oplus E_k(P_2) = E_0(P_1 \oplus P_2) $$

Ta có thể triền khai tấn công:

* Tính $E_k(P_1) \oplus E_k(Flag)$ bằng các giá trị trong output.txt.
* Đảo ngược phép encrypt bằng cách đảo ngược shift_rows và mix_columns, ta thu được $P_1 \oplus Flag$
* Thực hiện xor với $P_1$ để lấy được Flag.

## TRIỂN KHAI TẤN CÔNG


* Code tự động lấy flag:

script.py:
```python
from pwn import xor
from chall import to_matrix, from_matrix, gmul, gen_keys, pt1 # Lấy các hàm đã được viết trong chall.py

def inv_shift_rows(state):
    # Hàng 0: Giữ nguyên
    # Hàng 1: Dịch phải 1 (ngược với dịch trái 1)
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    # Hàng 2: Dịch phải 2 (giống dịch trái 2)
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    # Hàng 3: Dịch phải 3 (ngược với dịch trái 3, tức là dịch trái 1)
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return state

def inv_mix_columns(s):
    """Sử dụng ma trận nghịch đảo của MixColumns trong AES"""
    ss = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = [int(s[r][c], 16) if isinstance(s[r][c], str) else s[r][c] for r in range(4)]
        ss[0][c] = gmul(s0, '0e') ^ gmul(s1, '0b') ^ gmul(s2, '0d') ^ gmul(s3, '09')
        ss[1][c] = gmul(s0, '09') ^ gmul(s1, '0e') ^ gmul(s2, '0b') ^ gmul(s3, '0d')
        ss[2][c] = gmul(s0, '0d') ^ gmul(s1, '09') ^ gmul(s2, '0e') ^ gmul(s3, '0b')
        ss[3][c] = gmul(s0, '0b') ^ gmul(s1, '0d') ^ gmul(s2, '09') ^ gmul(s3, '0e')
    
    for i in range(4):
        for j in range(4):
            s[i][j] = hex(ss[i][j])[2:].zfill(2)
    return s

def decrypt_weak_AES(ct_hex, master_key_hex):
    round_keys = gen_keys(master_key_hex)

    # Đảo ngược vòng cuối (Vòng 10)
    # AddRoundKey (XOR) với khóa 10
    curr = xor(bytes.fromhex(ct_hex), bytes.fromhex(round_keys[10])).hex()
    
    state = to_matrix(curr)
    state = inv_shift_rows(state) # Vòng 10 chỉ có ShiftRows, không có MixColumns
    curr = from_matrix(state)

    # Đảo ngược 9 vòng lặp (Vòng 9 về 1)
    for i in range(9, 0, -1):
        # AddRoundKey (XOR) với khóa của vòng đó
        curr = xor(bytes.fromhex(curr), bytes.fromhex(round_keys[i])).hex()
        
        # Đảo ngược MixColumns
        state = to_matrix(curr)
        state = inv_mix_columns(state)
        
        # Đảo ngược ShiftRows
        state = inv_shift_rows(state)
        curr = from_matrix(state)

    # Đảo ngược AddRoundKey đầu tiên (Vòng 0)
    plaintext_hex = xor(bytes.fromhex(curr), bytes.fromhex(round_keys[0])).hex()
    return plaintext_hex

# Lấy dữ liệu
f = open('output.txt')
ct1 = f.readline()
ct_flag = f.readline()
f.close()

ct_diff = xor(bytes.fromhex(ct1), bytes.fromhex(ct_flag)).hex()
null_key = "00" * 16
diff_pt_hex = decrypt_weak_AES(ct_diff, null_key)

flag = xor(bytes.fromhex(diff_pt_hex), bytes.fromhex(pt1))

print(f"Flag: {flag.decode(errors='ignore')}")
```

Cây thư mục:
```
├── 🐍 chall.py
├── 📄 output.txt
└── 🐍 script.py
```

Kết quả thực thi:
```
Flag: picoCTF{spi1cy!}
```