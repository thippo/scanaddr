import sqlite3
import base58
import ctypes
import hashlib

NID_secp256k1 = 714

try:
    ssl_library = ctypes.cdll.LoadLibrary('libeay32.dll')
except:
    ssl_library = ctypes.cdll.LoadLibrary('libssl.so')

def WIF_to_compressed(privatekey_WIF):
    return base58.b58encode_check(base58.b58decode_check(privatekey_WIF)+b'\x01')

def compressed_to_WIF(privatekey_compressed):
    return base58.b58encode_check(base58.b58decode_check(privatekey_compressed)[:-1])

def whether_privatekey(privatekey):
    try:
        private_key_decode = base58.b58decode_check(privatekey)
        return True
    except:
        return False

def whether_compressed_privatekey(privatekey):
    private_key_decode = base58.b58decode_check(privatekey)
    if len(private_key_decode) ==33:
        return False
    elif len(private_key_decode) ==34:
        return True

def whether_bitcoinaddress(bitcoinaddress):
    try:
        private_key_decode = base58.b58decode_check(bitcoinaddress)
        return True
    except:
        return False

def int_to_32hex(number):
    assert isinstance(number, int) and number>0, 'number must be positive integer'
    str_bin = bin(number)[2:].rjust(256, '0')
    hex_privatekey = bytes([int(str_bin[x*8:x*8+8], 2) for x in range(32)])
    return hex_privatekey

def int_to_privatekey(number):
    assert isinstance(number, int) and number>0, 'number must be positive integer'
    uncompressed = base58.b58encode_check(b'\x80'+int_to_32hex(number))
    compressed = base58.b58encode_check(b'\x80'+int_to_32hex(number)+b'\x01')
    return uncompressed, compressed

def privatekey_to_int(privatekey):
    if whether_compressed_privatekey(privatekey):
        hex32private = base58.b58decode_check(privatekey)[1:-1]
    else:
        hex32private = base58.b58decode_check(privatekey)[1:]
    str_bin = ''.join([bin(x)[2:].rjust(8, '0') for x in hex32private])
    number = int(str_bin,2)
    return number

def _get_public_key(private_key, curve_name):
    k = ssl_library.EC_KEY_new_by_curve_name(curve_name)
    storage = ctypes.create_string_buffer(private_key)
    bignum_private_key = ssl_library.BN_new()
    ssl_library.BN_bin2bn(storage, 32, bignum_private_key)
    group = ssl_library.EC_KEY_get0_group(k)
    point = ssl_library.EC_POINT_new(group)
    ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
    ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
    ssl_library.EC_KEY_set_public_key(k, point)
    size = ssl_library.i2o_ECPublicKey(k, 0)
    storage = ctypes.create_string_buffer(size)
    pstorage = ctypes.pointer(storage)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(pstorage))
    public_key_uncompress = storage.raw
    ssl_library.EC_POINT_free(point)
    ssl_library.BN_free(bignum_private_key)
    ssl_library.EC_KEY_free(k)
    return public_key_uncompress, _compress(public_key_uncompress)

def _compress(public_key_uncompress):
    x_coord = public_key_uncompress[1:33]
    if public_key_uncompress[64] & 0x01:
        c = bytes([0x03]) + x_coord
    else:
        c = bytes([0x02]) + x_coord
    return c

def _sha256ripemd160(public_key):
    hasher = hashlib.sha256()
    hasher.update(public_key)
    hasher = hasher.digest()
    hasher2 = hashlib.new('ripemd160')
    hasher2.update(hasher)
    hasher2 = hasher2.digest()
    return hasher2

def _get_bitcoin_address(private_key):
    private_key_decode = base58.b58decode_check(private_key)
    if len(private_key_decode) ==33:
        private_key = private_key_decode[1:]
    elif len(private_key_decode) ==34:
        private_key = private_key_decode[1:-1]
    else:
        raise Exception
    public_key_uncompress,public_key_compress = _get_public_key(private_key, NID_secp256k1)
    return base58.b58encode_check(b'\x00'+_sha256ripemd160(public_key_uncompress)), base58.b58encode_check(b'\x00'+_sha256ripemd160(public_key_compress))

def now():
    #return '网站暂时关闭~'
    with sqlite3.connect("bitcoinnow.db") as cx:
        cu = cx.cursor()
        nowval = cu.execute('select * from nowint where id=1').fetchone()[1]
    return str(nowval)

def m():
    with sqlite3.connect("bitcoinfor.db") as cx1:
        cu1 = cx1.cursor()
        try:
            data = cu1.execute("select * from savetable").fetchall()
            return data
        except Exception as e:
            return str(e)

def e():
    with sqlite3.connect("bitcoinerror.db") as cx2:
        cu2 = cx2.cursor()
        try:
            data = cu2.execute("select * from errortable").fetchall()
            newdata = []
            for i in data:
                newdata.append((i[1], int_to_privatekey(i[1])[1], _get_bitcoin_address(int_to_privatekey(i[1])[1])[1]))
            return newdata
        except Exception as e:
            return str(e)

if __name__ == '__main__':
    print('#################')
    print(now())
    print('#################')
    print(m())
    print('#################')
    print(e())