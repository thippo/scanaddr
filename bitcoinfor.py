import requests
import base58
import ctypes
import hashlib
import sqlite3
import time
import random

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

headers = {'content-type': 'application/json','User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0'}

def insert_fordb(pk_int, privatekey, publickey, balance):
    with sqlite3.connect("bitcoinfor.db") as cx1:
        cu1 = cx1.cursor()
        cu1.execute("insert into savetable values(null, "+str(pk_int)+", '"+privatekey+"', '"+publickey+"', '"+balance+"')")
        cx1.commit()

def insert_errordb(pk_int):
    with sqlite3.connect("bitcoinerror.db") as cx2:
        cu2 = cx2.cursor()
        cu2.execute("insert into errortable values(null, "+str(pk_int)+", '-')") 
        cx2.commit()

def blockchain_api(pk_int, privatekey, publickey):
    print('blockchain_api')
    try:
        r = requests.get('https://blockchain.info/q/addressbalance/'+publickey, headers=headers, timeout=5)
        print(r.text)
        if int(r.text) > 0:
            insert_fordb(pk_int, privatekey, publickey, r.text)
        return 1
    except Exception as e:
        print(e)
        return 0

def bitgo_api(pk_int, privatekey, publickey):
    print('bitgo_api')
    try:
        r = requests.get('https://www.bitgo.com/api/v1/address/'+publickey, headers=headers, timeout=5)
        print(r.json()['balance'])
        if int(r.json()['balance']) >0 or int(r.json()['confirmedBalance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def blockr_api(pk_int, privatekey, publickey):
    print('blockr_api')
    try:
        r = requests.get('http://btc.blockr.io/api/v1/address/info/'+publickey, headers=headers, timeout=5)
        print(r.json()['data']['balance'])
        if int(r.json()['data']['balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['data']['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def blockcypher_api(pk_int, privatekey, publickey):
    print('blockcypher_api')
    try:
        r = requests.get('https://api.blockcypher.com/v1/btc/main/addrs/'+publickey+'/balance', headers=headers, timeout=5)
        print(r.json()['balance'])
        if int(r.json()['balance']) >0 or int(r.json()['unconfirmed_balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def coinprism_api(pk_int, privatekey, publickey):
    print('coinprism_api')
    try:
        r = requests.get('https://api.coinprism.com/v1/addresses/'+publickey, headers=headers, timeout=5)
        print(r.json()['balance'])
        if int(r.json()['balance']) >0 or int(r.json()['unconfirmed_balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def bitcoinchain_api(pk_int, privatekey, publickey):
    print('bitcoinchain_api')
    try:
        r = requests.get('https://api-r.bitcoinchain.com/v1/address/'+publickey, headers=headers, timeout=5)
        print(r.json()[0]['balance'])
        if int(r.json()[0]['balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()[0]['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def bitflyer_api(pk_int, privatekey, publickey):
    print('bitflyer_api')
    try:
        r = requests.get('https://chainflyer.bitflyer.jp/v1/address/'+publickey, headers=headers, timeout=5)
        print(r.json()['confirmed_balance'])
        if int(r.json()['confirmed_balance']) >0 or int(r.json()['unconfirmed_balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['confirmed_balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def btc_api(pk_int, privatekey, publickey):
    print('btc_api')
    try:
        r = requests.get('https://chain.api.btc.com/v3/address/'+publickey, headers=headers, timeout=5)
        print(r.json()['data']['balance'])
        if int(r.json()['data']['balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['data']['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def blocktrail_api(pk_int, privatekey, publickey):
    print('blocktrail_api')
    try:
        r = requests.get('https://api.blocktrail.com/v1/btc/address/'+publickey+'?api_key=MY_APIKEY', headers=headers, timeout=5)
        print(r.json()['balance'])
        if int(r.json()['balance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def bitpay_api(pk_int, privatekey, publickey):
    print('bitpay_api')
    try:
        r = requests.get('https://insight.bitpay.com/api/addr/'+publickey+'/?noTxList=1', headers=headers, timeout=5)
        print(r.json()['balance'])
        if int(r.json()['balance']) >0 or int(r.json()['unconfirmedBalance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

def blockexplorer_api(pk_int, privatekey, publickey):
    print('blockexplorer_api')
    try:
        r = requests.get('https://blockexplorer.com/api/addr/'+publickey, headers=headers, timeout=5)
        print(r.json()['balance'])
        if int(r.json()['balance']) >0 or int(r.json()['unconfirmedBalance']) >0:
            insert_fordb(pk_int, privatekey, publickey, r.json()['balance'])
        return 1
    except Exception as e:
        print(e)
        return 0

api_list = [blockchain_api, bitgo_api, blockr_api, blockcypher_api, coinprism_api, bitcoinchain_api, bitflyer_api, btc_api, blocktrail_api, bitpay_api, blockexplorer_api, ]

with sqlite3.connect("bitcoinnow.db") as cx:
    cu = cx.cursor()
    pk_int = int(cu.execute('select * from nowint where id=1').fetchone()[1])
    while 1:
        privatekey = int_to_privatekey(pk_int)[1]
        publickey = _get_bitcoin_address(privatekey)[1]
        print(pk_int)
        print(privatekey)
        print(publickey)
        e_bool = 1
        random.shuffle(api_list)
        for i in api_list:
            r_value = i(pk_int, privatekey, publickey)
            if r_value:
                e_bool = 0
                break
        if e_bool:
            insert_errordb(pk_int)
        cu.execute("update nowint set int_now="+str(pk_int)+" where id=1") 
        cx.commit()
        time.sleep(5)
        pk_int += 1

