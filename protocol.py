import binascii
import datetime
from bitstring import BitArray, ConstBitStream


def processFrame(data, client=False, encrypt_key=None):
    mask = data.read(8).uint
    ENCRYPTED_FLAG = 1 << 1
    COMPRESSED_FLAG = 1 << 2
    CHECKSUMMED_FLAG = 1 << 3
    if 0 != (mask & CHECKSUMMED_FLAG):
        checksum = data.read(32).uint
    message = data.read(len(data) - data.pos)
    if 0 != (mask & CHECKSUMMED_FLAG):
        real_checksum = binascii.crc32(message.bytes) % (1 << 32)
        if checksum != real_checksum:
            print(f"чексуммы не совпадают {checksum} - {real_checksum}")
            return
    if 0 != (mask & ENCRYPTED_FLAG):
        tmp = bytearray(message.bytes)
        message = ConstBitStream(crypt(tmp, encrypt_key))
    if client:
        message.pos += 32  # номер сообщения
    type_ = message.read(8).int
    return {"type": type_, "msg": decodeArray(message)}


def crypt(data, encrypt_key):
    i1 = int(len(data) / 2)
    i2 = min([len(data), len(encrypt_key) / 2])
    i = 0
    while i < i2:
        data[i] = encrypt_key[i * 2] ^ data[i]
        if len(data) > i1 + i:
            data[i1 + i] = encrypt_key[i * 2 + 1] ^ data[i1 + i]
        i += 1
    return data


def encodeArray(data):
    final_data = BitArray()
    final_data.append(f'int:32={len(data)}')
    for item in data:
        final_data.append(encodeValue(item))
    return final_data


def encodeValue(data, forDict=False):
    final_data = BitArray()
    if data is None:
        final_data.append(f'int:8=0')
    elif isinstance(data, bool):
        final_data.append(f'int:8=1')
        final_data.append(f'int:8={int(data)}')
    elif isinstance(data, int):
        if data < 2147483647 and data > -2147483648:
            final_data.append(f'int:8=2')
            final_data.append(f'int:32={data}')
        else:
            final_data.append(f'int:8=3')
            final_data.append(f'int:64={data}')
    elif isinstance(data, float):
        final_data.append(f'int:8=4')
        final_data.append(f'float:64={data}')
    elif isinstance(data, str):
        if not forDict:
            final_data.append(f'int:8=5')
        length = int(len(data.encode().hex()) / 2)
        while (length & 4294967168) != 0:
            final_data.append(f"uint:8={length & 127 | 128}")
            length = length >> 7
        final_data.append(f"uint:8={length & 127}")
        final_data.append(data.encode())
    elif isinstance(data, dict):
        final_data.append(f'int:8=6')
        final_data.append(encodeObject(data))
    elif isinstance(data, list):
        final_data.append(f'int:8=7')
        final_data.append(encodeArray(data))
    else:
        raise ValueError("Не могу энкодить " + str(type(data)))
    return final_data


def encodeObject(data):
    final_data = BitArray()
    final_data.append(f'int:32={len(data)}')
    for item in data.keys():
        final_data.append(encodeValue(item, forDict=True))
        final_data.append(encodeValue(data[item]))
    return final_data


def decodeArray(data):
    result = []
    length = data.read(32).int
    i = 0
    while i < length:
        try:
            result.append(decodeValue(data))
        except:
            return result
        i += 1
    return result


def decodeObject(data):
    fields = data.read(32).int
    obj = {}
    i = 0
    while i < fields:
        try:
            key = decodeString(data)
            obj[key] = decodeValue(data)
        except:
            return obj
        i += 1
    return obj


def decodeValue(data):
    dataType = data.read(8).int
    if dataType == 0:  # null
        return None
    elif dataType == 1:  # bool
        if data.read(8).int:
            return True
        else:
            return False
    elif dataType == 2:  # int
        return data.read(32).int
    elif dataType == 3:  # long
        return data.read(64).int
    elif dataType == 4:  # double
        return data.read(64).float
    elif dataType == 5:  # string
        return decodeString(data)
    elif dataType == 6:  # Object
        return decodeObject(data)
    elif dataType == 7:  # Array
        return decodeArray(data)
    elif dataType == 8:  # date
        return datetime.datetime.fromtimestamp(data.read(64).int / 1000)
    else:
        raise ValueError("Неизвестный тип данных: " + str(dataType))


def decodeString(data):
    i = 0
    b = data.read(8).uint
    value = 0
    while b & 128 != 0:
        value += (b & 127) << i
        i += 7
        if i > 35:
            raise Exception("Variable length quantity is too long")
        b = data.read(8).uint
    length = value | b << i
    return data.read(length * 8).bytes.decode()


def decodeLong(data):
    major = data.read(32).uint
    minor = data.read(32).uint
    if major & 2147483648:
        major = major ^ 4294967295
        minor = minor ^ 4294967295
        return -(major * 4294967296 + minor + 1)
    return major * 4294967296 + minor