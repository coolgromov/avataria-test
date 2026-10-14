import sys
import importlib
import asyncio
import binascii
from bitstring import BitArray, ConstBitStream
import protocol
import requests as r
import json
import time

HOST = "api4.vk.avataria.tortugasocial.com"
PORT = 8123
SOCIAL_NETWORK = 1

param = {"id":1,"jsonrpc":"2.0","method":"auth","params":["avataria-vk","",{"access_token":"","time":int(time.time()),"auth_key":""}]}
out = r.post("http://auth.tortugasocial.com/", json=param).json()
token =  out['result']['key']

def get_encrypt_key(key, uid):
    uid = "kd&k3*3"
    first = bytearray(key.encode())
    second = bytearray(uid.encode())
    i = 0
    while i < len(first):
        first[i] = second[i % len(second)] ^ first[i]
        i += 1
    return first


class AvatariaBot():
    def __init__(self):
        self.server = "house"
        self.sid = ""
        self.token = ""
        self.main = ""
        self.counter = 0
        self.checksummed = False
        self.compressed = False
        self.encrypted = False
        self.encrypt_key = None
        self.uid = None
        self.room = None
        tmp = importlib.import_module(sys.argv[1])
        class_ = getattr(tmp, "Module")
        self.module = class_(self)

    async def connect(self, ip, port):
        reader, self.writer = await asyncio.open_connection(ip, port)
        key = json.loads(r.get('http://cdn-sp.tortugasocial.com/avataria-ru/versions.json').text)
        await self.send([self.server, self.sid,
                         self.token,
                        {'apphsh': key['app/pnz-city.swf'], 'lng': 'ru',
                          'sid': self.sid,
                          'cfgsub': key['data/config_all_ru.zip_sub'], 'lcl': 'ru',
                          'nk': '', 'rd': 0,
                          'cfghsh': key['data/config_all_ru.zip'], 'cty': 0,
                          'fn': '', 'clvrn': "96.15.4",
                          'ctr': 0, 'ln': '',
                          'rftp': 'unknown', 'gdr': 2,
                          'bd': '1', 'rfid': '', 'snid': SOCIAL_NETWORK, 'pid': SOCIAL_NETWORK,
                          'appsub': key['app/pnz-city.swf_sub'], 'pht': '',
                          'v': 4,
                          'enop': {'brwvs': '86', 'brw': 'Chrome', 'scrs': '1920:1080', 'flvs': '32,0,0', 'osvs': '10', 'os': 'Windows'}}],
                        type_=1)
        buffer = ConstBitStream()
        while True:
            data = await reader.read(1024)
            if not data:
                break
            data = buffer + ConstBitStream(data)
            buffer = ConstBitStream()
            while len(data) - data.pos > 32:
                length = data.read(32).int
                if (len(data) - data.pos) / 8 < length:
                    data.pos = 0
                    break
                final_data = protocol.processFrame(data.read(length * 8),
                                                   False, self.encrypt_key)
                await self.process_data(final_data["msg"],
                                        final_data["type"])
            if (len(data) - data.pos) / 8 >= 32:
                buffer = data

    async def send(self, msg, type_=34):
        self.counter += 1
        data = BitArray(f"int:32={self.counter}")
        data.append(f"int:8={type_}")
        data.append(protocol.encodeArray(msg))
        if self.encrypted:
            tmp = bytearray(data.bytes)
            data = BitArray(protocol.crypt(tmp, self.encrypt_key))
        data.insert(self._make_header(data), 0)
        self.writer.write(data.bytes)
        await self.writer.drain()

    async def process_data(self, msg, type_):
        if type_ == 1:
            self.uid = msg[0]
            self.checksummed = msg[2]
            self.encrypted = msg[4]
            self.encrypt_key = get_encrypt_key(msg[1], self.uid)
            await self.module.auth_complete()
            print("Авторизован:", self.uid, self.token)
        elif type_ == 16 and msg[1] == self.uid:
            self.room = msg[0]
        elif type_ == 17 and msg[1] == self.uid:
            self.room = None
        elif type_ == 34:
            await self.module.on_message(msg)

    async def change_room(self, uid):
        if self.room:
            await self.send([self.room], type_=17)
        await self.send([None, "h.gr", {"lid": "house", "gid": uid,
                                        "rid": "livingroom"}])

    def _make_header(self, msg):
        buf = BitArray()
        header_length = 1
        mask = 0
        if self.encrypted:
            mask |= (1 << 1)
        if self.compressed:
            mask |= (1 << 2)
        if self.checksummed:
            mask |= (1 << 3)
            header_length += 4
        buf.append(f"int:32={len(msg.hex)//2+header_length}")
        buf.append(f"int:8={mask}")
        if self.checksummed:
            buf.append(f"uint:32={binascii.crc32(msg.bytes) % (1<<32)}")
        return buf


if __name__ == "__main__":
    bot = AvatariaBot()
    asyncio.run(bot.connect(HOST, PORT))