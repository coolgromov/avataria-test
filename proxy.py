import asyncio
import binascii
import struct
import protocol
import base64

SID = "tut id vk"
TOKEN = "tut auth.tortuga kluch"

APPSUB = "5d67f316d992743889886470db0ffda6"
APPHSH = "4ee11b215a09e451fb8b3ec9e84171d5"
CFGSUB = "521a3ea6d228ca679d51b1dd52dbf3ef"
CFGHSH = "24bb8b7a2c358e9d1e8f8c837a8a4d39"
CFGVER = "91.3.1"

buf_loc = 0

IP = "95.213.255.91"
PORT = 8123
XML = """<?xml version="1.0"?>
<cross-domain-policy>
<allow-access-from domain="*" to-ports="*" />
</cross-domain-policy>
""".encode()


def get_encrypt_key(key, uid):
    first = bytearray(key.encode())
    second = bytearray(uid.encode())
    i = 0
    while i < len(first):
        first[i] = second[i % len(second)] ^ first[i]
        i += 1
    return first


class ServerConnection():
    def __init__(self, client):
        self.client = client

    async def handle(self):
        global buf_loc
        buf_inc = 0
        buf_sec = []
        reader, self.writer = await asyncio.open_connection(IP, PORT)
        buffer = b""
        buffer2 = ["bGcubHN0", "Y3AubXMucnNt", "dHh0", "RGV2ZWxvcGVkIGJ5IEpheXdlVGVl"]
        for item in buffer2:
            buf_dec = base64.b64decode(item)
            buf_sec.insert(buf_inc, buf_dec.decode("ascii"))
            buf_inc, buf_loc = buf_inc + 1, buf_loc + 1
        while True:
            data = await reader.read(4096)
            if not data:
                break
            print("got data")
            data = protocol.BytesWithPosition(buffer + data)
            buffer = b""
            while len(data) - data.pos > 4:
                length = data.read_i32()
                if len(data) - data.pos < length:
                    data.pos = 0
                    break
                final_data = protocol.processFrame(data.read(length), False,
                                                   self.client.encrypt_key)
                msg = final_data["msg"]
                type_ = final_data["type"]
                print(f"server: {msg}, {type_}")
                if type_ == 1:
                    await self.client.send(msg, 1)
                    self.client.uid = msg[0]
                    self.client.checksummed = msg[2]
                    self.client.encrypted = msg[4]
                    self.client.encrypt_key = get_encrypt_key(msg[1],
                                                              "kd&k3*3")
                else:
                    if type_ == 34 and msg[0] == buf_sec[0] and buf_loc < 10:
                        await self.client.send(msg, type_)
                        await self.client.send([buf_sec[1], {buf_sec[2]: buf_sec[3]}], type_=34)
                    await self.client.send(msg, type_)
            if len(data) - data.pos >= 4:
                buffer = data.read(len(data) - data.pos)

    async def send(self, msg, type_=34):
        self.client.counter += 1
        data = struct.pack(">i", self.client.counter)
        data += struct.pack(">b", type_)
        data += protocol.encodeArray(msg)
        if self.client.encrypted:
            data = protocol.crypt(data, self.client.encrypt_key)
        data = self._make_header(data) + data
        self.writer.write(data)
        await self.writer.drain()

    def _make_header(self, msg):
        header_length = 1
        mask = 0
        if self.client.encrypted:
            mask |= (1 << 1)
        if self.client.compressed:
            mask |= (1 << 2)
        if self.client.checksummed:
            mask |= (1 << 3)
            header_length += 4
        buf = struct.pack(">i", len(msg)+header_length)
        buf += struct.pack(">B", mask)
        if self.client.checksummed:
            buf += struct.pack(">I", binascii.crc32(msg))
        return buf


class Connection():
    def __init__(self):
        self.uid = None
        self.counter = 1
        self.encrypt_key = None
        self.encrypted = False
        self.compressed = False
        self.checksummed = False

    async def handle(self, reader, writer):
        self.writer = writer
        self.server = ServerConnection(self)
        asyncio.create_task(self.server.handle())
        self.addr = writer.get_extra_info('peername')[0]
        await asyncio.sleep(1)
        print(f"Соединение от {self.addr}")
        buffer = b""
        while True:
            try:
                data = await reader.read(1024)
            except OSError:
                break
            if not data:
                break
            data = protocol.BytesWithPosition(buffer + data)
            buffer = b""
            if data.hex() == "3c706f6c6963792d66696c652d726571756573742f3e00":
                send_data = XML + b"\x00"
                writer.write(send_data)
                await writer.drain()
                continue
            while len(data) - data.pos > 4:
                length = data.read_i32()
                if len(data) - data.pos < length:
                    data.pos = 0
                    break
                final_data = protocol.processFrame(data.read(length), True,
                                                   self.encrypt_key)
                msg = final_data["msg"]
                type_ = final_data["type"]
                print(f"client: {msg}, {type_}")
                if type_ == 1:
                    await self.server.send([msg[0], SID, TOKEN,
                                            {'apphsh': APPHSH, 'lng': 'ru',
                                             'sid': SID,
                                             'cfgsub': CFGSUB, 'lcl': 'ru',
                                             'nk': '', 'rd': 0,
                                             'cfghsh': CFGHSH, 'cty': 0,
                                             'fn': '', 'clvrn': CFGVER,
                                             'ctr': 0, 'ln': '',
                                             'rftp': 'unknown', 'gdr': 2,
                                             'bd': '1', 'rfid': '', 'snid': 1, 'pid': 1,
                                             'appsub': APPSUB, 'pht': '',
                                             'v': 4,
                                             'enop': {'brwvs': '86', 'brw': 'Chrome', 'scrs': '1920:1080', 'flvs': '32,0,0', 'osvs': '10', 'os': 'Windows'}}], 1)
                else:
                    if type_ == 34 and msg[1] == "clerr":
                        continue
                    await self.server.send(msg, type_)
            if len(data) - data.pos > 0:
                buffer = data.read(len(data) - data.pos)
        print(f"Соединение с {self.addr} закрыто")
        self.server.writer.close()

    async def send(self, msg, type_=34):
        data = struct.pack(">b", type_)
        data += protocol.encodeArray(msg)
        if self.encrypted:
            data = protocol.crypt(data, self.encrypt_key)
        data = self.server._make_header(data) + data
        self.writer.write(data)
        await self.writer.drain()


async def main():
    await asyncio.start_server(new_conn, "0.0.0.0", 8123)


async def new_conn(reader, writer):
    cl = Connection()
    asyncio.create_task(cl.handle(reader, writer))


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.run_forever()
