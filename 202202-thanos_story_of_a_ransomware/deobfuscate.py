from pathlib import Path
from typing import List
from Crypto.Cipher import AES
from base64 import b64decode
from re import match
from argparse import ArgumentParser
import logging
import zlib
import struct
import json

logger = logging.basicConfig(level=logging.INFO)

B64_REGEX = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"


class ResourceDecryptor(object):

    def __init__(self, key: List[int], iv: List[int], resource: str, offset=75, xor_value=0x666BEEF):
        self.offset = offset
        self.xor_value = xor_value
        self.data = self.get_data_from_file(resource)
        self.decrypter = self.get_aes_context(
            bytes(key),
            bytes(iv)
        )
        self.deobfuscate()

    def set_offset(self, offset: int):
        self.offset = offset

    def set_xor_value(self, xor_value: int):
        self.xor_value = xor_value

    @staticmethod
    def get_data_from_file(filepath: str):
        resource = Path(filepath)
        if not resource.is_file():
            raise ValueError("File resource not found")
        else:
            with open(resource, 'rb') as fd:
                return fd.read()

    @staticmethod
    def get_aes_context(key: str, iv: str, mode=AES.MODE_CBC):
        return AES.new(key, mode, iv)

    # TO DO
    @staticmethod
    def validate_header(data: bytes, value=8223355):
        return data == struct.pack('<I', value)

    @staticmethod
    def match_b64(s: str):
        try:
            if match(B64_REGEX, s):
                s = b64decode(s).decode()
                s.replace("\\", "\\\\")
        finally:
            return s

    def deobfuscate(self):
        if self.validate_header(self.data[:3] + b'\x00'):
            self.data = self.decrypter.decrypt(self.data[4:])
        else:
            raise ValueError("Header not valid: {} != ".format(self.data[:3]))
        self.data = zlib.decompress(self.data[16:], -15)

    def run(self):
        self.data = self.run_part1()
        self.data = zlib.decompress(self.data[16:], -15)
        counter = 0
        for s in self.extract_strings(self.data):
            print(self.match_b64(s))
            counter += 1
        logging.info("{} strings decoded".format(counter))

    def get_value_from_index(self, index: int):
        return int(self.data[index])

    def decrypt_string_at_offset(self, offset):
        size = self.get_value_from_index(offset)
        if size & 0x80:
            if size & 0x40:
                size = (size & 0x1F) << 24
                offset += 1
                size += self.get_value_from_index(offset) << 16
                offset += 1
                size += self.get_value_from_index(offset) << 8
                offset += 1
                size += self.get_value_from_index(offset)
            else:
                size = (size & 0x3F) << 8
                offset += 1
                size += self.get_value_from_index(offset)
        s = b64decode(self.data[offset + 1:offset + 1 + size]).decode("utf-8")
        try:
            s = b64decode(s.encode("utf-8")).decode("utf-8")
        except Exception:
            try:
                s = b64decode(s.encode("utf-8")[::-1]).decode("utf-8")
            except Exception:
                pass
        return s, offset + size + 1

    def decrypt_all_strings(self):
        offset = 0
        while offset < len(self.data):
            s, next_offset = self.decrypt_string_at_offset(offset)
            yield offset, s
            offset = next_offset

    def decrypt_one_string(self, value: int, rid: int):
        value -= rid
        value ^= self.xor_value
        value -= self.offset
        return self.decrypt_string_at_offset(value)[0]


def main():
    parser = ArgumentParser(description="Decrypt resource file from spook sample")
    parser.add_argument("input", help="Resource File")
    parser.add_argument("-r", "--rid", help="RID of the class", type=int)
    parser.add_argument("-i", "--integer", help="Integer value to decode", type=int)
    parser.add_argument("-d", "--data", help="File contianing rid followed by a list of integer to decode (json)")
    parser.add_argument("-f", "--filter", help="Filter print value for a data file")
    parser.add_argument("-c", "--config", help="config file including key, IV, offset and xor_value for a specific resource file", default="./config.json")
    args = parser.parse_args()
    resource_file = Path(args.input)
    if not resource_file.is_file():
        raise ValueError("The file {} does not exist".format(args.input))
    config = Path(args.config)
    if not config.is_file():
        raise ValueError("The file {} does not exist".format(args.config))
    else:
        with open(config, 'r') as fd:
            config = json.load(fd)
    if (args.rid and not args.integer) or (args.integer and not args.rid):
        raise ValueError("You should provide both rid and integer")
    if args.data:
        if not Path(args.data).is_file():
            raise ValueError("The file {} does not exist".format(args.data))
        with open(Path(args.data)) as fd:
            input_data = json.load(fd)
    if args.filter and not args.data:
        raise ValueError("Yous must specify a data file to filter on")
    elif args.filter and args.data:
        if match(r"\d{5,10}", args.filter):
            filter = int(args.filter)
        else:
            filter = args.filter

    decrypter = ResourceDecryptor(
        config['key'],
        config['iv'],
        resource_file
    )

    if 'offset' in config:
        decrypter.set_offset(config['offset'])
    if 'xor_value' in config:
        decrypter.set_xor_value(config['xor_value'])

    if args.integer and args.rid:
        print(decrypter.decrypt_one_string(args.integer, args.rid))
    elif args.data:
        for rid, data in input_data.items():
            if args.filter and isinstance(filter, str):
                if filter != data["name"]:
                    continue
            print("\n## RID {} - {}\n".format(rid, data["name"]))
            for v in data["values"]:
                if args.filter and isinstance(filter, int):
                    if v != filter:
                        continue
                print("[Offset {}] ==> \'{}\'".format(v, decrypter.decrypt_one_string(int(v), int(rid))))
    else:
        for s in decrypter.decrypt_all_strings():
            print(s[1])


if __name__ == "__main__":
    main()
