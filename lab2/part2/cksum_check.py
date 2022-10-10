import os
import sys
from ctypes import *

class cksum_checker(object):
    def __init__(self):
        self.afl_post_library_path = './post_library.so'
        self.afl_post_library = CDLL(self.afl_post_library_path)
        self.afl_post_library.afl_postprocess.argtypes = (POINTER(c_ubyte), POINTER(c_uint))
        self.afl_post_library.afl_postprocess.restype = POINTER(c_ubyte)
        self.cksum_check_library_path = './cksum_check.so'
        self.cksum_check_library = CDLL(self.cksum_check_library_path)
        self.cksum_check_library.check.argtypes = (POINTER(c_ubyte), c_uint)
        self.cksum_check_library.check.restype = c_int
        self.cksum_check_library.shouldbe.argtypes = (POINTER(c_ubyte), c_uint)
        self.cksum_check_library.shouldbe.restype = c_ushort
    def cksum_check(self, arg_in_buf, arg_len):
        return self.cksum_check_library.check(arg_in_buf, arg_len)
    def cksum_shouldbe(self, arg_in_buf, arg_len):
        return self.cksum_check_library.shouldbe(arg_in_buf, arg_len)
    def afl_postprocess_wrapper(self, arg_in_buf, arg_len):
        ret = self.afl_post_library.afl_postprocess(arg_in_buf, arg_len)
        return ret
    def test_one(self, testcase:str):
        bytes_array = bytearray.fromhex(testcase)
        buf_type = c_ubyte * len(bytes_array)
        buf = buf_type.from_buffer(bytes_array)
        buf_len = c_uint(len(bytes_array))
        fixed_buf = self.afl_postprocess_wrapper(buf, byref(buf_len))
        fixed_buf_s = ''.join('%02x' % fixed_buf[i] for i in range(len(bytes_array)))
        check_result = self.cksum_check(fixed_buf, buf_len)
        if check_result == 0:
            print('SUCCESS The checksum is correct')
        else:
            if len(fixed_buf_s) // 2 < 20:
                print('ERROR your fixed buf is not long enough to hold an IP header')
            else:
                print('ERROR checksum should be ' + str(hex(self.cksum_shouldbe(fixed_buf, buf_len))) + ', your checksum is 0x' + fixed_buf_s[20:24] + ' your output buffer is ' + fixed_buf_s)
        return
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python3', sys.argv[0], '<hex string of an IP packet>')
        print('       e.g. python3', sys.argv[0], '4500003401304000400610350a0a0a310a0a0afbd82f0277dd29f53db57e6e1b8010002e9bce00000101080a006bf2ed0058ed27')
        exit(1)
    if len(sys.argv[1]) // 2 < 20:
        print('ERROR The input is not long enough to hold an IP header')
        exit(1)
    c = cksum_checker()
    c.test_one(sys.argv[1])
