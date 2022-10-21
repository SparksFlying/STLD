from ast import Tuple
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import xmlrpc.client
import xmlrpc
import phe
import random
import utility
import math
from typing import Union, List
# 获取秘钥
CA_server = xmlrpc.client.ServerProxy("http://localhost:10801")
pk = phe.PaillierPublicKey(CA_server.getPub())
sk = phe.PaillierPrivateKey(pk, *CA_server.getPri())

assert(sk.decrypt(pk.encrypt(10)) == 10)
print("--get done--")


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2', '/RPC3')


class DAPServer(SimpleXMLRPCServer):

    def __init__(self, addr: tuple, requestHandler) -> None:
        super().__init__(addr, requestHandler, allow_none=True)
        self.DSP_server = xmlrpc.client.ServerProxy("http://localhost:8000")

    def _SME(self, Y: list):
        print("Y[0]={}".format([y[0] for y in Y]))
        Y = [[y[0], phe.EncryptedNumber(pk, y[1])] for y in Y]
        n = len(Y)
        bit_length = utility.getMaxBitLength(n)
        for i, y in enumerate(Y):
            p_i = sk.decrypt(y[1])
            Y[i][1] = p_i
        print("before sort Y={}".format(Y))
        Y.sort(key=lambda x: x[1], reverse=True)
        print("Y={}".format(Y))
        r2 = int(random.random()*1e3) % (n-1)

        # S_w=[pk.encrypt(Y[r2][0]),pk.encrypt(Y[-1][0])]
        S_w = [
            [pk.encrypt(int(bit)).ciphertext()
             for bit in "{0:b}".format(Y[r2][0]).zfill(bit_length)],
            [pk.encrypt(int(bit)).ciphertext()
             for bit in "{0:b}".format(Y[-1][0]).zfill(bit_length)]
        ]
        S_l = utility.permute([Y[idx][0] for idx in list(
            set([i for i in range(n)])-set([r2])-set([n-1]))])
        return S_w, S_l

    # Secure Integer Comparison Protocol
    # level为1时返回密文
    def _SIC(self, c: int, level=0) -> int:
        m = sk.decrypt(phe.EncryptedNumber(pk, c)) % pk.n
        u = 0
        if int(utility.getMaxBitLength(abs(m))) > int(utility.getMaxBitLength(pk.n)/2):
            u = 1
        if level == 0:
            return u
        else:
            return pk.encrypt(u).ciphertext()

    def _SVC(self, C: List[int], level=0) -> List[int]:
        C = [phe.EncryptedNumber(pk, c) for c in C]
        M = [sk.decrypt(c) for c in C]
        int_bit_length = 32
        max_bit_length = utility.getMaxBitLength(pk.n)
        num_int_per_ciphertext = int(max_bit_length/int_bit_length)

        ret = [[]]*len(M)
        all_x=[]
        for midx in range(len(M)):
            m_expr = "{0:b}".format(abs(M[midx])).zfill(max_bit_length)
            for idx in range(num_int_per_ciphertext):
                x_i = int(m_expr[idx*int_bit_length:(idx+1)*int_bit_length], 2) - 2**(int_bit_length-1)
                all_x.append(x_i)
                u_i = 0
                if int(utility.getMaxBitLength(x_i%pk.n)) > int(utility.getMaxBitLength(pk.n)/2):
                    u_i = 1
                if level == 0:
                    ret[midx].append(u_i)
                else:
                    ret[midx].append(pk.encrypt(u_i).ciphertext())
        print(all_x)
        return ret


with DAPServer(('localhost', 10802),
               requestHandler=RequestHandler) as server:

    print(server)

    server.register_introspection_functions()

    server.register_function(server._SME, name="_SME")
    server.register_function(server._SIC, name="_SIC")
    server.register_function(server._SVC, name="_SVC")
    server.serve_forever()
