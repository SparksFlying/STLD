from heapq import heappop, heappush
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import xmlrpc.client
import xmlrpc
import phe
import math
import random
import utility
import numpy as np
from typing import Union, List
import copy

USE_PLAINTEXT = 0
USE_CIPHERTEXT = 1

# 获取秘钥
CA_server = xmlrpc.client.ServerProxy("http://localhost:10801")
pk = phe.PaillierPublicKey(CA_server.getPub())
sk = phe.PaillierPrivateKey(pk, *CA_server.getPri())

assert(sk.decrypt(pk.encrypt(10)) == 10)
#print("--get done--")

LEFT_BOTTOM_CORNER = -2
RIGHT_UP_CORNER = 1


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2', '/RPC3')


class DSPServer(SimpleXMLRPCServer):

    def __init__(self, addr: tuple, requestHandler) -> None:
        super().__init__(addr, requestHandler, allow_none=True)
        self.data = [1, 2, 3, 4, 5]
        self._threshold = 10
        
        self.DAP_server = xmlrpc.client.ServerProxy("http://localhost:10802")

    def topkQuery(self, k):
        X = []
        for i in range(10):
            X.append([[pk.encrypt(i), pk.encrypt(i+1),
                     pk.encrypt(i+2)], pk.encrypt(i+10)])
        # return [[[c.ciphertext() for c in x_i[0]],x_i[1].ciphertext()] for x_i in self._SME(X)]
        res = self._SME(X)
        return [[[sk.decrypt(c) for c in x_i[0]], sk.decrypt(x_i[1])] for x_i in res]

    # Secure Minimum Extraction
    def _SME(self, X: list) -> list:
        k = len(X)
        Y = []
        S = []
        bit_length = utility.getMaxBitLength(k)
        phi = [i for i in range(k)]
        r1 = int(random.random()*1e3) % k
        for i, item in enumerate(X):
            x_i, p_i = item
            S.append(phi[i])
            Y.append([phi[i], p_i+r1])

        # permute Y
        #print("Y[0]={}".format([y[0] for y in Y]))
        S_w, S_l = self.DAP_server._SME(
            [[y[0], y[1].ciphertext()] for y in utility.permute(Y)])

        # recover ciphertext
        for i in range(len(S_w)):
            for j in range(len(S_w[i])):
                S_w[i][j] = phe.EncryptedNumber(pk, S_w[i][j])

        # print("S={}".format(S))
        #print("S_w={}".format([int("".join([str(sk.decrypt(val)) for val in item]),2) for item in S_w]))
        # print("S_l={}".format(S_l))
        #
        X_l = set()
        X_res = [0]*len(X)
        for j in range(len(S_l)):
            for l in range(k):
                if S[l] == S_l[j]:
                    X_res[j] = X[l]
                    X_l.add(l)

        #
        x1, x2 = list(set(S)-X_l)
        # print("x1={},x2={}".format(x1,x2))
        for j, expr2 in enumerate(S_w):
            P = [None, None]
            for idx, x in enumerate([x1, x2]):
                expr = "{0:b}".format(S[x]).zfill(bit_length)
                P[idx] = expr2[0]
                if expr[0] == '0':
                    P[idx] = 1-P[idx]
                for bidx in range(1, bit_length):
                    if expr[bidx] == '0':
                        P[idx] = self._SM(P[idx], 1-expr2[bidx])
                    else:
                        P[idx] = self._SM(P[idx], expr2[bidx])
            # print("j={},P1={},P2={}".format(j,sk.decrypt(P[0]),sk.decrypt(P[1])))
            d = len(X[x1][0])
            X_res[len(S_l)+j] = [
                [self._SM(X[x1][0][didx], P[0])+self._SM(X[x2][0][didx], P[1])
                 for didx in range(d)],
                self._SM(X[x1][1], P[0])+self._SM(X[x2][1], P[1])
            ]
        return X_res

    # get distance(a,b)²
    def _SSED(self, a: list, b: list) -> phe.EncryptedNumber:
        assert(len(a) >= 2)
        assert(len(b) >= 2)
        dis = pk.encrypt(0)
        for didx in range(2):
            dis = dis+self._SM(a[didx]-b[didx], a[didx]-b[didx])
        return dis

    # Secure Integer Comparison Protocol
    # 当a<=b return 1,否则return 0
    # level为1时返回密文
    def _SIC(self, a: phe.EncryptedNumber, b: phe.EncryptedNumber, level=0) -> Union[int, phe.EncryptedNumber]:
        X = self._times(a, 2)
        Y = self._times(b, 2)+1
        coin = pk.get_random_lt_n() % 2
        if coin == 1:
            z = X-Y
        else:
            z = Y-X
        max_bit_length = int(utility.getMaxBitLength(pk.n)/4-2)
        # r=1
        r = int(pk.get_random_lt_n() % (2**max_bit_length))+1

        c = self._times(z, r)
        ret = self.DAP_server._SIC(c.ciphertext(), level)
        if level == 1:
            ret = phe.EncryptedNumber(pk, ret)
        if coin == 1:
            return ret
        else:
            return 1-ret

    def _SVC(self, a: List[phe.EncryptedNumber], b: List[phe.EncryptedNumber], level=0) -> List[Union[int, phe.EncryptedNumber]]:

        int_bit_length = 32

        coin = pk.get_random_lt_n() % 2
        coin = 1
        if coin == 1:
            Z = [self._times(a[i], 2)-(self._times(b[i], 2) + 1) + 2**(int_bit_length-1)
                 for i in range(len(a))]
        else:
            Z = [(self._times(b[i], 2)+1)-self._times(a[i], 2) + 2**(int_bit_length-1)
                 for i in range(len(a))]

        max_bit_length = utility.getMaxBitLength(pk.n)

        r = 1
        #r = int(pk.get_random_lt_n() % (2**max_bit_length))+1

        Z = [self._times(z, r) for z in Z]

        # 固定明文位长，计算需要的密文数量
        num_int_per_ciphertext = int(max_bit_length/int_bit_length)
        num_ciphertext = int(math.ceil(len(Z)/num_int_per_ciphertext))

        C = [pk.encrypt(0)]*num_ciphertext

        idx = 0
        for i in range(num_ciphertext):
            # idx~idx+min(num_int_per_ciphertext,len(Z))填充到C[i]中
            s, e = idx, min(idx+num_int_per_ciphertext, len(Z))
            for j in range(s, e):
                C[i] = C[i] + \
                    self._times(Z[j], pow(2, int_bit_length*(e-s-j-1)))

        ret = self.DAP_server._SVC([c.ciphertext() for c in C], level)
        print(ret)

        res = []

        for i in range(num_ciphertext-1):
            for j in range(num_int_per_ciphertext):
                if level == 0:
                    res.append(ret[i][j])
                else:
                    res.append(phe.EncryptedNumber(pk, ret[i][j]))
        rest = len(Z)-len(res)
        for i in range(rest):
            if level == 0:
                if coin == 1:
                    res.append(ret[-1][num_int_per_ciphertext-rest+i])
                else:
                    res.append(1-ret[-1][num_int_per_ciphertext-rest+i])
            else:
                if coin == 1:
                    res.append(phe.EncryptedNumber(
                        pk, ret[-1][num_int_per_ciphertext-rest+i]))
                else:
                    res.append(1 - phe.EncryptedNumber(pk,
                               ret[-1][num_int_per_ciphertext-rest+i]))
        return res

    def _SDDC(self, a: List[phe.EncryptedNumber], b: List[phe.EncryptedNumber], q: List[phe.EncryptedNumber]) -> int:
        d_a, d_b = self._SSED(a, q), self._SSED(b, q)
        s_a, s_b = copy.deepcopy(d_a), copy.deepcopy(d_b)
        for i in range(2, len(a)):
            s_a = s_a+a[i]
            s_b = s_b+b[i]
        delta = self._SIC(s_b, s_a)
        if delta == 0:
            return 0
        C = self._SVC([d_a].extend([a[i] for i in range(2, len(a))], [
                      d_b].extend([b[i] for i in range(2, len(b))])), level=0)
        assert(len(C) == len(a)-1)

        res = C[0]
        for i in range(1, len(C)):
            res = res & C[i]  # self._SM(res, C[i])
        return res

    def _check_in(self, C: List[utility.ERTreeEntry], q: List[phe.EncryptedNumber]) -> int:
        for idx, o_l in C:
            if self._SDDC(o_l._rect[LEFT_BOTTOM_CORNER], o_l._rect[RIGHT_UP_CORNER], q) == 1 and\
                    self._SDDC(o_l._rect[RIGHT_UP_CORNER], o_l._rect[LEFT_BOTTOM_CORNER], q) == 0:
                return 1
        return 0

    def _SLBC(self, Z: utility.ERTreeEntry, q: List[phe.EncryptedNumber], C: List[utility.ERTreeEntry]):
        for i, o in enumerate(Z._entries):
            if Z._level > 2 and self._check_in(C, q):
                self._SLBC(o, q, C)
            else:
                for o_l in C:
                    if self._SDDC(o_l._rect[LEFT_BOTTOM_CORNER], o_l._rect[RIGHT_UP_CORNER], q) == 1:
                        o_l._score = (o_l._count) % pk.n

    def _SLTD(self, root: utility.ERTreeEntry, q: List[phe.EncryptedNumber], k: int):
        H = []
        F = set()
        phi = pk.encrypt(0)
        self._SLBC(root, q, root._entries)
        W = []

        EXIST, ANY = 1, 0

        def _check_in(o: utility.ERTreeEntry, type=EXIST):
            for p in F:
                if self._SDDC(p, q, o._rect[LEFT_BOTTOM_CORNER]) == 1:
                    return type == EXIST
            return type != EXIST

        for entry in root._entries:
            heappush(H, entry)

        while len(H) > 0:
            o = heappop(H)
            if self._SIC(entry._score, phi) == 1 and _check_in(o, EXIST):
                break
            if o._level > 2:
                C = [o_c for o_c in o._entries if _check_in(o_c, ANY)]
                self._SLBC(root, q, C)
                for o_c in o:
                    heappush(H, o_c)
            else:
                Z = utility.B(o)
                self.UpdateResult(W, F, Z, q, phi, o)
        return W

    def UpdateResult(self,  W: list,
                     F: set,
                     Z: List[List[phe.EncryptedNumber]],
                     q: List[phe.EncryptedNumber],
                     phi: phe.EncryptedNumber,
                     o: utility.ERTreeEntry,
                     root: utility.ERTreeEntry
                     ):
        T = set()
        
        EXIST, ANY = 1, 0

        def _check_in(p_e:List[phe.EncryptedNumber], type=ANY):
            for p in F:
                if self._SDDC(p, q, p_e) == 1:
                    return type == EXIST
            return type != EXIST
        
        for p_e in Z:
            if _check_in(p_e, ANY):
                T.add((p_e, o._score))
        
        if len(T) > self._threshold:
            self._SLBC(root, q, [p_e for p_e, _ in T])
            for p_e, score in T:
                epsilon = self._SIC(score, phi, USE_CIPHERTEXT)
                # k-th phi , how k is determined
                o_tmp, o_tmp_score = self._SM(epsilon, p_e)
                
            

    # return E(-a)
    def _ciphertextRevert(self, a: phe.EncryptedNumber) -> phe.EncryptedNumber:
        tmp = phe.phe.util.powmod(a.ciphertext(), pk.n-1, pk.nsquare)
        return phe.EncryptedNumber(pk, tmp)

    # return times×a
    def _times(self, a: phe.EncryptedNumber, times: int) -> phe.EncryptedNumber:
        return phe.EncryptedNumber(pk, phe.phe.util.powmod(a.ciphertext(), times, pk.nsquare))
    # Secure mul

    def _SM(self, a: phe.EncryptedNumber, b: phe.EncryptedNumber) -> phe.EncryptedNumber:
        # 稍后修改
        return pk.encrypt(sk.decrypt(a)*sk.decrypt(b))


with DSPServer(('localhost', 8000),
               requestHandler=RequestHandler) as server:

    # 为ERTreeEntry提供密文分数上的比较方法
    utility.ERTreeEntry.cmpFunctor = server._SIC
    # print(server)
    # def decorate(func):
    #     def wrapper(*args):
    #         func(server,*args)
    #     return wrapper
    # print(server._SIC(pk.encrypt(1), pk.encrypt(2)))  # 1
    # print(server._SIC(pk.encrypt(1), pk.encrypt(1)))  # 1
    # print(server._SIC(pk.encrypt(2), pk.encrypt(1)))  # 0
    # print(server._SIC(pk.encrypt(100), pk.encrypt(200)))  # 1
    print(sk.decrypt(server._SSED(
        [pk.encrypt(10), pk.encrypt(20)], [pk.encrypt(20), pk.encrypt(10)])))
    print(server._SVC([pk.encrypt(3), pk.encrypt(1), pk.encrypt(2)], [
          pk.encrypt(2), pk.encrypt(3), pk.encrypt(4)]))
    # .DAP_server._SVC([pk.encrypt((-55340232234013556739)%pk.n).ciphertext()])

    server.register_introspection_functions()

    server.register_function(server.topkQuery, name="topkQuery")
    # server.register_function(decorate(server.topkQuery),name="topkQuery")

    server.serve_forever()