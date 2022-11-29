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
import time
import ctypes
USE_PLAINTEXT = 0
USE_CIPHERTEXT = 1
MIN = 0
MAX = 1

# get pub and priv keys
CA_server = xmlrpc.client.ServerProxy("http://localhost:10801")
pk = phe.PaillierPublicKey(CA_server.getPub())
sk = phe.PaillierPrivateKey(pk, *CA_server.getPri())

assert(sk.decrypt(pk.encrypt(10)) == 10)
#print("--get done--")

LEFT_BOTTOM_CORNER = 0
RIGHT_UP_CORNER = 1

distCache = dict()

entryInfos = dict()


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2', '/RPC3')


def _scores_clear(entry: utility.ERTreeEntry):
    entry._score = pk.encrypt(0)


class DSPServer(SimpleXMLRPCServer):

    def __init__(self, addr: tuple, requestHandler, threshold=4) -> None:
        super().__init__(addr, requestHandler, allow_none=True)
        self.root = None
        self._threshold = threshold

        self.DAP_server = xmlrpc.client.ServerProxy("http://localhost:10802")

    def topkQuery(self, q: List[int], k: int):
        q = [phe.EncryptedNumber(pk, val) for val in q]
        W = self._STLD(self.root, q, k)
        utility.traverseERTree(self.root, _scores_clear)
        distCache.clear()
        return [[[sk.decrypt(val) for val in w[0]], sk.decrypt(w[1])] for w in W]

    # Secure Minimum Extraction
    def _SME(self, X: list) -> list:
        if len(X) < 2:
            return X
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
        # S_w, S_l = self.DAP_server._SME(
        #     [[y[0], y[1].ciphertext()] for y in utility.permute(Y)])
        S_w, S_l = self.DAP_SME(
            [[y[0], y[1].ciphertext()] for y in utility.permute(Y)])

        # recover ciphertext
        for i in range(len(S_w)):
            for j in range(len(S_w[i])):
                S_w[i][j] = phe.EncryptedNumber(pk, S_w[i][j])

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
            dis = dis + self._SM(a[didx] - b[didx], a[didx] - b[didx])
        return dis

    # Secure Integer Comparison Protocol
    # if a <= b then return 1, else return 0
    # when level = 1, result is presented as ciphertext
    def _SIC(self, a: phe.EncryptedNumber, b: phe.EncryptedNumber, level=USE_PLAINTEXT) -> Union[int, phe.EncryptedNumber]:
        X = self._times(a, 2)
        Y = self._times(b, 2)
        Y = Y + pk.encrypt(1)
        coin = pk.get_random_lt_n() % 2
        if coin == 1:
            z = X-Y
        else:
            z = Y-X
        max_bit_length = int(utility.getMaxBitLength(pk.n) / 4 - 2)
        r = int(pk.get_random_lt_n() % (2**max_bit_length))+1

        c = self._times(z, r)
        #ret = self.DAP_server._SIC(c.ciphertext(), level)
        ret = self.DAP_SIC(c.ciphertext(), level)
        if level == 1:
            ret = phe.EncryptedNumber(pk, ret)
        if coin == 1:
            return ret
        else:
            return 1-ret

    # packed SIC
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

        r = int(pk.get_random_lt_n() % (2 ** (max_bit_length / 4 - 2))) + 1

        Z = [self._times(z, r) for z in Z]

        # calc needed number of ciphertexts with solid bit length of plaintext
        num_int_per_ciphertext = int(max_bit_length/int_bit_length)
        num_ciphertext = int(math.ceil(len(Z)/num_int_per_ciphertext))

        C = [None] * num_ciphertext
        for i in range(num_ciphertext):
            C[i] = pk.encrypt(0)

        idx = 0
        for i in range(num_ciphertext):
            # idx~idx+min(num_int_per_ciphertext,len(Z)) fill in C[i]
            s, e = idx, min(idx+num_int_per_ciphertext, len(Z))
            for j in range(s, e):
                C[i] = C[i] + \
                    self._times(Z[j], pow(2, int_bit_length*(e-s-j-1)))
            idx += num_int_per_ciphertext

        #ret = self.DAP_server._SVC([c.ciphertext() for c in C], level)
        ret = self.DAP_SVC([c.ciphertext() for c in C], level)

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

    def _SDDC(self, d_a: phe.EncryptedNumber, d_b: phe.EncryptedNumber, a: List[phe.EncryptedNumber], b: List[phe.EncryptedNumber], q: List[phe.EncryptedNumber]) -> int:
        assert(len(a) == len(b))
        s_a, s_b = copy.deepcopy(d_a), copy.deepcopy(d_b)
        for i in range(2, len(a)):
            s_a = s_a + a[i]
            s_b = s_b + b[i]
        delta = self._SIC(s_b, s_a)
        if delta == 1:
            return 0

        s_a = [d_a]
        s_a.extend([a[i] for i in range(2, len(a))])
        s_b = [d_b]
        s_b.extend([b[i] for i in range(2, len(b))])
        C = self._SVC(s_a, s_b, level=0)
        assert(len(C) == len(a)-1)

        res = C[0]
        for i in range(1, len(C)):
            res = res & C[i]
        return res

    def getDistRelQ(self, obj: utility.ERTreeEntry, q: List[phe.EncryptedNumber], isRect=False, minOrMax=MIN) -> phe.EncryptedNumber:
        if isRect == True:
            if id(obj) in distCache:
                if distCache[id(obj)][minOrMax]:
                    return distCache[id(obj)][minOrMax]
                else:
                    if minOrMax == MIN:
                        dist = self.getMinDistance(obj._rect, q)
                    else:
                        dist = self.getMaxDistance(obj._rect, obj._midPoint, q)
                    distCache[id(obj)][minOrMax] = dist
                    return dist
            else:
                distCache[id(obj)] = [None, None]
                if minOrMax == MIN:
                    dist = self.getMinDistance(obj._rect, q)
                else:
                    dist = self.getMaxDistance(obj._rect, obj._midPoint, q)
                distCache[id(obj)][minOrMax] = dist
                return dist
        else:
            if id(obj) in distCache:
                return distCache[id(obj)]
            else:
                dist = self._SSED(obj._data, q)
                distCache[id(obj)] = dist
                return dist

    def _check_in(self, C: List[utility.ERTreeEntry], o: utility.ERTreeEntry, q: List[phe.EncryptedNumber], isLeaf=False) -> int:
        if isLeaf:
            for p in C:
                d_p = self.getDistRelQ(p, q)
                d_o_max = self.getDistRelQ(o, q, True, MAX)
                d_o_min = self.getDistRelQ(o, q, True, MIN)
                if self._SDDC(d_p, d_o_max, p._data, o._rect[RIGHT_UP_CORNER], q) == 1 and\
                        self._SDDC(d_p, d_o_min, p._data, o._rect[LEFT_BOTTOM_CORNER], q) == 0:
                    return 1
            return 0
        else:
            for o_l in C:
                d_o_l_min = self.getDistRelQ(o_l, q, True, MIN)
                d_o_max = self.getDistRelQ(o, q, True, MAX)
                d_o_l_max = self.getDistRelQ(o_l, q, True, MAX)
                d_o_min = self.getDistRelQ(o, q, True, MIN)
                if self._SDDC(d_o_l_min, d_o_max, o_l._rect[LEFT_BOTTOM_CORNER], o._rect[RIGHT_UP_CORNER], q) == 1 and\
                        self._SDDC(d_o_l_max, d_o_min, o_l._rect[RIGHT_UP_CORNER], o._rect[LEFT_BOTTOM_CORNER], q) == 0:
                    return 1
            return 0

    def _SLBC(self, Z: List[utility.ERTreeEntry], q: List[phe.EncryptedNumber], C: List[utility.ERTreeEntry]):
        # print("SLBC start")
        for o in Z:
            if o._level > 2 and self._check_in(C, o, q, False):
                self._SLBC(o._entries, q, C)
            else:
                for o_l in C:
                    d_o_l_min = self.getDistRelQ(o_l, q, True, MIN)
                    d_o_max = self.getDistRelQ(o, q, True, MAX)
                    # print(entryInfos[id(o_l)].format(str(sk.decrypt(o_l._score))))
                    # print(entryInfos[id(o)].format(str(sk.decrypt(o._score))))
                    # print("o_l min dist to Q:{}".format(str(sk.decrypt(d_o_l_min))))
                    # print("o max dist to Q:{}".format(str(sk.decrypt(d_o_max))))
                    if self._SDDC(d_o_l_min, d_o_max, o_l._rect[LEFT_BOTTOM_CORNER], o._rect[RIGHT_UP_CORNER], q) == 1:
                        tmp = o_l._score + o._count
                        o_l._score.ciphertext = tmp.ciphertext
        # print("SLBC end")

    def _SBC(self, Z: List[utility.ERTreeEntry], q: List[phe.EncryptedNumber], C: List[utility.ERTreeEntry]):
        # print("SBC start")
        for o in Z:
            if o._level > 1 and self._check_in(C, o, q, True):
                if o._level == 2:
                    self._SBC(utility.B(o), q, C)

                else:
                    self._SBC(o._entries, q, C)

            else:
                if o._level > 1:
                    # print("o level > 1")
                    for p in C:
                        d_p = self.getDistRelQ(p, q)
                        d_o = self.getDistRelQ(o, q, True, MIN)
                        if self._SDDC(d_p, d_o, p._data, o._rect[LEFT_BOTTOM_CORNER], q) == 1:
                            tmp = p._score + o._count
                            p._score.ciphertext = tmp.ciphertext
                        # print(entryInfos[id(p)].format(str(sk.decrypt(p._score))))
                        # print(entryInfos[id(o)].format(str(sk.decrypt(o._score))))
                else:
                    # print("o level == 1")
                    for p in C:

                        d_p = self.getDistRelQ(p, q)
                        d_o = self.getDistRelQ(o, q)
                        if self._SDDC(d_p, d_o, p._data, o._data, q) == 1:
                            tmp = p._score + o._count
                            p._score.ciphertext = tmp.ciphertext
                        # print(entryInfos[id(p)].format(str(sk.decrypt(p._score))))
        # print("SLBC end")

    def _STLD(self, root: utility.ERTreeEntry, q: List[phe.EncryptedNumber], k: int):
        H = []
        F = set()
        F_l = set()
        T = set()
        phi = pk.encrypt(0)
        self._SLBC([root], q, [root])
        W = [None] * k
        for i in range(k):
            W[i] = [[None] * self.dim, None]
            for j in range(self.dim):
                W[i][0][j] = pk.encrypt(2**64)
            W[i][1] = pk.encrypt(-1)

        EXIST, ANY = 1, 0

        def _check_in(o: utility.ERTreeEntry, type=EXIST):
            for p in F:
                d_p = self._SSED(p, q)
                d_o = self.getDistRelQ(o, q, True, MIN)
                if self._SDDC(d_p, d_o, p, o._rect[LEFT_BOTTOM_CORNER], q) == 1:
                    return type == EXIST
            return type != EXIST

        heappush(H, root)

        while len(H) > 0:
            o = heappop(H)
            if self._SIC(o._score, phi) == 1 and _check_in(o, EXIST):
                break
            if o._level > 2:
                Z = o._entries
                C = [o_c for o_c in Z if _check_in(o_c, ANY)]
                self._SLBC([root], q, C)
                for o_c in Z:
                    heappush(H, o_c)
            else:
                Z = utility.B(o)
                W, F = self.UpdateResult(
                    W, F, F_l, Z, q, phi, o, self.root, k, T, self._threshold)
        W, F = self.UpdateResult(
            W, F, F_l, [], q, phi, None, self.root, k, T, 0)
        # self.printEntryInfos()
        return W

    def printW(self, W: list):
        for idx, (p, score) in enumerate(W):
            print("{}:[{}], {}".format(idx, ",".join(
                [str(sk.decrypt(val)) for val in p]), str(sk.decrypt(score))))

    def printEntryInfos(self):
        for addr, info in entryInfos.items():
            entry = ctypes.cast(addr, ctypes.py_object).value
            print(info.format(str(sk.decrypt(entry._score))))

    def UpdateResult(self,  W: list,
                     F: set,
                     F_l: set,
                     Z: List[utility.ERTreeEntry],
                     q: List[phe.EncryptedNumber],
                     phi: phe.EncryptedNumber,
                     o: utility.ERTreeEntry,
                     root: utility.ERTreeEntry,
                     k: int,
                     T: set,
                     delta_0: int
                     ):

        EXIST, ANY = 1, 0

        def _check_in(p_e_data: List[phe.EncryptedNumber], type=ANY):
            for p in F:
                d_p = self._SSED(p, q)
                d_p_e = self._SSED(p_e_data, q)
                if self._SDDC(d_p, d_p_e, p, p_e_data, q) == 1:
                    return type == EXIST
            return type != EXIST

        for p_e in Z:
            if _check_in(p_e._data, ANY):
                T.add((p_e, p_e._score))

        if len(T) > delta_0:
            self._SBC([root], q, [p_e for p_e, _ in T])
            for p_e, score in T:
                # print(entryInfos[id(p_e)].format(str(sk.decrypt(score))))
                epsilon = self._SIC(score, phi, USE_CIPHERTEXT)
                o_l = [None] * len(p_e._data)
                for i in range(len(o_l)):
                    o_l[i] = self._SM(epsilon, p_e._data[i]) + \
                        self._SM(1 - epsilon, W[k - 1][0][i])
                o_l_score = self._SM(epsilon, score) + \
                    self._SM(1 - epsilon, W[k - 1][1])
                for i in range(len(o_l)):
                    W[k - 1][0][i] = self._SM(epsilon, W[k - 1][0][i]) + \
                        self._SM(1 - epsilon, p_e._data[i])
                W[k - 1][1] = self._SM(epsilon, W[k - 1][1]) + \
                    self._SM(1 - epsilon, score)

                if self._SIC(o_l_score, pk.encrypt(0), USE_PLAINTEXT) == 0 and _check_in(o_l, ANY):
                    F_l.add(tuple(o_l))
                W = self._SME(W)
                phi.ciphertext = W[k - 1][1].ciphertext
                F = F_l
                F.add(tuple(W[k - 1][0]))
                # print("end")
                # self.printW(W)
            T.clear()
        return W, F

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

    # 1 |  2  | 3
    #    *****
    # 8  * 9 *  4
    #    *****
    # 7 |  6  | 5
    def getMinDistance(self, encRect: List[phe.EncryptedNumber], q: List[phe.EncryptedNumber]):
        assert(len(q) == 2)
        assert(len(encRect) == 2)
        dist = pk.encrypt(0)

        lowFlags = [False, False]
        highFlags = [False, False]

        for i in range(2):
            lowFlags[i] = self._SIC(
                encRect[LEFT_BOTTOM_CORNER][i], q[i], USE_PLAINTEXT)
            highFlags[i] = self._SIC(
                q[i], encRect[RIGHT_UP_CORNER][i], USE_PLAINTEXT)

        if not lowFlags[0] and not lowFlags[1]:
            df = [encRect[LEFT_BOTTOM_CORNER][i] - q[i] for i in range(2)]
            dist = self._SM(df[0], df[0]) + self._SM(df[1], df[1])
        elif not lowFlags[0] and lowFlags[1] and highFlags[1]:
            df0 = encRect[LEFT_BOTTOM_CORNER][0] - q[0]
            dist = self._SM(df0, df0)
        elif not lowFlags[0] and not highFlags[1]:
            df0 = encRect[LEFT_BOTTOM_CORNER][0] - q[0]
            df1 = encRect[RIGHT_UP_CORNER][1] - q[1]
            dist = self._SM(df0, df0) + self._SM(df1, df1)
        elif lowFlags[0] and highFlags[0] and not highFlags[1]:
            df1 = q[1] - encRect[RIGHT_UP_CORNER][1]
            dist = self._SM(df1, df1)
        elif not highFlags[0] and not highFlags[1]:
            df0 = encRect[RIGHT_UP_CORNER][0] - q[0]
            df1 = encRect[RIGHT_UP_CORNER][1] - q[1]
            dist = self._SM(df0, df0) + self._SM(df1, df1)
        elif not highFlags[0] and lowFlags[1] and highFlags[1]:
            df0 = q[0] - encRect[RIGHT_UP_CORNER][0]
            dist = self._SM(df0, df0)
        elif not highFlags[0] and not lowFlags[1]:
            df0 = encRect[RIGHT_UP_CORNER][0] - q[0]
            df1 = encRect[LEFT_BOTTOM_CORNER][1] - q[1]
            dist = self._SM(df0, df0) + self._SM(df1, df1)
        elif lowFlags[0] and highFlags[0] and not lowFlags[1]:
            df1 = encRect[LEFT_BOTTOM_CORNER][1] - q[1]
            dist = self._SM(df1, df1)
        else:
            pass
        return dist

    def getMaxDistance(self, encRect: List[phe.EncryptedNumber], midPoint: List[phe.EncryptedNumber], q: List[phe.EncryptedNumber]):
        assert(len(q) == 2)
        assert(len(midPoint) >= 2)
        xFlag = self._SIC(q[0], midPoint[0], USE_PLAINTEXT)
        yFlag = self._SIC(q[1], midPoint[1], USE_PLAINTEXT)
        if xFlag == 0 and yFlag == 0:
            return self._SSED(q, encRect[LEFT_BOTTOM_CORNER])
        elif xFlag == 0 and yFlag == 1:
            return self._SSED(q, [encRect[LEFT_BOTTOM_CORNER][0], encRect[RIGHT_UP_CORNER][1]])
        elif xFlag == 1 and yFlag == 0:
            return self._SSED(q, [encRect[RIGHT_UP_CORNER][0], encRect[LEFT_BOTTOM_CORNER][1]])
        return self._SSED(q, encRect[RIGHT_UP_CORNER])

    def load(self, filePath='data/anti_2_1000_rtree.txt'):
        t = utility.deSeriRtree(filePath)
        self.dim = len(t.root.rect[LEFT_BOTTOM_CORNER])
        self.root = utility.encryptRTree(pk, sk, entryInfos, t)
        utility.count(self.root, pk)
        # utility.blindEncryptRTree(self.root)

        # def fn(entry: utility.ERTreeEntry):
        #     if entry._is_leaf == True:
        #         print("[{}], count={}".format(",".join([str(sk.decrypt(val)) for val in entry._data]), sk.decrypt(entry._count)))
        #     else:
        #         rect = utility.decryptPolygon(sk, entry._rect).bounds
        #         print("[{}], count={}".format(",".join([str(val) for val in rect]), str(sk.decrypt(entry._count))))
        # utility.traverseERTree(self.root, fn=fn)
    ######################################################################
    # DAP protocols
    def DAP_SME(self, Y: list):
        Y = [[y[0], phe.EncryptedNumber(pk, y[1])] for y in Y]
        n = len(Y)
        bit_length = utility.getMaxBitLength(n)
        for i, y in enumerate(Y):
            p_i = sk.decrypt(y[1])
            Y[i][1] = p_i
        Y.sort(key=lambda x: x[1], reverse=True)
        r2 = int(random.random()*1e3) % (n-1)

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
    def DAP_SIC(self, c: int, level=USE_PLAINTEXT) -> int:
        m = sk.decrypt(phe.EncryptedNumber(pk, c)) % pk.n
        u = 0
        if int(utility.getMaxBitLength(abs(m))) > int(utility.getMaxBitLength(pk.n)/2):
            u = 1
        if level == 0:
            return u
        else:
            return pk.encrypt(u).ciphertext()

    def DAP_SVC(self, C: List[int], level=0) -> List[int]:
        C = [phe.EncryptedNumber(pk, c) for c in C]
        M = [sk.decrypt(c) for c in C]
        int_bit_length = 32
        max_bit_length = utility.getMaxBitLength(pk.n)
        num_int_per_ciphertext = int(max_bit_length/int_bit_length)

        ret = [[]]*len(M)
        all_x = []
        for midx in range(len(M)):
            m_expr = "{0:b}".format(abs(M[midx])).zfill(max_bit_length)
            for idx in range(num_int_per_ciphertext):
                x_i = int(m_expr[idx*int_bit_length:(idx+1) *
                          int_bit_length], 2) - 2**(int_bit_length-1)
                all_x.append(x_i)
                u_i = 0
                if int(utility.getMaxBitLength(x_i % pk.n)) > int(utility.getMaxBitLength(pk.n)/2):
                    u_i = 1
                if level == 0:
                    ret[midx].append(u_i)
                else:
                    ret[midx].append(pk.encrypt(u_i).ciphertext())
        return ret
    ######################################################################


def calcScores(points):
    scores = [0] * len(points)
    for i, p in enumerate(points):
        for j, op in enumerate(points):
            if i == j:
                continue
            domi = False
            notDomi = False
            for k in range(len(p)):
                if p[k] > op[k]:
                    notDomi = True
                    break
                elif p[k] < op[k]:
                    domi = True
                else:
                    pass
            if notDomi:
                continue
            if domi:
                scores[i] += 1
    return scores


def getCorrectScores(points, q: List[int], k: int):
    # points = utility.read()
    res = []
    for i in range(len(points)):
        res.append([])
    for i, p in enumerate(points):
        res[i].append((p[0] - q[0]) * (p[0] - q[0]) +
                      (p[1] - q[1]) * (p[1] - q[1]))
        for j in range(2, len(points[i])):
            res[i].append(p[j])
    scores = calcScores(res)
    id2score = [[i, score] for i, score in enumerate(scores)]
    id2score = sorted(id2score, key=lambda item: item[1], reverse=True)
    minScore = id2score[k - 1][1]
    p2score = dict()
    for item in id2score:
        if item[1] >= minScore:
            p2score[tuple(points[item[0]])] = item[1]
    return p2score


def test_correctness(p2score: dict, server: DSPServer, q: List[int], k: int):
    W = server.topkQuery([pk.encrypt(val).ciphertext() for val in q], k)
    assert(len(W) == k)
    for p, score in W:
        try:
            assert(tuple(p) in p2score)
            assert(p2score[tuple(p)] == score)
        except(AssertionError):
            print("\terror")
            print("\tcorrect answer")
            print(p2score)
            print("\twrong answer")
            print(W)
            print(q)
            print(k)
            exit()
    print("correct")


def test_SIC(server: DSPServer):
    assert(server._SIC(pk.encrypt(1746), pk.encrypt(113)) == 0)  # 0
    assert(server._SIC(pk.encrypt(1), pk.encrypt(2)) == 1)  # 1
    assert(server._SIC(pk.encrypt(2), pk.encrypt(1)) == 0)  # 0
    assert(server._SIC(pk.encrypt(0), pk.encrypt(0)) == 1)  # 1
    assert(server._SIC(pk.encrypt(1), pk.encrypt(1000000)) == 1)  # 1
    assert(server._SIC(pk.encrypt(1000000), pk.encrypt(1)) == 0)  # 0


def test_SVC(server: DSPServer):
    assert(server._SVC([pk.encrypt(1), pk.encrypt(1), pk.encrypt(1)], [
        pk.encrypt(1), pk.encrypt(1), pk.encrypt(1)]) == [1, 1, 1])
    assert(server._SVC([pk.encrypt(3), pk.encrypt(1), pk.encrypt(2)], [
        pk.encrypt(2), pk.encrypt(3), pk.encrypt(4)]) == [0, 1, 1])


def test_getDistance(server: DSPServer):
    encRect = [[pk.encrypt(1), pk.encrypt(11)], [
        pk.encrypt(56), pk.encrypt(43)]]
    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(0), pk.encrypt(44)])) == 1 + 1)
    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(1), pk.encrypt(43)])) == 0)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(28), pk.encrypt(44)])) == 1)
    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(29), pk.encrypt(43)])) == 0)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(57), pk.encrypt(44)])) == 1 + 1)
    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(56), pk.encrypt(43)])) == 0)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(57), pk.encrypt(42)])) == 1)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(57), pk.encrypt(10)])) == 1 + 1)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(28), pk.encrypt(10)])) == 1)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(0), pk.encrypt(0)])) == 1 + 11*11)

    assert(sk.decrypt(server.getMinDistance(
        encRect, [pk.encrypt(0), pk.encrypt(12)])) == 1)

    # max
    assert(sk.decrypt(server.getMaxDistance(encRect, [pk.encrypt(
        28), pk.encrypt(27)], [pk.encrypt(0), pk.encrypt(44)])) == 56*56+33*33)
    assert(sk.decrypt(server.getMaxDistance(encRect, [pk.encrypt(
        28), pk.encrypt(27)], [pk.encrypt(0), pk.encrypt(0)])) == 56*56+43*43)
    assert(sk.decrypt(server.getMaxDistance(encRect, [pk.encrypt(
        28), pk.encrypt(27)], [pk.encrypt(57), pk.encrypt(44)])) == 56*56+33*33)
    assert(sk.decrypt(server.getMaxDistance(encRect, [pk.encrypt(
        28), pk.encrypt(27)], [pk.encrypt(57), pk.encrypt(10)])) == 56*56+33*33)


with DSPServer(('localhost', 8000),
               requestHandler=RequestHandler) as server:

    # 为ERTreeEntry提供密文分数上的比较方法
    utility.ERTreeEntry.cmpFunctor = server._SIC

    server.load('data/test_2_12_rtree.txt')
    
    server.register_introspection_functions()

    server.register_function(server.topkQuery, name="topkQuery")

    server.serve_forever()
