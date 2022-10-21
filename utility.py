from heapq import heappop, heappush
import numpy as np
from queue import Queue
from rtreelib import RTree, Rect, RTreeNode, RTreeEntry
from phe import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
import phe
from shapely.geometry import box, Point, LineString, Polygon
from geodaisy import converters
import json
from typing import Callable, List, Union
import sys
import math

pk, sk = phe.generate_paillier_keypair(n_length=1024)


def getMaxBitLength(a: int):
    return int(math.floor(math.log2(a)) + 1)


def encryptPolygon(pk: PaillierPublicKey, poly: Polygon):
    geo_json = converters.wkt_to_geojson(poly.wkt)
    res = []
    for p in json.loads(geo_json)["coordinates"][0]:
        res.append([])
        for v in p:
            res[-1].append(pk.encrypt(v))
    return res


def decryptPolygon(sk: PaillierPrivateKey, encrypted_poly: List[List[EncryptedNumber]]) -> Polygon:
    plain_polygon = [[sk.decrypt(v2) for v2 in v1] for v1 in encrypted_poly]
    poly = Polygon([Point(*val) for val in plain_polygon])
    return poly


def getMBR(entries: List[RTreeEntry]) -> box:
    min_x, min_y = sys.maxsize, sys.maxsize
    max_x, max_y = -sys.maxsize, -sys.maxsize
    for entry in entries:
        min_x, min_y = min(min_x, entry.rect.min_x), min(
            min_y, entry.rect.min_y)
        max_x, max_y = max(max_x, entry.rect.max_x), max(
            max_y, entry.rect.max_y)
    return box(min_x, min_y, max_x, max_y)


class ERTreeEntry:
    cmpFunctor = None

    def __init__(self, pk: PaillierPublicKey, entry: Union[RTreeEntry, RTreeNode]):

        self._level = 0
        self._count = 0
        self._score = pk.encrypt(0)
        # 树根，需要手动构造rect
        if type(entry) == RTreeNode:
            self._is_leaf = False
            self._entries = []
            # 以逆时针保存顶点，_rect[1]表示右上角，_rect[-2]表示左下角
            self._rect = encryptPolygon(pk, getMBR(entry.entries))
            return
        if entry.is_leaf == False:
            self._is_leaf = False
            self._entries = []
            b = box(entry.rect.min_x, entry.rect.min_y,
                    entry.rect.max_x, entry.rect.max_y)
            self._rect = encryptPolygon(pk, b)
        else:
            self._is_leaf = True
            self._data = [pk.encrypt(val) for val in entry.data]

            #
    def __lt__(self, other):
        if ERTreeEntry.cmpFunctor:
            return not ERTreeEntry.cmpFunctor(other._score, self.score)


def encryptRTree(pk: PaillierPublicKey, t: RTree) -> ERTreeEntry:
    height = len(t.get_levels()) + 1
    root = ERTreeEntry(pk, t.root)
    root._level = height
    # 层序遍历
    q = Queue()
    for entry in t.root.entries:
        q.put((entry, root))
    i = height-1
    while q.qsize():
        size = q.qsize()
        while size:
            size -= 1
            curNode, par = q.get()
            eentry = ERTreeEntry(pk, curNode)
            eentry._level = i
            par._entries.append(eentry)
            assert(type(curNode) == RTreeEntry)
            if curNode.is_leaf == False:
                for entry in curNode.child.entries:
                    q.put((entry, eentry))
        i -= 1
    return root


def traverseERTree(root: ERTreeEntry, fn: Callable[[ERTreeEntry], None]):
    fn(root)
    if root._is_leaf == True:
        return
    else:
        for entry in root._entries:
            traverseERTree(entry, fn)


def countRecur(root: ERTreeEntry):
    if root._is_leaf == True:
        root._count = 1
    else:
        acc = 0
        for entry in root._entries:
            countRecur(entry)
            acc += entry._count
        root._count = acc
# 计数每个结点的孩子数


def count(root: ERTreeEntry):
    countRecur(root)

    def fn(root: ERTreeEntry):
        root._count = pk.encrypt(root._count)
    # 加密count
    traverseERTree(root, fn)


def read(path='data/test_2_12.txt'):
    points = np.loadtxt(path, delimiter=' ')
    return points


def test_TraverseRTree():

    t = RTree(min_entries=3, max_entries=8)
    points = read()
    for i, p in enumerate(points):
        t.insert(p[2:], Rect(p[0], p[1], p[0], p[1]))

    # 层序遍历
    q = Queue()
    for entry in t.root.entries:
        q.put(entry)
    i = 0
    while q.qsize():
        print("level ", i)
        size = q.qsize()
        while size:
            size -= 1
            cur_node = q.get()
            assert(type(cur_node) == RTreeEntry)
            if cur_node.is_leaf == False:
                print("\t", [val for val in cur_node.rect])
                entries = cur_node.child.entries
                for entry in entries:
                    q.put(entry)
            else:
                print("\t", [val for val in cur_node.data])
        i += 1


def test_EncryptRTree():
    t = RTree(min_entries=3, max_entries=8)
    points = read()
    for i, p in enumerate(points):
        t.insert(p[2:], Rect(p[0], p[1], p[0], p[1]))
    et = encryptRTree(pk, t)
    # count(et)
    # print(et)
    blindEncryptRTree(et)


def getLevel2(root: ERTreeEntry):
    q = Queue()
    q.put((root, None))
    level2 = []
    while not q.empty():
        size = q.qsize()
        while size:
            size -= 1
            cur, par = q.get()

            # 若给level2，合并孩子
            if cur._level == 2:
                level2.append((cur, par))
                while not q.empty():
                    tmp, tmppar = q.get()
                    if tmp._level == 2:
                        level2.append((tmp, tmppar))
                    else:
                        break
                break

            if cur._is_leaf == False:
                for entry in cur._entries:
                    q.put((entry, cur))
    return level2


def blindEncryptRTree(root: ERTreeEntry):
    level2 = getLevel2(root)
    s = 0
    e = 0
    n = len(level2)
    res = []
    while e < n:
        par = level2[s][1]
        while e < n and level2[e][1] == par:
            e += 1
        res.append([])
        for i in range(s, e):
            res[-1].append(level2[i][0])
        s = e

    # 合并
    for lst in res:
        dataArea = []
        for entry in lst:
            for leafEntry in entry._entries:
                dataArea.extend(leafEntry._data)
            entry._dataMatrix = [
                len(dataArea) - len(entry._entries), len(dataArea)]
            entry._entries = dataArea


def B(entry: ERTreeEntry)->List[List[phe.EncryptedNumber]]:
    assert(entry._level == 2)
    return entry._entries[entry._dataMatrix[0], entry._dataMatrix[0]]


def permute(lst: list):
    return listMoveLeft(lst, 1)


def rePermute(lst: list):
    return listMoveRight(lst, 1)

# A为原始列表，a为左移位数


def listMoveLeft(A, a):
    for i in range(a):
        A.insert(len(A), A[0])
        A.remove(A[0])
    return A
# A为原始列表，a为右移位数


def listMoveRight(A, a):
    for i in range(a):
        A.insert(0, A.pop())
    return A


def test_heap():
    class person(object):
        def __init__(self, name, score):
            self.name = name
            self.score = score

        def __lt__(self, other):
            return self.score > other.score

        def getScore(self, type):
            if type == 1:
                return self.name
            else:
                return self.score

    p1 = person("张三", 15)
    p2 = person("李四", 23)
    p3 = person("王五", 12)
    p4 = person("朱五", 32)
    pq = []
    heappush(pq, p1)
    heappush(pq, p2)
    heappush(pq, p3)
    heappush(pq, p4)

    print(heappop(pq).name)
    print(heappop(pq).name)
    print(heappop(pq).name)
    print(heappop(pq).name)

    func = p1.getScore
    print(func(1))


def oct2tf(n: int):
    res = ''
    while 1:
        if n:
            res = str(n % 25)+" "+res
            n = int(n/25)
        else:
            break
    print(res)


if __name__ == "__main__":
    # lst=[0,1,2,3,4,5,6]
    # plst=permute(lst)
    # print(plst)
    # print(rePermute(plst))
    # test_TraverseRTree()
    # test_EncryptRTree()
    # test_heap()
    # oct2tf(25*25*25+25*25+24)
    # print(sk.decrypt(phe.EncryptedNumber(pk, 0)) % pk.n)
    print(2**(32*8) - int(17427837550325006964220455868666983721929980374831474853756604175645848103901551705016654656038859193991389623134168850601886116570446278302448139124273156105094222026291672960014102862164327770489215877638276585344863812851502161610141497115171751335229803121560516637637627245416754744445681414523269559512963359647039465536922203586426184230110563043961412371630170806715482983634832513735409752728092062529689285793697376019849514339399829734002605889047996369105477699482831775883463818492197433378712707377753955038838774017516116050152648829581042874982274332755206412722264817979738249461861780721190932559031))
    print(getMaxBitLength(int(17427837550325006964220455868666983721929980374831474853756604175645848103901551705016654656038859193991389623134168850601886116570446278302448139124273156105094222026291672960014102862164327770489215877638276585344863812851502161610141497115171751335229803121560516637637627245416754744445681414523269559512963359647039465536922203586426184230110563043961412371630170806715482983634832513735409752728092062529689285793697376019849514339399829734002605889047996369105477699482831775883463818492197433378712707377753955038838774017516116050152648829581042874982274332755206412722264817979738249461861780721190932559031)))
