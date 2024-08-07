from heapq import heappop, heappush
import numpy as np
from queue import Queue
from phe import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
import phe
from geodaisy import converters
import json
from typing import Callable, List, Union
import sys
import math

Rect = List[List[int]]
Point = List[int]

LEFT_BOTTOM_CORNER = 0
RIGHT_UP_CORNER = 1

pk, sk = phe.generate_paillier_keypair(n_length=1024)


def getMaxBitLength(a: int):
    if a == 0:
        return 1
    return int(math.floor(math.log2(a)) + 1)

# rect = [leftBottom, rightTop], leftBottom = [x0, x1, ..., xd-1]
def encryptRectangle(pk: PaillierPublicKey, rect: Rect):
    assert(len(rect) == 2)
    dim = len(rect[0])
    encRect = []
    for p in rect:
        encRect.append([])
        for i in range(dim):
            encRect[-1].append(pk.encrypt(int(p[i])))
    return encRect


def decryptRectangle(sk: PaillierPrivateKey, encRect: List[List[phe.EncryptedNumber]]) -> Rect:
    dim = len(rect[0])
    rect = []
    for p in rect:
        rect.append([])
        for i in range(dim):
            rect[-1].append(sk.decrypt(p[i]))
    return rect


def getMBR(rects: List[Rect]) -> Rect:
    assert(len(rects) > 0)
    dim = len(rects[0][LEFT_BOTTOM_CORNER])
    mbr = [[sys.maxsize] * dim, [-sys.maxsize] * dim]
    for rect in rects:
        for i in range(dim):
            mbr[LEFT_BOTTOM_CORNER][i] = min(mbr[LEFT_BOTTOM_CORNER][i], rect[LEFT_BOTTOM_CORNER][i])
            mbr[RIGHT_UP_CORNER][i] = max(mbr[RIGHT_UP_CORNER][i], rect[RIGHT_UP_CORNER][i])
    return mbr


class RTreeEntry1:
    def __init__(self) -> None:
        self.is_leaf = None
        self.rect = [None, None]
        self.data = []
        self.entries = []
        
class RTree:
    def __init__(self) -> None:
        self.root = None
        self.height = None
    
    def load(filePath) -> None:
        pass
    
    def getHeight(self):
        return self.height

class ERTreeEntry:
    cmpFunctor = None

    def __init__(self, pk: PaillierPublicKey, entry: RTreeEntry1):

        self._level = 0
        self._count = 0
        self._score = pk.encrypt(0)
        # 树根，需要手动构造rect
        # if type(entry) == RTreeNode:
        #     self._is_leaf = False
        #     self._entries = []
        #     # 以逆时针保存顶点，_rect[1]表示右上角，_rect[-2]表示左下角
        #     self._rect = encryptPolygon(pk, getMBR(entry.entries))
        #     return
        if entry.is_leaf == False:
            self._is_leaf = False
            self._entries = []
            self._rect = encryptRectangle(pk, entry.rect)
            # save mid point of entry.rect
            self._midPoint = [None] * len(entry.rect[LEFT_BOTTOM_CORNER])
            for i in range(len(self._midPoint)):
                self._midPoint[i] = pk.encrypt(int((entry.rect[LEFT_BOTTOM_CORNER][i] + entry.rect[RIGHT_UP_CORNER][i]) / 2))
        else:
            self._is_leaf = True
            self._data = [pk.encrypt(int(val)) for val in entry.data]

            #
    def __lt__(self, other):
        if ERTreeEntry.cmpFunctor:
            return not ERTreeEntry.cmpFunctor(other._score, self._score)

def deSeriRtree(filePath: str) -> RTree:
    with open(filePath, 'r') as f:
        lines = [line for line in f.read().split("e") if line]
        dim, height = [int(val) for val in lines[0].split(' ') if val != '\n' and val != '']
        # for level in levels:
        #     print(level)
        root = RTreeEntry1()
        levelStruct = []
        for i, level in enumerate(lines[1:]):
            level = level.lstrip()
            if not level:
                break
            levelStruct.append([])
            # leaves
            if i == height - 1:
                points = [ [int(float(val)) for val in data.split(',')] for data in level.split(' ')[1:] if data != '\n' and data != '']
                for j, p in enumerate(points):
                    entry = RTreeEntry1()
                    entry.is_leaf = True
                    entry.data = p
                    levelStruct[-1].append(entry)
            else: # non leaves
                items = [val for val in level.split(' ') if val != '\n' and val != '']
                size = int(items[0])
                for j in range(size):
                    entry = RTreeEntry1()
                    entry.is_leaf = False
                    entry.rect[LEFT_BOTTOM_CORNER] = [int(float(val)) for val in items[1 + j * 3].split(',')]
                    entry.rect[RIGHT_UP_CORNER] = [int(float(val)) for val in items[1 + j * 3 + 1].split(',')]
                    entry.entries = [None] * int(items[1 + j * 3 + 2])
                    levelStruct[-1].append(entry)
            if len(levelStruct) > 1:
                idx = 0
                for j in range(len(levelStruct[-2])):
                    for k in range(len(levelStruct[-2][j].entries)):
                        levelStruct[-2][j].entries[k] = levelStruct[-1][idx]
                        idx += 1
        if len(levelStruct[0]) > 1:
            root = RTreeEntry1()
            root.is_leaf = False
            root.rect = getMBR([entry.rect for entry in levelStruct[0]])
            root.entries = levelStruct[0]
            t = RTree()
            t.root = root
            t.height = height + 1
            return t
        t = RTree()
        t.root = levelStruct[0][0]
        t.height = height
        return t          



def encryptRTree(pk: PaillierPublicKey, sk: PaillierPrivateKey, entryInfos: dict, t: RTree) -> ERTreeEntry:
    height = t.getHeight()
    root = ERTreeEntry(pk, t.root)
    entryInfos[id(root)] = "root:[min:{}, max:{}]".format(str(t.root.rect[0]), str(t.root.rect[1])) + ", score:{}"
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
            if curNode.is_leaf == False:
                entryInfos[id(eentry)] = "nonLeaf:[min:{}, max:{}]".format(str(curNode.rect[0]), str(curNode.rect[1])) + ", score:{}"
            else:
                entryInfos[id(eentry)] = "leaf:[{}]".format(str(curNode.data)) + ", score:{}"
            eentry._level = i
            par._entries.append(eentry)
            
            if curNode.is_leaf == False:
                for entry in curNode.entries:
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


def count(root: ERTreeEntry, pk: phe.PaillierPublicKey):
    countRecur(root)

    def fn(root: ERTreeEntry):
        root._count = pk.encrypt(int(root._count))
    # 加密count
    traverseERTree(root, fn)


def read(path='data/test_2_12.txt'):
    points = np.loadtxt(path, delimiter=' ', dtype=np.uint32)
    return points


def test_TraverseRTree():
    
    t = RTree()
    t.load()
    
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
            if cur_node.is_leaf == False:
                print("\t", [val for val in cur_node.rect])
                entries = cur_node.entries
                for entry in entries:
                    q.put(entry)
            else:
                print("\t", [val for val in cur_node.data])
        i += 1


def test_EncryptRTree():
    t = RTree()
    t.load()
    et = encryptRTree(pk, t)
    # count(et, pk)
    # print(et)
    # blindEncryptRTree(et)


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
            start = len(dataArea)
            for leafEntry in entry._entries:
                dataArea.append(leafEntry._data)
            entry._dataMatrix = [start, len(dataArea)]
            entry._entries = dataArea


def B(entry: ERTreeEntry) -> List[ERTreeEntry]:
    assert(entry._level == 2)
    return entry._entries
    # return entry._entries[entry._dataMatrix[0], entry._dataMatrix[1]]


def permute(lst: list):
    if not lst:
        return []
    return listMoveLeft(lst, 1)


def rePermute(lst: list):
    if not lst:
        return []
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


def buildRtree(points: np.array, min_entries = 3, max_entries = 8) -> RTree:
    assert(len(points.shape) == 2)
    assert(points.shape[0] > 0)
    assert(points.shape[1] > 2)
    t=RTree(min_entries = min_entries, max_entries = max_entries)
    for point in points:
        t.insert(data = point, rect = Rect(point[0], point[1], point[0], point[1]))
    return t
        
    

def test_buildRtree():
    points = read()
    t = buildRtree(points)
    pk, sk = phe.generate_paillier_keypair(n_length=1024)
    root = encryptRTree(pk, t)
    count(root, pk)
    blindEncryptRTree(root)
    print("done")

def change(a: phe.EncryptedNumber):
    a.ciphertext = pk.encrypt(0).ciphertext

def test_pass_val_ref():
    a = pk.encrypt(1)
    change(a)
    print(sk.decrypt(a))
    b = pk.encrypt(2)
    c = a + b
    print(sk.decrypt(c))
if __name__ == "__main__":
    t = deSeriRtree('data/test_2_12_rtree.txt')
    et = encryptRTree(pk, t)
    # lst=[0,1,2,3,4,5,6]
    # plst=permute(lst)
    # print(plst)
    # print(rePermute(plst))
    # test_TraverseRTree()
    # test_EncryptRTree()
    # test_heap()
    # oct2tf(25*25*25+25*25+24)
    # print(sk.decrypt(phe.EncryptedNumber(pk, 0)) % pk.n)
    # test_pass_val_ref()
    # a = 36491858199304345395830723440730068116670675985920885413929858751583035298478640634876243898885833283323795243091709199590919990587767358686701199256736755051938258340006566604752767074218992506704969047660508439480876542031565811941489417665846657924461460567121984535277781776044850541326889296177331720408
    # b = 109475574597913036187492170322190204350012027957762656241789576254749105895435921904628731696657499849971385729275127598772759971763302076060103597770210265155814775020019699814258301222656977520114907142981525318442629626094697435824468252997539973773384381701365953605833345328134551623980667888531995161229
    # print(b/a)
    # test_buildRtree()
    # print(getMaxBitLength(100))
    # print(getMaxBitLength(1000))
    # print(getMaxBitLength(10000))
    # print(getMaxBitLength(100000))
    # print(getMaxBitLength(int(17427837550325006964220455868666983721929980374831474853756604175645848103901551705016654656038859193991389623134168850601886116570446278302448139124273156105094222026291672960014102862164327770489215877638276585344863812851502161610141497115171751335229803121560516637637627245416754744445681414523269559512963359647039465536922203586426184230110563043961412371630170806715482983634832513735409752728092062529689285793697376019849514339399829734002605889047996369105477699482831775883463818492197433378712707377753955038838774017516116050152648829581042874982274332755206412722264817979738249461861780721190932559031)))
