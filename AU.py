import xmlrpc.client
import phe
from typing import Union, List

DSP_server=xmlrpc.client.ServerProxy("http://localhost:8000")
CA_server = xmlrpc.client.ServerProxy("http://localhost:10801")
pk = phe.PaillierPublicKey(CA_server.getPub())


print(DSP_server.system.listMethods())

class AU:
    def query(self, q: List[int], k: int):
        q = [pk.encrypt(val).ciphertext() for val in q]
        DSP_server.topkQuery(q, k)


au = AU()
au.query([1, 2], 2)