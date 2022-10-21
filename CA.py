import phe
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler


pk,sk=phe.generate_paillier_keypair(n_length=1024)
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2', '/RPC3')


with SimpleXMLRPCServer(('localhost', 10801),
                        requestHandler=RequestHandler) as server:
    server.register_introspection_functions()

    @server.register_function(name='getPub')
    def getPub():
        return pk.n
    
    @server.register_function(name='getPri')
    def getPri():
        return sk.p,sk.q

    server.serve_forever()
    
    
"""
1. 熟悉C++编程，具备良好的编码能力与编程规范
2. 具有较强的逻辑分析能力，擅长发现问题以及排查问题
3. 具有良好的团队合作能力，善于协调团队和个人的关系
4. 具有良好的学习习惯，善于领悟、接受新事物和新技术
"""