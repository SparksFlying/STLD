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
    
