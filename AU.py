import xmlrpc.client
import phe
DSP_server=xmlrpc.client.ServerProxy("http://localhost:8000")



print(DSP_server.system.listMethods())

print(DSP_server.topkQuery(2))