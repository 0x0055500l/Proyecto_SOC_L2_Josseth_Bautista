from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import argparse

parser=argparse.ArgumentParser(description='Vista local de ATLAS SOC')
parser.add_argument('--port',type=int,default=8791)
args=parser.parse_args()
root=Path(__file__).resolve().parent/'dist'

class Handler(SimpleHTTPRequestHandler):
    extensions_map={**SimpleHTTPRequestHandler.extensions_map,'.mjs':'text/javascript','.js':'text/javascript','.wasm':'application/wasm'}
    def __init__(self,*a,**kw):
        super().__init__(*a,directory=str(root),**kw)

print(f'ATLAS SOC: http://127.0.0.1:{args.port}/',flush=True)
ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
