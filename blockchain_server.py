from flask import Flask
from flask import jsonify

import blockchain
import wallet

app = Flask(__name__)

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.config['port'] = port

    app.run(host = '0.0.0.0', port=port, threaded=True, debug=True)