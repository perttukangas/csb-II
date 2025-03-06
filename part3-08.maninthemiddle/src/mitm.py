import http.server as hs
import requests
import sys


class Mitm(hs.BaseHTTPRequestHandler):
    remote_address = None  # domain name to connect

    def do_GET(self):
        resp = requests.get(self.remote_address + self.path)

        self.send_response(resp.status_code)
        self.send_header("Content-type", resp.headers["Content-type"])

        if resp.headers["Content-type"] == "text/html":
            self.end_headers()
            self.wfile.write(resp.text.upper().encode())
        else:
            self.end_headers()
            self.wfile.write(resp.content)


def start_server(local_port, remote_address):
    Mitm.remote_address = remote_address
    server = hs.HTTPServer(("localhost", local_port), Mitm)
    server.serve_forever()


# This makes sure the main function is not called immediately
# when TMC imports this module
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python %s local_port remote_address" % sys.argv[0])
    else:
        start_server(int(sys.argv[1]), sys.argv[2])
