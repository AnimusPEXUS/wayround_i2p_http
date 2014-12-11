
import socket
import logging

import org.wayround.utils.socket_server
import org.wayround.http.server
import org.wayround.http.message


def hc(request):
    print("request is:\n{}".format(request))

    #f = request.sock.makefile()
    #print("hc 02")

    #data = f.read()

    #print("hc 03")
    #print("data {}".format(data))

    resp = org.wayround.http.message.HTTPResponse(
        200,
        [('Content-Type','text/plain;codepage=UTF-8')],
        [b'test']
        )
    return resp

hs = org.wayround.http.server.HTTPServer(
    hc
    )

sock = socket.socket()
sock.bind(('127.0.0.1', 8080))
sock.listen(5)

ss = org.wayround.utils.socket_server.SocketServer(
    sock,
    hs.callable_for_socket_server
    )

try:
    ss.start()    
    print("waiting ss")
    ss.wait()
    print("ss exited")
except KeyboardInterrupt:
    ss.stop()
except:
    logging.exception("ERROR")
    
#sock.shutdown()
sock.close()
