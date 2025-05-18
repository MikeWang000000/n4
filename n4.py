#!/usr/bin/env python3

from typing import Optional, Tuple, List
import argparse
import logging
import struct
import socket
import select
import time
import sys

args = argparse.Namespace()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(filename)s:%(lineno)d] %(message)s"
)

class N4Error:
    class InvalidPacket(Exception):
        pass
    class PunchFailure(Exception):
        pass

class N4Packet:

    # packet format:
    #   [ command (1 byte) | reserved (1 byte) | data (6 bytes) ]

    SIZE      = 8

    CMD_HELLO = 0x01    # client --TCP-> server
    CMD_READY = 0x02    # client <-TCP-- server
    CMD_EXCHG = 0x03    # client --UDP-> server
    CMD_PINFO = 0x04    # client <-TCP-- server
    CMD_PUNCH = 0x05    # client <-UDP-> client

    RESERVED  = 0x00

    @staticmethod
    def hello(ident: bytes) -> bytes:
        pkt = struct.pack(
            "!BB6s", N4Packet.CMD_HELLO, N4Packet.RESERVED, ident
        )
        return pkt

    @staticmethod
    def dec_hello(pkt: bytes) -> Optional[bytes]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ident = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_HELLO:
            return None
        return ident

    @staticmethod
    def ready() -> bytes:
        pkt = struct.pack(
            "!BB6s", N4Packet.CMD_READY, N4Packet.RESERVED, b""
        )
        return pkt

    @staticmethod
    def dec_ready(pkt: bytes) -> Optional[bool]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, _ = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_READY:
            return None
        return True

    @staticmethod
    def exchange(ident: bytes) -> bytes:
        pkt = struct.pack(
            "!BB6s", N4Packet.CMD_EXCHG, N4Packet.RESERVED, ident
        )
        return pkt

    @staticmethod
    def dec_exchange(pkt: bytes) -> Optional[bytes]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ident = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_EXCHG:
            return None
        return ident

    @staticmethod
    def peerinfo(peeraddr: Tuple[str, int]) -> bytes:
        ip, port = peeraddr
        ipb = socket.inet_aton(ip)
        pkt = struct.pack(
            "!BB4sH", N4Packet.CMD_PINFO, N4Packet.RESERVED, ipb, port
        )
        return pkt

    @staticmethod
    def dec_peerinfo(pkt: bytes) -> Optional[Tuple[str, int]]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ipb, port = struct.unpack("!BB4sH", pkt)
        if cmd != N4Packet.CMD_PINFO:
            return None
        ip = socket.inet_ntoa(ipb)
        peeraddr = (ip, port)
        return peeraddr

    @staticmethod
    def punch(ident: bytes) -> Optional[bytes]:
        pkt = struct.pack(
            "!BB6s", N4Packet.CMD_PUNCH, N4Packet.RESERVED, ident
        )
        return pkt

    @staticmethod
    def dec_punch(pkt: bytes) -> Optional[bytes]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ident = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_PUNCH:
            return None
        return ident


class N4Server:
    ident       : bytes
    bind_port   : int
    sock        : Optional[socket.socket]
    usock       : Optional[socket.socket]
    conn        : List[socket.socket]

    def __init__(self, ident: bytes, bind_port: int) -> None:
        self.ident = ident
        self.bind_port = bind_port
        self.sock = None
        self.usock = None
        self.conn = []

    def _init_sock(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_REUSEADDR"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(("0.0.0.0", self.bind_port))
        self.sock.listen(5)

        self.usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_REUSEADDR"):
            self.usock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            self.usock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.usock.bind(("0.0.0.0", self.bind_port))

        logging.info("Listening on TCP/%d and UDP/%d" % (self.bind_port, self.bind_port))

    def _close_all_sock(self) -> None:
        if self.sock:
            self.sock.close()

        if self.usock:
            self.usock.close()

        while self.conn:
            s = self.conn.pop()
            s.close()

    def _clear_usock_buff(self) -> None:
        while True:
            r, w, x = select.select([self.usock], [], [], 0)
            if not r:
                return
            self.usock.recvfrom(0xffff)

    @staticmethod
    def _sock_same_peer_ip(sock, addr):
        return sock.getpeername()[0] == addr[0]

    def _wait_client(self) -> None:
        while len(self.conn) < 2:
            c, addr = self.sock.accept()
            logging.info("New connection: %s:%d" % (addr[0], addr[1]))
            try:
                r, w, x = select.select([c], [], [], 60)
                if r:
                    hello_pkt = r[0].recv(N4Packet.SIZE)
                    recv_ident = N4Packet.dec_hello(hello_pkt)
                    if not recv_ident:
                        raise N4Error.InvalidPacket("Invalid packet from N4 Client")
                    if recv_ident == self.ident:
                        self.conn.append(r[0])
                    else:
                        logging.info("Identifier mismatch. Ignored.")
            except Exception as e:
                logging.error(e)
            finally:
                if c not in self.conn:
                    c.close()

    def serve(self) -> None:
        self._init_sock()
        self._wait_client()
        self._clear_usock_buff()

        ready_pkt = N4Packet.ready()
        self.conn[0].send(ready_pkt)
        self.conn[1].send(ready_pkt)
        ok1 = ok2 = False
        try:
            while True:
                exchg_pkt, addr = self.usock.recvfrom(0xffff)
                recv_ident = N4Packet.dec_exchange(exchg_pkt)
                if not recv_ident:
                    raise N4Error.InvalidPacket("Invalid packet from N4 Client")
                if recv_ident != self.ident:
                    continue

                if not ok1 and self._sock_same_peer_ip(self.conn[0], addr):
                    pinfo_pkt = N4Packet.peerinfo(addr)
                    self.conn[1].send(pinfo_pkt)
                    ok1 = True
                elif not ok2 and self._sock_same_peer_ip(self.conn[1], addr):
                    pinfo_pkt = N4Packet.peerinfo(addr)
                    self.conn[0].send(pinfo_pkt)
                    ok2 = True
                if ok1 and ok2:
                    break
        except Exception as ex:
            logging.error(ex)
        finally:
            self._clear_usock_buff()
            self._close_all_sock()


class N4Client:
    ident            : bytes
    server_host      : str
    server_port      : int
    src_port_start   : int
    src_port_count   : int
    peer_port_offset : int
    allow_cross_ip   : bool
    sock             : Optional[socket.socket]
    pool             : List[socket.socket]

    def __init__(self,
                 ident: bytes,
                 server_host: str, server_port: int,
                 src_port_start: int, src_port_count: int,
                 peer_port_offset: int,
                 allow_cross_ip: bool) -> None:
        self.ident              = ident
        self.server_host        = server_host
        self.server_port        = server_port
        self.src_port_start     = src_port_start
        self.src_port_count     = src_port_count
        self.peer_port_offset   = peer_port_offset
        self.allow_cross_ip     = allow_cross_ip
        self.sock               = None
        self.pool               = []

    def _init_sock(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        for i in range(self.src_port_count):
            port = 0
            if self.src_port_start:
                port = self.src_port_start + i
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if hasattr(socket, "SO_REUSEADDR"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("0.0.0.0", port))
            self.pool.append(sock)

    def _close_all_sock(self) -> None:
        if self.sock:
            self.sock.close()

        while self.pool:
            s = self.pool.pop()
            s.close()

    def punch(self, wait: int) -> Tuple[Tuple[str, int], int]:
        self._init_sock()

        hello_pkt = N4Packet.hello(self.ident)
        self.sock.send(hello_pkt)

        logging.info(" <= Hello ")

        ready_pkt = self.sock.recv(N4Packet.SIZE)
        if not N4Packet.dec_ready(ready_pkt):
            raise N4Error.InvalidPacket("Invalid packet from N4 Server")

        logging.info(" => Ready ")

        exchg_pkt = N4Packet.exchange(self.ident)
        # send three times to avoid packet loss
        for _ in range(3):
            self.pool[0].sendto(
                exchg_pkt, (self.server_host, self.server_port)
            )

        logging.info(" <= Exchange ")

        pinfo_pkt = self.sock.recv(N4Packet.SIZE)
        peer = N4Packet.dec_peerinfo(pinfo_pkt)
        if not peer:
            raise N4Error.InvalidPacket("Invalid packet from N4 Server")

        peer_ip, peer_port = peer
        target = (peer_ip, peer_port + self.peer_port_offset)

        logging.info(" => Peer: %s:%d " % peer)
        logging.info(" [ Target: %s:%d ] " % target)

        punch_pkt = N4Packet.punch(self.ident)
        # repeat five times to avoid packet loss
        for _ in range(5):
            for sock in self.pool:
                sock.sendto(punch_pkt, target)

        logging.info(" <= Punch ")

        etime = time.time() + wait
        while True:
            r, w, x = select.select(self.pool, [], [], etime-time.time())
            if not r:
                self._close_all_sock()
                raise N4Error.PunchFailure

            recv_punch_pkt, recv_peer = r[0].recvfrom(0xffff)
            if recv_punch_pkt == punch_pkt:
                if recv_peer[0] == peer[0]:
                    break
                elif self.allow_cross_ip:
                    break

        logging.info(" => Punch from peer ")

        # Now UDP hole punching is successful.
        # send ten times back to peer to avoid packet loss
        for _ in range(10):
            r[0].sendto(punch_pkt, recv_peer)
            time.sleep(0.2)

        logging.info(" <= Punch ")

        _, src_port = r[0].getsockname()
        self._close_all_sock()

        return recv_peer, src_port


def srv_main():
    ident   = args.a
    port    = args.l
    while True:
        n4s = N4Server(ident, port)
        n4s.serve()


def cli_main():
    ident       = args.a
    server_host = args.h
    server_port = args.p
    port        = args.b
    count       = args.n
    offset      = args.o
    check_peer  = args.x
    while True:
        try:
            n4c = N4Client(
                ident=ident,
                server_host=server_host,
                server_port=server_port,
                src_port_start=port,
                src_port_count=count,
                peer_port_offset=offset,
                allow_cross_ip=check_peer
            )
            logging.info("==================")
            logging.info("Source port: %d-%d" % (port, port+count))
            peer, src_port = n4c.punch(wait=10)
            peer_ip, peer_port = peer
            logging.info("------")
            logging.info("Local port:    %d" % src_port)
            logging.info("Peer address:  %s:%d" % (peer_ip, peer_port))
            logging.info("------")
            logging.info("[ WIN ]")
            logging.info("------")
            logging.info("> nc -u -p %d %s %d" % (src_port, peer_ip, peer_port))
            break
        except N4Error.PunchFailure:
            logging.info("[ LOSE ]")
            port += count
            continue


def main() -> None:
    global args

    def ident_t(a):
        b = str(a).encode("ascii", "ignore").ljust(6)
        if len(b) != 6:
            raise ValueError
        return b

    argp = argparse.ArgumentParser(add_help=False)
    group = argp.add_argument_group("options")
    group.add_argument(
        "-a", type=ident_t, metavar="<ident>", default=b"n4n4n4",
        help="identifier (6 chars max)"
    )
    group = argp.add_argument_group("server options")
    group.add_argument(
        "-s", action="store_true", help="run in server mode"
    )
    group.add_argument(
        "-l", type=int, metavar="<port>", default=1721,
        help="set server port to listen on"
    )
    group = argp.add_argument_group("client options")
    group.add_argument(
        "-c", action="store_true", help="run in client mode"
    )
    group.add_argument(
        "-b", type=int, metavar="<port>", default=30000,
        help="source port start"
    )
    group.add_argument(
        "-n", type=int, metavar="<count>", default=25,
        help="source port count"
    )
    group.add_argument(
        "-o", type=int, metavar="<offset>", default=20,
        help="peer port offset"
    )
    group.add_argument(
        "-h", type=str, help="hostname of N4 server (required)", default=None
    )
    group.add_argument(
        "-p", type=int, help="port of N4 server", default=1721
    )
    group.add_argument(
        "-x", action="store_true", help="allow peer ip NOT get from server"
    )
    args = argp.parse_args()
    if args.s:
        srv_main()
    elif args.c and args.h:
        cli_main()
    else:
        argp.print_help()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        print("\nStopped")
        sys.exit()
