"""/ws/mqtt side channel (MQTT 3.1.1 + protobuf) for the Terncy integration.

`python-terncy`, which the gateway is built on, only speaks `/ws/json`. That
endpoint's attribute vocabulary is a fixed, closed table (recovered from the
hub's `/system/lib/libwsserver.so`, see
`docs/wsjson-attrkey-table-20261012.md`) that contains neither the switch
button-LED (`AttrID 41`, `cfg-button-led-status`) nor the dial angle
(`AttrID 33`, `last-dial-angle`).  Both properties exist only on the hub's
`/ws/mqtt` endpoint - the channel the mobile App uses - which speaks MQTT 3.1.1
carrying protobuf messages.

This module implements the minimum of that transport needed for the two
features:

* encode a `WriteAttributeRequest` to control the button-LED;
* decode device attribute reports so the dial angle can be surfaced.

It is fully self-contained (no MQTT client library) and is only instantiated
when the user supplies the hub MQTT credentials in the integration options.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import ssl
import struct
import time
from collections.abc import Callable

from ..const import MQTT_READABLE_ATTRS

# WebSocket
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA

# MQTT
_MQTT_KEEPALIVE = 60
_MQTT_PING_INTERVAL = 45.0
_MQTT_WRITE_TIMEOUT = 10.0

RECONNECT_MIN = 3.0
RECONNECT_MAX = 300.0

_uuid_seq = 0


def _new_uuid() -> str:
    """Build a non-zero, time-based UUID (v1 layout).

    The hub rejects an all-zero request UUID with `#10{code}`, so we do not
    depend on `uuid.uuid4()` (which was observed to return zeros on some
    broken builds).
    """
    global _uuid_seq
    _uuid_seq += 1
    ts = time.time_ns() // 100
    time_low = ts & 0xFFFFFFFF
    time_mid = (ts >> 32) & 0xFFFF
    time_hi = ((ts >> 48) & 0x0FFF) | 0x1000
    clk = 0x8000 | (_uuid_seq & 0x3FFF)
    node = int.from_bytes(os.urandom(6), "big") | 0x010000000000
    return "%08x-%04x-%04x-%04x-%012x" % (time_low, time_mid, time_hi, clk, node)


# --------------------------------------------------------------------------- #
# protobuf (wire format)
# --------------------------------------------------------------------------- #
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _pb_ld(field: int, data: bytes) -> bytes:
    return _varint((field << 3) | 2) + _varint(len(data)) + data


def _pb_vi(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _pb_read_varint(buf: bytes, i: int):
    value = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7


def _pb_fields(buf: bytes):
    """Yield (field, wire_type, value) for a protobuf message."""
    i = 0
    n = len(buf)
    while i < n:
        key, i = _pb_read_varint(buf, i)
        field, wire = key >> 3, key & 0x07
        if wire == 0:
            value, i = _pb_read_varint(buf, i)
        elif wire == 2:
            ln, i = _pb_read_varint(buf, i)
            value = buf[i : i + ln]
            i += ln
        elif wire == 5:
            value = buf[i : i + 4]
            i += 4
        elif wire == 1:
            value = buf[i : i + 8]
            i += 8
        else:
            return
        yield field, wire, value


def _to_signed(value: int) -> int:
    """Interpret a raw varint as two's-complement 64-bit.

    The hub stores attribute values as signed ints; a negative dial angle (e.g.
    -12) is sign-extended by protobuf into a 10-byte varint, which reads back as
    a large unsigned number unless reinterpreted.
    """
    return value - (1 << 64) if value >= (1 << 63) else value


# --------------------------------------------------------------------------- #
# MQTT 3.1.1
# --------------------------------------------------------------------------- #
def _mqtt_packet(type_flags: int, payload: bytes) -> bytes:
    return bytes([type_flags]) + _varint(len(payload)) + payload


def _mqtt_str(value: str | bytes) -> bytes:
    data = value.encode() if isinstance(value, str) else value
    return struct.pack(">H", len(data)) + data


def _mqtt_parse(buf: bytes):
    """Return (type, flags, body, consumed) or None if incomplete."""
    if len(buf) < 2:
        return None
    value = 0
    mult = 0
    i = 1
    while True:
        if i >= len(buf):
            return None
        bte = buf[i]
        value |= (bte & 0x7F) << (7 * mult)
        i += 1
        if not bte & 0x80:
            break
        mult += 1
        if mult > 3:
            return None
    total = i + value
    if len(buf) < total:
        return None
    return buf[0] >> 4, buf[0] & 0x0F, bytes(buf[i:total]), total


def _mqtt_connect(client_id: str, username: str, password: str) -> bytes:
    # The hub requires BOTH the username and password *flags* to be set even
    # when the password value is empty, otherwise it rejects the CONNECT.
    flags = 0x02 | 0x80 | 0x40  # clean session + username + password
    payload = _mqtt_str(client_id) + _mqtt_str(username) + _mqtt_str(password)
    vh = _mqtt_str("MQTT") + bytes([4, flags]) + struct.pack(">H", _MQTT_KEEPALIVE)
    return _mqtt_packet(0x10, vh + payload)


def _mqtt_subscribe(pid: int, topics: list[str]) -> bytes:
    payload = struct.pack(">H", pid)
    for topic in topics:
        payload += _mqtt_str(topic) + bytes([1])
    return _mqtt_packet(0x82, payload)


def _mqtt_publish(topic: str, body: bytes, pid: int | None = None) -> bytes:
    qos = 1 if pid is not None else 0
    vh = _mqtt_str(topic)
    if pid is not None:
        vh += struct.pack(">H", pid)
    return _mqtt_packet(0x30 | (qos << 1), vh + body)


def _mqtt_pingreq() -> bytes:
    return b"\xc0\x00"


def _mqtt_puback(pid: int) -> bytes:
    return _mqtt_packet(0x40, struct.pack(">H", pid))


def _read_mqtt_str(buf: bytes, off: int):
    n = struct.unpack_from(">H", buf, off)[0]
    return buf[off + 2 : off + 2 + n], off + 2 + n


# --------------------------------------------------------------------------- #
# WebSocket framing
# --------------------------------------------------------------------------- #
def _ws_frame(payload: bytes, opcode: int = _OP_BINARY) -> bytes:
    hdr = bytearray([0x80 | opcode])
    n = len(payload)
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127)
        hdr += struct.pack(">Q", n)
    mask = os.urandom(4)
    hdr += mask
    return bytes(hdr) + bytes(b ^ mask[i & 3] for i, b in enumerate(payload))


async def _ws_read_message(reader: asyncio.StreamReader):
    """Return (opcode, payload) of the next complete WS message."""
    frag = b""
    frag_op = None
    while True:
        b1, b2 = await reader.readexactly(2)
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", await reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", await reader.readexactly(8))[0]
        mask = await reader.readexactly(4) if masked else None
        data = await reader.readexactly(length) if length else b""
        if mask:
            data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
        if opcode == 0x0:  # continuation
            frag += data
            if fin:
                return frag_op, frag
        elif opcode in (0x1, 0x2):
            if fin:
                return opcode, data
            frag_op, frag = opcode, data
        else:  # control frame
            return opcode, data


# --------------------------------------------------------------------------- #
# Bridge
# --------------------------------------------------------------------------- #
class TerncyMqttBridge:
    """MQTT-over-WSS side channel to a Terncy hub."""

    def __init__(
        self,
        host: str,
        port: int,
        hub_id: str,
        username: str,
        password: str,
        client_id: str,
        logger,
        on_report: Callable[[str, str, int], None],
    ):
        self.host = host
        self.port = port
        self.hub_id = hub_id  # box-1c-82-59-90-1f-23
        self.username = username
        self.password = password
        self.client_id = client_id
        self.logger = logger
        self._on_report = on_report

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._rbuf = b""
        self._pid = 0
        self._pending: dict[str, asyncio.Future] = {}

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        self._stopped = False
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._stopped = True
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    async def _run(self) -> None:
        delay = RECONNECT_MIN
        while not self._stopped:
            try:
                await self._connect()
                delay = RECONNECT_MIN
                self.logger.info("[mqtt] side channel connected to %s", self.hub_id)
                await self._read_loop()
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001
                if not self._stopped:
                    self.logger.debug("[mqtt] side channel error: %r", err)
            finally:
                self._reader = self._writer = None
                self._rbuf = b""
            if self._stopped:
                break
            self.logger.info("[mqtt] reconnecting in %.0fs", delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX)

    # -- connection --------------------------------------------------------- #
    async def _connect(self) -> None:
        # Do NOT use ssl.create_default_context() here: it calls
        # load_default_certs()/set_default_verify_paths(), which do blocking
        # disk I/O and get flagged by HA's event-loop blocking-call detector.
        # The hub presents a self-signed certificate and we do not verify it,
        # so a bare client context is both sufficient and non-blocking.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=ctx, server_hostname=self.host
        )
        self._reader, self._writer = reader, writer

        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            "GET /ws/mqtt HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Protocol: mqtt, mqttv3.1, mqttv3.11\r\n"
            "\r\n"
        ) % (self.host, key)
        writer.write(request.encode())
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        if b" 101" not in head.split(b"\r\n", 1)[0]:
            raise OSError(f"ws handshake failed: {head[:120]!r}")

        client_id = "%s%s" % (self.client_id, os.urandom(3).hex())
        await self._send(_mqtt_connect(client_id, self.username, self.password))
        ptype, _flags, body = await self._next_mqtt()
        if ptype != 2 or not body or body[0] != 0:
            raise OSError(f"mqtt CONNACK failed: type={ptype} body={body!r}")

        await self._subscribe([f"message/{self.username}", f"event/{self.hub_id}"])

    async def _subscribe(self, topics: list[str]) -> None:
        self._pid = (self._pid + 1) & 0xFFFF or 1
        await self._send(_mqtt_subscribe(self._pid, topics))
        ptype, _flags, _body = await self._next_mqtt()
        if ptype != 9:
            raise OSError(f"mqtt SUBACK expected, got type={ptype}")

    # -- io ----------------------------------------------------------------- #
    async def _send(self, data: bytes, opcode: int = _OP_BINARY) -> None:
        if self._writer is None:
            raise OSError("mqtt side channel is not connected")
        self._writer.write(_ws_frame(data, opcode))
        await self._writer.drain()

    async def _next_mqtt(self):
        """Return the next non-keepalive MQTT (type, flags, body)."""
        while True:
            while True:
                parsed = _mqtt_parse(self._rbuf)
                if parsed is None:
                    break
                ptype, flags, body, consumed = parsed
                self._rbuf = self._rbuf[consumed:]
                if ptype == 12:  # PINGREQ
                    await self._send(_mqtt_packet(0xD0, b""))
                elif ptype == 13:  # PINGRESP
                    continue
                else:
                    return ptype, flags, body
            opcode, payload = await _ws_read_message(self._reader)
            if opcode == _OP_PING:
                await self._send(payload, _OP_PONG)
            elif opcode == _OP_CLOSE:
                raise OSError("ws closed by peer")
            elif opcode == _OP_BINARY:
                self._rbuf += payload

    async def _read_loop(self) -> None:
        # MQTT keepalive is about *outbound* traffic: a broker drops a client it
        # has not heard from within 1.5 * keepalive (90s for our 60s keepalive).
        # The hub pushes presence reports every few seconds, so pinging only when
        # the *inbound* stream goes idle (the previous behaviour) meant we never
        # sent a PINGREQ and the hub tore the channel down every ~90s.  Ping on a
        # wall-clock schedule instead, independent of what we receive.
        keepalive = asyncio.ensure_future(self._keepalive_loop())
        try:
            while True:
                ptype, flags, body = await self._next_mqtt()
                if ptype == 3:  # PUBLISH
                    await self._handle_publish(flags, body)
        finally:
            keepalive.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await keepalive

    async def _keepalive_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(_MQTT_PING_INTERVAL)
                await self._send(_mqtt_pingreq())
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            # a failed ping means the socket is gone; close it so the read loop
            # fails fast and the reconnect logic kicks in
            if self._writer is not None:
                with contextlib.suppress(Exception):
                    self._writer.close()

    async def _handle_publish(self, flags: int, body: bytes) -> None:
        qos = (flags >> 1) & 0x03
        topic, off = _read_mqtt_str(body, 0)
        if qos > 0:
            pid = struct.unpack_from(">H", body, off)[0]
            off += 2
            await self._send(_mqtt_puback(pid))
        payload = body[off:]
        topic = topic.decode("utf-8", "replace")
        if topic == f"message/{self.username}":
            self._handle_response(payload)
        elif topic.startswith("event/"):
            self._handle_event(payload)

    def _handle_response(self, payload: bytes) -> None:
        """Resolve a pending write future.

        The future carries the hub result: ``0`` on success (``#64`` present),
        otherwise the ``ErrorResponse.#1`` error code (e.g. ``41``
        ``EC_DEVICE_STATUS_ALREADY_SET``), or ``-1`` if neither is present.
        """
        req_id = None
        ok = False
        code = None
        for field, wire, value in _pb_fields(payload):
            if field == 2 and wire == 2:
                req_id = value.decode("latin1")
            elif field == 64:
                ok = True
            elif field == 10 and wire == 2:
                for f2, w2, v2 in _pb_fields(value):
                    if f2 == 1 and w2 == 0:
                        code = v2
        if req_id and (future := self._pending.pop(req_id, None)):
            if not future.done():
                future.set_result(0 if ok else (code if code is not None else -1))

    def _handle_event(self, payload: bytes) -> None:
        """Decode `{#1 evt, #2 src, #3 ts, #8 {#1 entity, #2 attr{...}}}`."""
        try:
            for field, wire, value in _pb_fields(payload):
                if field != 8 or wire != 2:
                    continue
                eid = None
                attrid = uval = sval = None
                for f2, w2, v2 in _pb_fields(value):
                    if f2 == 1 and w2 == 2:
                        eid = v2.decode("latin1")
                    elif f2 == 2 and w2 == 2:
                        for f3, w3, v3 in _pb_fields(v2):
                            if f3 == 1 and w3 == 0:
                                attrid = v3
                            elif f3 == 2 and w3 == 0:
                                uval = v3
                            elif f3 == 5 and w3 == 0:
                                sval = v3
                name = MQTT_READABLE_ATTRS.get(attrid)
                if name is None or eid is None:
                    continue
                raw = sval if sval is not None else uval
                if raw is None:
                    continue
                self._dispatch(eid, name, _to_signed(raw))
        except Exception:  # noqa: BLE001
            self.logger.debug("[mqtt] failed to decode event", exc_info=True)

    def _dispatch(self, eid: str, name: str, value: int) -> None:
        try:
            self._on_report(eid, name, value)
        except Exception:  # noqa: BLE001
            self.logger.exception("[mqtt] report callback failed")

    # -- writes ------------------------------------------------------------- #
    async def write_attribute(self, eid: str, attrid: int, value: int) -> bool:
        """Send a WriteAttributeRequest; return True when the hub ACKs (#64)."""
        if self._writer is None:
            self.logger.warning("[mqtt] can't write %s attr %d: not connected", eid, attrid)
            return False
        req_id = _new_uuid()
        inner = (
            _pb_ld(1, eid.encode())
            + _pb_vi(2, attrid)
            + _pb_vi(3, value)
            + _pb_vi(5, 0)
            + _pb_vi(9, 0)
        )
        message = (
            _pb_ld(1, req_id.encode())
            + _pb_ld(3, self.username.encode())
            + _pb_ld(63, inner)
        )
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[req_id] = future
        self._pid = (self._pid + 1) & 0xFFFF or 1
        try:
            await self._send(_mqtt_publish(f"message/{self.hub_id}", message, self._pid))
            code = await asyncio.wait_for(future, _MQTT_WRITE_TIMEOUT)
            if code == 0:
                return True
            self.logger.warning(
                "[mqtt] write to %s attr %d rejected (error code %s)", eid, attrid, code
            )
            return False
        except asyncio.TimeoutError:
            self.logger.warning(
                "[mqtt] write %s attr %d timed out (no response)", eid, attrid
            )
            return False
        finally:
            self._pending.pop(req_id, None)
