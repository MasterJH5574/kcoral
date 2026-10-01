"""Strict multipart/form-data parsing and encoding for protocol payloads."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from email.parser import BytesHeaderParser
from email.policy import default

from .errors import ValidationError


@dataclass(frozen=True)
class MultipartPart:
    name: str
    content_type: str
    data: bytes


def parse_multipart(content_type: str | None, body: bytes) -> list[MultipartPart]:
    if not content_type or not content_type.lower().startswith("multipart/form-data"):
        raise ValidationError("expected a multipart/form-data request")
    try:
        header = BytesHeaderParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\n\r\n".encode("ascii")
        )
        boundary = header.get_boundary()
        if header.get_content_type() != "multipart/form-data" or not boundary:
            raise ValidationError("malformed multipart/form-data boundary")
        marker = b"--" + boundary.encode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ValidationError("malformed multipart/form-data boundary") from exc
    if b"\r" in marker or b"\n" in marker or header["content-type"].defects:
        raise ValidationError("malformed multipart/form-data boundary")

    # Scan framing as bytes. The email parser is used only for small MIME
    # headers, never to decode/copy a potentially gigabyte-sized binary body.
    def next_boundary(start: int) -> tuple[int, int, bool]:
        candidate = 0 if start == 0 and body.startswith(marker) else -1
        while True:
            if candidate < 0:
                found = body.find(b"\n" + marker, start)
                if found < 0:
                    raise ValidationError("malformed multipart/form-data body")
                candidate = found + 1
            tail = candidate + len(marker)
            closing = body[tail : tail + 2] == b"--"
            if closing:
                tail += 2
            while tail < len(body) and body[tail] in (32, 9):
                tail += 1
            if body[tail : tail + 2] == b"\r\n":
                return candidate, tail + 2, closing
            if body[tail : tail + 1] == b"\n":
                return candidate, tail + 1, closing
            if closing and tail == len(body):
                return candidate, tail, closing
            # A boundary prefix inside binary data is not a delimiter.
            start = candidate + len(marker)
            candidate = -1

    _, part_start, closing = next_boundary(0)
    parts: list[MultipartPart] = []
    while not closing:
        boundary_start, next_start, closing = next_boundary(part_start)
        part_end = boundary_start - 1  # boundary's preceding LF
        if part_end > part_start and body[part_end - 1 : part_end] == b"\r":
            part_end -= 1
        # Only scan the current part's header lines; payload bytes stay opaque.
        cursor = part_start
        while True:
            end = body.find(b"\n", cursor, part_end)
            if end < 0:
                raise ValidationError("malformed multipart part headers")
            if body[cursor:end] in (b"", b"\r"):
                payload_start = end + 1
                break
            cursor = end + 1
        item = BytesHeaderParser(policy=default).parsebytes(body[part_start:payload_start])
        if item.defects:
            raise ValidationError("malformed multipart part headers")
        part_start = next_start
        if len(item.get_all("content-disposition", [])) != 1:
            raise ValidationError("each multipart part must have one Content-Disposition")
        if len(item.get_all("content-type", [])) != 1:
            raise ValidationError("each multipart part must have one Content-Type")
        if item["content-disposition"].defects:
            raise ValidationError("multipart part has a malformed Content-Disposition")
        if item["content-type"].defects:
            raise ValidationError("multipart part has a malformed Content-Type")
        if item.get_content_maintype() == "multipart":
            raise ValidationError("nested multipart parts are not supported")
        if item.get_content_disposition() != "form-data":
            raise ValidationError("multipart parts must use form-data disposition")
        names = [
            value
            for key, value in item.get_params(header="content-disposition", unquote=True)[1:]
            if key.lower() == "name"
        ]
        if len(names) != 1 or not isinstance(names[0], str) or not names[0]:
            raise ValidationError("multipart part is missing its name")
        name = names[0]
        transfer_encoding = item.get("content-transfer-encoding")
        if transfer_encoding and transfer_encoding.lower() not in ("binary", "8bit"):
            raise ValidationError("encoded multipart parts are not supported")
        payload = body[payload_start:part_end]
        parts.append(MultipartPart(name=name, content_type=item.get_content_type(), data=payload))
    if not parts:
        raise ValidationError("multipart body has no parts")
    return parts


def encode_multipart(parts: list[MultipartPart]) -> tuple[bytes, str]:
    if not parts:
        raise ValueError("at least one multipart part is required")
    while True:
        boundary = f"kcoral-{secrets.token_hex(16)}"
        delimiter = f"\r\n--{boundary}".encode("ascii")
        if all(delimiter not in part.data for part in parts):
            break

    chunks: list[bytes] = []
    for part in parts:
        if not part.name or any(character in part.name for character in '"\r\n'):
            raise ValueError(f"invalid multipart part name: {part.name!r}")
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("ascii"),
                f'Content-Disposition: form-data; name="{part.name}"\r\n'.encode("ascii"),
                f"Content-Type: {part.content_type}\r\n\r\n".encode("ascii"),
                part.data,
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
