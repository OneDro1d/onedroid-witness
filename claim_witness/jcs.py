"""RFC 8785 (JCS) canonical JSON, restricted to integers (BD9): no floats anywhere in a signed payload, so the number
serialisation of RFC 8785 §3.2.2.3 reduces to plain decimal integers within the I-JSON range."""
import json

MAX_INT = 2 ** 53 - 1


class CanonicalError(ValueError):
    pass


def _str(s):
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalError("string is not valid Unicode (lone surrogate)") from None
    # json.dumps with ensure_ascii=False escapes exactly what ES6 JSON.stringify escapes: '"', '\\', and the controls
    # below 0x20 (\b \t \n \f \r short forms, the rest as lowercase \u00xx)
    return json.dumps(s, ensure_ascii=False)


def _ser(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if not -MAX_INT <= v <= MAX_INT:
            raise CanonicalError("integer outside the I-JSON range")
        out.append(str(int(v)))
    elif isinstance(v, float):
        raise CanonicalError("floats are not allowed in signed payloads (BD9: integers only)")
    elif isinstance(v, str):
        out.append(_str(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _ser(x, out)
        out.append("]")
    elif isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonicalError("object keys must be strings")
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))):
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _ser(v[k], out)
        out.append("}")
    else:
        raise CanonicalError(f"type {type(v).__name__} is not JSON")


def canonical(obj):
    """The RFC 8785 bytes of obj (UTF-8)."""
    out = []
    _ser(obj, out)
    return "".join(out).encode("utf-8")


def _no_float(s):
    raise CanonicalError("floats are not allowed (BD9)")


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise CanonicalError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_const(s):
    raise CanonicalError(f"{s} is not JSON")


def loads_strict(data):
    """Parse JSON bytes, refusing floats, NaN/Infinity, duplicate keys and invalid UTF-8."""
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise CanonicalError("not UTF-8") from None
    try:
        return json.loads(data, parse_float=_no_float, parse_constant=_no_const, object_pairs_hook=_pairs)
    except CanonicalError:
        raise
    except ValueError as e:
        raise CanonicalError(f"not JSON: {e}") from None


def is_canonical(data):
    try:
        return canonical(loads_strict(data)) == bytes(data)
    except CanonicalError:
        return False
