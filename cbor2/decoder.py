import re
import struct
from datetime import datetime, timedelta
from io import BytesIO

from cbor2.compat import timezone, xrange, byte_as_integer
from cbor2.types import CBORTag, undefined, break_marker, CBORSimpleValue

timestamp_re = re.compile(r'^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)'
                          r'(?:\.(\d+))?(?:Z|([+-]\d\d):(\d\d))$')


class CBORDecodeError(Exception):
    """Raised when an error occurs deserializing a CBOR datastream."""

fmt_by_subtype = {
    24: '>B', 25: '>H', 26: '>L', 27: '>Q'
}

size_by_subtype = (
    0, 0, 0, 0,   0, 0, 0, 0,
    0, 0, 0, 0,   0, 0, 0, 0,
    0, 0, 0, 0,   0, 0, 0, 0,
    1, 2, 4, 8,   0, 0, 0, 0,
)

class CBORDecoder(object):

    def decode_uint(decoder, initial_byte, tokendata):
        # Major tag 0
        subtype = initial_byte & 31
        if subtype < 24:
            return subtype
        elif subtype in fmt_by_subtype:
            return struct.unpack(fmt_by_subtype[subtype], tokendata)[0]
        else:
            raise CBORDecodeError('unknown unsigned integer subtype 0x%x' % subtype)


    def decode_negint(decoder, initial_byte, tokendata):
        # Major tag 1
        uint = decoder.decode_uint(initial_byte, tokendata)
        return -uint - 1


    def decode_bytestring(decoder, initial_byte, tokendata):
        # Major tag 2
        subtype = initial_byte & 31
        if subtype == 31:
            # Indefinite length
            buf = bytearray()
            while True:
                initial_byte, tokendata = decoder.read_token()
                if initial_byte == 255:
                    return buf
                else:
                    buf.extend(tokendata)
        else:
            return tokendata


    def decode_string(decoder, initial_byte, tokendata):
        # Major tag 3
        return decoder.decode_bytestring(initial_byte, tokendata).decode('utf-8')


    def decode_array(decoder, initial_byte, tokendata):
        # Major tag 4
        subtype = initial_byte & 31
        items = []
        decoder.set_shareable(None, items)
        if subtype == 31:
            # Indefinite length
            while True:
                value = decoder.decode()
                if value is break_marker:
                    break
                else:
                    items.append(value)
        else:
            length = decoder.decode_uint(initial_byte, tokendata)
            for _ in xrange(length):
                item = decoder.decode()
                items.append(item)

        return items


    def decode_map(decoder, initial_byte, tokendata):
        # Major tag 5
        subtype = initial_byte & 31
        dictionary = {}
        decoder.set_shareable(None, dictionary)
        if subtype == 31:
            # Indefinite length
            while True:
                key = decoder.decode()
                if key is break_marker:
                    break
                else:
                    value = decoder.decode()
                    dictionary[key] = value
        else:
            length = decoder.decode_uint(initial_byte, tokendata)
            for _ in xrange(length):
                key = decoder.decode()
                value = decoder.decode()
                dictionary[key] = value

        if decoder.object_hook:
            return decoder.object_hook(decoder, dictionary)
        else:
            return dictionary


    def decode_semantic(decoder, initial_byte, tokendata):
        # Major tag 6
        tagnum = decoder.decode_uint(initial_byte & 31, tokendata)

        # Special handling for the "shareable" tag
        if tagnum == 28:
            decoder._allocate_shareable()
            ret = decoder.decode()
            decoder._pop_shareable()
            return ret

        value = decoder.decode()
        semantic_decoder = decoder.semantic_decoders.get(tagnum)
        if semantic_decoder:
            return semantic_decoder(decoder, value)

        tag = CBORTag(tagnum, value)
        if decoder.tag_hook:
            return decoder.tag_hook(decoder, tag, None)
        else:
            return tag


    def decode_special(decoder, initial_byte, tokendata):
        # Simple value
        subtype = initial_byte & 31
        if subtype < 20:
            return CBORSimpleValue(subtype)

        # Major tag 7
        return decoder.special_decoders[subtype](decoder, tokendata)


    #
    # Semantic decoders (major tag 6)
    #

    def decode_datetime_string(decoder, value):
        # Semantic tag 0
        match = timestamp_re.match(value)
        if match:
            year, month, day, hour, minute, second, micro, offset_h, offset_m = match.groups()
            if offset_h:
                tz = timezone(timedelta(hours=int(offset_h), minutes=int(offset_m)))
            else:
                tz = timezone.utc

            return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                            int(micro or 0), tz)
        else:
            raise CBORDecodeError('invalid datetime string: {}'.format(value))


    def decode_epoch_datetime(decoder, value):
        # Semantic tag 1
        return datetime.fromtimestamp(value, timezone.utc)


    def decode_positive_bignum(decoder, value):
        # Semantic tag 2
        from binascii import hexlify
        return int(hexlify(value), 16)


    def decode_negative_bignum(decoder, value):
        # Semantic tag 3
        return -decoder.decode_positive_bignum(value) - 1


    def decode_fraction(decoder, value):
        # Semantic tag 4
        from decimal import Decimal
        exp = Decimal(value[0])
        mantissa = Decimal(value[1])
        return mantissa * (10 ** exp)


    def decode_bigfloat(decoder, value):
        # Semantic tag 5
        from decimal import Decimal
        exp = Decimal(value[0])
        mantissa = Decimal(value[1])
        return mantissa * (2 ** exp)


    def decode_shareable(decoder, value):
        # Semantic tag 28
        decoder.set_shareable(None, value)
        return value

    def decode_sharedref(decoder, value):
        # Semantic tag 29
        try:
            shared = decoder._shareables[value]
        except IndexError:
            raise CBORDecodeError('shared reference %d not found' % value)

        if shared is None:
            raise CBORDecodeError('shared value %d has not been initialized' % value)
        else:
            return shared


    def decode_rational(decoder, value):
        # Semantic tag 30
        from fractions import Fraction
        return Fraction(*value)


    def decode_regexp(decoder, value):
        # Semantic tag 35
        return re.compile(value)


    def decode_mime(decoder, value):
        # Semantic tag 36
        from email.parser import Parser
        return Parser().parsestr(value)


    def decode_uuid(decoder, value):
        # Semantic tag 37
        from uuid import UUID
        return UUID(bytes=value)


    #
    # Special decoders (major tag 7)
    #

    def decode_simple_value(decoder, tokendata):
        return CBORSimpleValue(struct.unpack('>B', tokendata)[0])


    def decode_float16(decoder, tokendata):
        # Code adapted from RFC 7049, appendix D
        from math import ldexp

        def decode_single(single):
            return struct.unpack("!f", struct.pack("!I", single))[0]

        payload = struct.unpack('>H', tokendata)[0]
        value = (payload & 0x7fff) << 13 | (payload & 0x8000) << 16
        if payload & 0x7c00 != 0x7c00:
            return ldexp(decode_single(value), 112)

        return decode_single(value | 0x7f800000)


    def decode_float32(decoder, tokendata):
        return struct.unpack('>f', tokendata)[0]


    def decode_float64(decoder, tokendata):
        return struct.unpack('>d', tokendata)[0]


    major_decoders = {
        0: decode_uint,
        1: decode_negint,
        2: decode_bytestring,
        3: decode_string,
        4: decode_array,
        5: decode_map,
        6: decode_semantic,
        7: decode_special
    }

    special_decoders = {
        20: lambda self, tokendata: False,
        21: lambda self, tokendata: True,
        22: lambda self, tokendata: None,
        23: lambda self, tokendata: undefined,
        24: decode_simple_value,
        25: decode_float16,
        26: decode_float32,
        27: decode_float64,
        31: lambda self, tokendata: break_marker
    }

    semantic_decoders = {
        0: decode_datetime_string,
        1: decode_epoch_datetime,
        2: decode_positive_bignum,
        3: decode_negative_bignum,
        4: decode_fraction,
        5: decode_bigfloat,
        28: decode_shareable,
        29: decode_sharedref,
        30: decode_rational,
        35: decode_regexp,
        36: decode_mime,
        37: decode_uuid
    }


    """
    Deserializes a CBOR encoded byte stream.

    :param tag_hook: Callable that takes 3 arguments: the decoder instance, the
        :class:`~cbor2.types.CBORTag` and the shareable index for the resulting object, if any.
        This callback is called for any tags for which there is no built-in decoder.
        The return value is substituted for the CBORTag object in the deserialized output.
    :param object_hook: Callable that takes 2 arguments: the decoder instance and the dictionary.
        This callback is called for each deserialized :class:`dict` object.
        The return value is substituted for the dict in the deserialized output.
    """

    __slots__ = ('fp', 'tag_hook', 'object_hook', '_shareables', '_shareables_stack')

    def __init__(self, fp, tag_hook=None, object_hook=None):
        self.fp = fp
        self.tag_hook = tag_hook
        self.object_hook = object_hook
        self._shareables = []
        self._shareables_stack = []

    def _allocate_shareable(self):
        index = len(self._shareables)
        self._shareables.append(None)
        self._shareables_stack.append(index)
        return index

    def _pop_shareable(self):
        self._shareables_stack.pop()

    def set_shareable(self, _, value):
        """
        Set the shareable value for the last encountered shared value marker, if any.

        If the given index is ``None``, the index is chosen automatically or ignored
        if irrelevant in current context.

        :param index: the value of the ``shared_index`` argument to the decoder
        :param value: the shared value

        """
        if self._shareables_stack:
            index = self._shareables_stack[-1]
            if self._shareables[index] is None:
                self._shareables[index] = value
            else:
                assert self._shareables[index] is value

    def read_token(self):
        """
        Read initial byte and any immediately following data that is
        not an independent item.
        """
        initial_byte = byte_as_integer(self.fp.read(1))

        subtype = initial_byte & 31
        datasize = size_by_subtype[subtype]
        tokendata = self.fp.read(datasize)

        if 0x60 <= initial_byte | 0x20 <= 0x7b:
            datasize = self.decode_uint(subtype, tokendata)
            tokendata = self.fp.read(datasize)

        return initial_byte, tokendata

    _cache = {}
    def add_cache(self, token, value):
        cache = self._cache
        if token in cache:
            assert value == cache[token]
        cache[token] = value
        if len(cache) > 400:
            cache.clear()

    def decode(self):
        """
        Decode the next value from the stream.

        :raises CBORDecodeError: if there is any problem decoding the stream

        """
        try:
            token = self.read_token()
            if token in self._cache:
                return self._cache[token]
            initial_byte, tokendata = token
            major_type = initial_byte >> 5
            subtype = initial_byte & 31
        except Exception as e:
            raise CBORDecodeError('error reading major type at index {}: {}'
                                  .format(self.fp.tell(), e))

        decoder = self.major_decoders[major_type]
        try:
            result = decoder(self, subtype, tokendata)
            if major_type not in (4, 5, 6) and len(tokendata) < 200:
                self.add_cache(token, result)
            return result
        except CBORDecodeError:
            raise
        except Exception as e:
            raise CBORDecodeError('error decoding value at index {}: {}'.format(self.fp.tell(), e))

    def decode_from_bytes(self, buf):
        """
        Wrap the given bytestring as a file and call :meth:`decode` with it as the argument.

        This method was intended to be used from the ``tag_hook`` hook when an object needs to be
        decoded separately from the rest but while still taking advantage of the shared value
        registry.

        """
        old_fp = self.fp
        self.fp = BytesIO(buf)
        retval = self.decode()
        self.fp = old_fp
        return retval


def loads(payload, **kwargs):
    """
    Deserialize an object from a bytestring.

    :param bytes payload: the bytestring to serialize
    :param kwargs: keyword arguments passed to :class:`~.CBORDecoder`
    :return: the deserialized object

    """
    fp = BytesIO(payload)
    return CBORDecoder(fp, **kwargs).decode()


def load(fp, **kwargs):
    """
    Deserialize an object from an open file.

    :param fp: the input file (any file-like object)
    :param kwargs: keyword arguments passed to :class:`~.CBORDecoder`
    :return: the deserialized object

    """
    return CBORDecoder(fp, **kwargs).decode()
