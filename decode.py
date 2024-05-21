class ASN1Encoder:
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL_TYPE = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30

class ASN1Decoder:

    @staticmethod
    def decode_integer(buf, pos):
        length = buf[pos + 1]
        value = int.from_bytes(buf[pos + 2:pos + 2 + length], byteorder='big', signed=True)
        return value, pos + 2 + length
    # decode_integer方法解码一个整数。
    # 从buf的pos + 1位置获取长度字节。
    # 使用int.from_bytes方法从buf[pos + 2]开始读取length字节，并将其转换为整数。
    # 返回解码后的整数值和新的位置。

    @staticmethod
    def decode_octet_string(buf, pos):
        length = buf[pos + 1]
        value = buf[pos + 2:pos + 2 + length].decode()
        return value, pos + 2 + length
    # decode_octet_string方法解码一个八位字节字符串。
    # 从buf的pos + 1位置获取长度字节。
    # 从buf[pos + 2]开始读取length字节，并将其解码为字符串。
    # 返回解码后的字符串值和新的位置。

    @staticmethod
    def decode_null(buf, pos):
        return None, pos + 2
    # decode_null方法处理NULL类型。
    # NULL类型的长度总是2字节（类型和长度字节），直接返回None和新的位置。

    @staticmethod
    def decode_object_identifier(buf, pos):
        length = buf[pos + 1]
        value = []
        oid = buf[pos + 2:pos + 2 + length]
        value.append(oid[0] // 40)
        value.append(oid[0] % 40)
        i = 1
        while i < len(oid):
            subid = 0
            while i < len(oid) and oid[i] & 0x80:
                subid = (subid << 7) | (oid[i] & 0x7f)
                i += 1
            if i < len(oid):
                subid = (subid << 7) | (oid[i] & 0x7f)
                i += 1
            value.append(subid)
        return value, pos + 2 + length
    # decode_object_identifier方法解码一个对象标识符（OID）。
    # 从buf的pos + 1位置获取长度字节。
    # 从buf[pos + 2]开始读取length字节，并进行解码。
    # OID的第一个字节特殊处理，前两个值由第一个字节决定。
    # 之后的字节通过循环处理，每7位一组。
    # 返回解码后的OID值列表和新的位置。

    @staticmethod
    def decode_sequence(buf, pos):
        length = buf[pos + 1]
        return buf[pos + 2:pos + 2 + length], pos + 2 + length   
    # decode_sequence方法解码一个序列。
    # 从buf的pos + 1位置获取长度字节。
    # 返回序列的字节数组和新的位置。

class SNMP:
    @staticmethod
    def decode_snmp(buf):
        pos = 0
        if buf[pos] != ASN1Encoder.SEQUENCE:
            raise ValueError("Invalid SNMP message")
        pos += 1
        length = buf[pos]
        pos += 1
        end_pos = pos + length
        version, pos = ASN1Decoder.decode_integer(buf, pos)
        community, pos = ASN1Decoder.decode_octet_string(buf, pos)
        oid, pos = ASN1Decoder.decode_object_identifier(buf, pos)
        if pos >= len(buf):
            raise ValueError("Invalid SNMP message: unexpected end of buffer")
        if buf[pos] == ASN1Encoder.INTEGER:
            type = ASN1Encoder.INTEGER
            value, pos = ASN1Decoder.decode_integer(buf, pos)
        elif buf[pos] == ASN1Encoder.OCTET_STRING:
            type = ASN1Encoder.OCTET_STRING
            value, pos = ASN1Decoder.decode_octet_string(buf, pos)
        elif buf[pos] == ASN1Encoder.NULL_TYPE:
            type = ASN1Encoder.NULL_TYPE
            value, pos = ASN1Decoder.decode_null(buf, pos)
        else:
            raise ValueError("Unsupported type")
        return {
            "version": version,
            "community": community,
            "oid": '.'.join(map(str, oid)),
            "type": type,
            "value": value
        }
    # decode_snmp方法解码SNMP消息。
    # 检查第一个字节是否为序列类型，不是则抛出错误。
    # 获取消息长度，并计算消息结束位置。
    # 按顺序解码版本、community和OID。
    # 检查是否到达缓冲区末尾，如果是则抛出错误。
    # 根据后续字节的类型解码对应的值（整型、八位字节字符串或NULL）。
    # 返回解码后的SNMP消息字典。

def decode_snmp_message(hex_str):
    snmp_bytes = bytes.fromhex(hex_str.replace(" ", ""))
    s1 = SNMP.decode_snmp(snmp_bytes)
    decoded_snmp = "{\n"
    for key, value in s1.items():
        decoded_snmp += f"    '{key}': {repr(value)},\n"
    decoded_snmp = decoded_snmp.rstrip(",\n") + "\n}"
    return decoded_snmp
    # decode_snmp_message函数将十六进制字符串转换为字节数组。
    # 调用SNMP.decode_snmp方法解码字节数组。
    # 将解码结果格式化为字符串返回。
    