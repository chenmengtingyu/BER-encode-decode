class ASN1Encoder:
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL_TYPE = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30

    @staticmethod
    def encode_integer(value):
        buf = bytearray()
        if -128 <= value <= 127:
            buf.append(ASN1Encoder.INTEGER)
            buf.append(1)
            buf.append(value & 0xff)
        elif -32768 <= value <= 32767:
            buf.append(ASN1Encoder.INTEGER)
            buf.append(2)
            buf.extend([(value >> 8) & 0xff, value & 0xff])
        else:
            buf.append(ASN1Encoder.INTEGER)
            buf.append(4)
            buf.extend([(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff])
        return buf
    # encode_integer方法编码一个整数值。
    # 创建一个空的字节数组buf。
    # 根据整数的大小选择不同的编码长度：
    # -128到127之间的整数编码为1字节。
    # -32768到32767之间的整数编码为2字节。
    # 其他范围的整数编码为4字节。
    # 将类型和长度字节追加到buf中，然后追加整数值的字节表示。
    # 返回编码后的字节数组buf。

    @staticmethod
    def encode_octet_string(value):
        buf = bytearray()
        buf.append(ASN1Encoder.OCTET_STRING)
        buf.append(len(value))
        buf.extend(value.encode())
        return buf
    # encode_octet_string方法编码一个八位字节字符串。
    # 创建一个空的字节数组buf。
    # 追加八位字节字符串类型和长度字节。
    # 将字符串的字节表示追加到buf中。
    # 返回编码后的字节数组buf。

    @staticmethod
    def encode_null():
        return bytearray([ASN1Encoder.NULL_TYPE, 0])
    # encode_null方法编码一个NULL类型。
    # NULL类型总是编码为类型字节和长度字节（长度为0）。
    # 返回编码后的字节数组。    

    @staticmethod
    def encode_object_identifier(oid):
        buf = bytearray([ASN1Encoder.OBJECT_IDENTIFIER])
        encoded_oid = bytearray()
        encoded_oid.append(oid[0] * 40 + oid[1])
        for subid in oid[2:]:
            if subid < 128:
                encoded_oid.append(subid)
            else:
                stack = []
                stack.append(subid & 0x7f)
                subid >>= 7
                while subid > 0:
                    stack.append(0x80 | (subid & 0x7f))
                    subid >>= 7
                while stack:
                    encoded_oid.append(stack.pop())
        buf.append(len(encoded_oid))
        buf.extend(encoded_oid)
        return buf
    # encode_object_identifier方法编码一个对象标识符（OID）。
    # 创建一个包含对象标识符类型字节的字节数组buf。
    # 将OID的前两个值编码为一个字节并追加到encoded_oid数组中。
    # 逐个处理OID的其余部分，如果子标识符小于128，直接追加；否则使用基数128编码。
    # 追加编码后的OID长度字节和内容到buf中。
    # 返回编码后的字节数组buf。

    @staticmethod
    def encode_sequence(elements):
        buf = bytearray([ASN1Encoder.SEQUENCE])
        length = sum(len(element) for element in elements)
        
        if length <= 127:
            buf.append(length)
        else:
            length_bytes = bytearray()
            while length > 0:
                length_bytes.insert(0, length & 0xff)
                length >>= 8
            buf.append(0x80 | len(length_bytes))
            buf.extend(length_bytes)
        
        for element in elements:
            buf.extend(element)
        return buf
    # encode_sequence方法编码一个ASN.1序列。
    # 创建一个包含序列类型字节的字节数组buf。
    # 计算序列中所有元素的总长度。
    # 根据总长度选择不同的长度编码方式：
    # 小于等于127时，直接追加长度字节。
    # 大于127时，使用长形式编码，追加长度的字节表示。
    # 将序列中的每个元素追加到buf中。
    # 返回编码后的字节数组buf。

class SNMP:
    @staticmethod
    def encode_snmp(version, community, oid, oidlen, type, value):
        encoded_version = ASN1Encoder.encode_integer(version)
        encoded_community = ASN1Encoder.encode_octet_string(community)
        encoded_oid = ASN1Encoder.encode_object_identifier(oid)
        if type == ASN1Encoder.INTEGER:
            encoded_value = ASN1Encoder.encode_integer(value)
        elif type == ASN1Encoder.OCTET_STRING:
            encoded_value = ASN1Encoder.encode_octet_string(value)
        elif type == ASN1Encoder.NULL_TYPE:
            encoded_value = ASN1Encoder.encode_null()
        else:
            raise ValueError("Unsupported type")
        sequence = ASN1Encoder.encode_sequence([encoded_version, encoded_community, encoded_oid, encoded_value])
        return sequence
    # encode_snmp方法编码一个SNMP消息。
    # 调用ASN1Encoder的编码方法分别编码版本、community、OID和值。
    # 根据值的类型选择不同的编码方法。
    # 将编码后的各个部分组合成一个ASN.1序列并返回。

def encode_snmp_message(version, community, oid, value):
    oid = list(map(int, oid.split('.')))
    oidlen = len(oid)
    snmp = SNMP.encode_snmp(version, community, oid, oidlen, ASN1Encoder.OCTET_STRING, value)
    s = snmp.hex().replace(" "," ")
    encoded_snmp = ""
    for i in range(0, len(s), 16):
        line = s[i:i+16]
        encoded_snmp += " ".join(line[j:j+2] for j in range(0, len(line), 2)) + "\n"
    return encoded_snmp
    # encode_snmp_message函数将OID字符串转换为整数列表。
    # 调用SNMP.encode_snmp方法编码SNMP消息。
    # 将编码结果转换为十六进制字符串，并每16个字符分行。
    # 返回格式化后的十六进制字符串。