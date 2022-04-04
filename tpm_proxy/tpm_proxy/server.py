
# Echo server program
import socket
import os
import struct
from sty import fg, bg, ef, rs

from enum import Enum

from scapy.utils import PcapReader, PcapWriter
from scapy.layers.inet import Ether, IP, TCP
from scapy.compat import raw

from random import randint

socket_path = "/tmp/sniffer_socket"

class TypeShow(Enum):
    RAW = 1
    BEAUTY = 2

class packet_socket():

    def __init__(self, type_ = None, data = None):
        self.type_ = type_
        self.data = data
        self.len = None if data is None else len(data)

    def unpack(self, conn):
        data = conn.recv(3)
        if not data:
            return -1
        self.type_ = struct.unpack("<B", data[0:1])[0]
        self.len = struct.unpack("<H", data[1:3])[0]
        self.data = conn.recv(self.len)
        print(data + self.data)
        assert len(self.data) <= self.len
        if len(self.data) == self.len:
            return self.len
        return -1


def process_raw(data):
    if data.type_ == 0x1:
        type_ = "WRITE"
    else:
        type_ = "READ"

    print(f"{type_} : {' '.join(hex(x) for x in data.data)}")

TPM_1_2_COMMANDS = \
{
    0x000000F1 : "Get Ticks",
    0x1e : "TODO",
    0x99 : "TODO",
}

TPM_2_COMMANDS = \
{
  0x0000011F    : 'TPM_CC_FIRST',
  0x0000011F    : 'TPM_CC_NV_UndefineSpaceSpecial',
  0x00000120    : 'TPM_CC_EvictControl',
  0x00000121    : 'TPM_CC_HierarchyControl',
  0x00000122    : 'TPM_CC_NV_UndefineSpace',
  0x00000124    : 'TPM_CC_ChangeEPS',
  0x00000125    : 'TPM_CC_ChangePPS',
  0x00000126    : 'TPM_CC_Clear',
  0x00000127    : 'TPM_CC_ClearControl',
  0x00000128    : 'TPM_CC_ClockSet',
  0x00000129    : 'TPM_CC_HierarchyChangeAuth',
  0x0000012A    : 'TPM_CC_NV_DefineSpace',
  0x0000012B    : 'TPM_CC_PCR_Allocate',
  0x0000012C    : 'TPM_CC_PCR_SetAuthPolicy',
  0x0000012D    : 'TPM_CC_PP_Commands',
  0x0000012E    : 'TPM_CC_SetPrimaryPolicy',
  0x0000012F    : 'TPM_CC_FieldUpgradeStart',
  0x00000130    : 'TPM_CC_ClockRateAdjust',
  0x00000131    : 'TPM_CC_CreatePrimary',
  0x00000132    : 'TPM_CC_NV_GlobalWriteLock',
  0x00000133    : 'TPM_CC_GetCommandAuditDigest',
  0x00000134    : 'TPM_CC_NV_Increment',
  0x00000135    : 'TPM_CC_NV_SetBits',
  0x00000136    : 'TPM_CC_NV_Extend',
  0x00000137    : 'TPM_CC_NV_Write',
  0x00000138    : 'TPM_CC_NV_WriteLock',
  0x00000139    : 'TPM_CC_DictionaryAttackLockReset',
  0x0000013A    : 'TPM_CC_DictionaryAttackParameters',
  0x0000013B    : 'TPM_CC_NV_ChangeAuth',
  0x0000013C    : 'TPM_CC_PCR_Event',
  0x0000013D    : 'TPM_CC_PCR_Reset',
  0x0000013E    : 'TPM_CC_SequenceComplete',
  0x0000013F    : 'TPM_CC_SetAlgorithmSet',
  0x00000140    : 'TPM_CC_SetCommandCodeAuditStatus',
  0x00000141    : 'TPM_CC_FieldUpgradeData',
  0x00000142    : 'TPM_CC_IncrementalSelfTest',
  0x00000143    : 'TPM_CC_SelfTest',
  0x00000144    : 'TPM_CC_Startup',
  0x00000145    : 'TPM_CC_Shutdown',
  0x00000146    : 'TPM_CC_StirRandom',
  0x00000147    : 'TPM_CC_ActivateCredential',
  0x00000148    : 'TPM_CC_Certify',
  0x00000149    : 'TPM_CC_PolicyNV',
  0x0000014A    : 'TPM_CC_CertifyCreation',
  0x0000014B    : 'TPM_CC_Duplicate',
  0x0000014C    : 'TPM_CC_GetTime',
  0x0000014D    : 'TPM_CC_GetSessionAuditDigest',
  0x0000014E    : 'TPM_CC_NV_Read',
  0x0000014F    : 'TPM_CC_NV_ReadLock',
  0x00000150    : 'TPM_CC_ObjectChangeAuth',
  0x00000151    : 'TPM_CC_PolicySecret',
  0x00000152    : 'TPM_CC_Rewrap',
  0x00000153    : 'TPM_CC_Create',
  0x00000154    : 'TPM_CC_ECDH_ZGen',
  0x00000155    : 'TPM_CC_HMAC',
  0x00000155    : 'TPM_CC_MAC',
  0x00000156    : 'TPM_CC_Import',
  0x00000157    : 'TPM_CC_Load',
  0x00000158    : 'TPM_CC_Quote',
  0x00000159    : 'TPM_CC_RSA_Decrypt',
  0x0000015B    : 'TPM_CC_HMAC_Start',
  0x0000015B    : 'TPM_CC_MAC_Start',
  0x0000015C    : 'TPM_CC_SequenceUpdate',
  0x0000015D    : 'TPM_CC_Sign',
  0x0000015E    : 'TPM_CC_Unseal',
  0x00000160    : 'TPM_CC_PolicySigned',
  0x00000161    : 'TPM_CC_ContextLoad',
  0x00000162    : 'TPM_CC_ContextSave',
  0x00000163    : 'TPM_CC_ECDH_KeyGen',
  0x00000164    : 'TPM_CC_EncryptDecrypt',
  0x00000165    : 'TPM_CC_FlushContext',
  0x00000167    : 'TPM_CC_LoadExternal',
  0x00000168    : 'TPM_CC_MakeCredential',
  0x00000169    : 'TPM_CC_NV_ReadPublic',
  0x0000016A    : 'TPM_CC_PolicyAuthorize',
  0x0000016B    : 'TPM_CC_PolicyAuthValue',
  0x0000016C    : 'TPM_CC_PolicyCommandCode',
  0x0000016D    : 'TPM_CC_PolicyCounterTimer',
  0x0000016E    : 'TPM_CC_PolicyCpHash',
  0x0000016F    : 'TPM_CC_PolicyLocality',
  0x00000170    : 'TPM_CC_PolicyNameHash',
  0x00000171    : 'TPM_CC_PolicyOR',
  0x00000172    : 'TPM_CC_PolicyTicket',
  0x00000173    : 'TPM_CC_ReadPublic',
  0x00000174    : 'TPM_CC_RSA_Encrypt',
  0x00000176    : 'TPM_CC_StartAuthSession',
  0x00000177    : 'TPM_CC_VerifySignature',
  0x00000178    : 'TPM_CC_ECC_Parameters',
  0x00000179    : 'TPM_CC_FirmwareRead',
  0x0000017A    : 'TPM_CC_GetCapability',
  0x0000017B    : 'TPM_CC_GetRandom',
  0x0000017C    : 'TPM_CC_GetTestResult',
  0x0000017D    : 'TPM_CC_Hash',
  0x0000017E    : 'TPM_CC_PCR_Read',
  0x0000017F    : 'TPM_CC_PolicyPCR',
  0x00000180    : 'TPM_CC_PolicyRestart',
  0x00000181    : 'TPM_CC_ReadClock',
  0x00000182    : 'TPM_CC_PCR_Extend',
  0x00000183    : 'TPM_CC_PCR_SetAuthValue',
  0x00000184    : 'TPM_CC_NV_Certify',
  0x00000185    : 'TPM_CC_EventSequenceComplete',
  0x00000186    : 'TPM_CC_HashSequenceStart',
  0x00000187    : 'TPM_CC_PolicyPhysicalPresence',
  0x00000188    : 'TPM_CC_PolicyDuplicationSelect',
  0x00000189    : 'TPM_CC_PolicyGetDigest',
  0x0000018A    : 'TPM_CC_TestParms',
  0x0000018B    : 'TPM_CC_Commit',
  0x0000018C    : 'TPM_CC_PolicyPassword',
  0x0000018D    : 'TPM_CC_ZGen_2Phase',
  0x0000018E    : 'TPM_CC_EC_Ephemeral',
  0x0000018F    : 'TPM_CC_PolicyNvWritten',
  0x00000190    : 'TPM_CC_PolicyTemplate',
  0x00000191    : 'TPM_CC_CreateLoaded',
  0x00000192    : 'TPM_CC_PolicyAuthorizeNV',
  0x00000193    : 'TPM_CC_EncryptDecrypt2',
  0x00000194    : 'TPM_CC_AC_GetCapability',
  0x00000195    : 'TPM_CC_AC_Send',
  0x00000196    : 'TPM_CC_Policy_AC_SendSelect',
  0x00000197    : 'TPM_CC_CertifyX509',
  0x00000198    : 'TPM_CC_ACT_SetTimeout',
  0x00000198    : 'TPM_CC_LAST',
  0x20000000    : 'CC_VEND',
}

TPM_RH_Constans = \
{
  0x40000000 : 'TPM_RH_SRK',
  0x40000001 : 'TPM_RH_OWNER',
  0x40000002 : 'TPM_RH_REVOKE',
  0x40000003 : 'TPM_RH_TRANSPORT',
  0x40000004 : 'TPM_RH_OPERATOR',
  0x40000005 : 'TPM_RH_ADMIN',
  0x40000006 : 'TPM_RH_EK',
  0x40000007 : 'TPM_RH_NULL',
  0x40000008 : 'TPM_RH_UNASSIGNED',
  0x40000009 : 'TPM_RS_PW',
  0x4000000A : 'TPM_RH_LOCKOUT',
  0x4000000B : 'TPM_RH_ENDORSEMENT',
  0x4000000C : 'TPM_RH_PLATFORM',
  0x4000000D : 'TPM_RH_PLATFORM_NV',
  0x40000010 : 'TPM_RH_AUTH_00',
  0x4000010F : 'TPM_RH_AUTH_FF',
  0x40000110 : 'TPM_RH_ACT_0',
  0x4000011F : 'TPM_RH_ACT_F',
}

TPM_PT_PCR_Constants = \
{
  0x00000000 : 'TPM_PT_PCR_FIRST',
  0x00000000 : 'TPM_PT_PCR_SAVE',
  0x00000001 : 'TPM_PT_PCR_EXTEND_L0',
  0x00000002 : 'TPM_PT_PCR_RESET_L0',
  0x00000003 : 'TPM_PT_PCR_EXTEND_L1',
  0x00000004 : 'TPM_PT_PCR_RESET_L1',
  0x00000005 : 'TPM_PT_PCR_EXTEND_L2',
  0x00000006 : 'TPM_PT_PCR_RESET_L2',
  0x00000007 : 'TPM_PT_PCR_EXTEND_L3',
  0x00000008 : 'TPM_PT_PCR_RESET_L3',
  0x00000009 : 'TPM_PT_PCR_EXTEND_L4',
  0x0000000A : 'TPM_PT_PCR_RESET_L4',
  0x0000000B : 'reserved',
  0x0000000C : 'reserved',
  0x0000000D : 'reserved',
  0x0000000E : 'reserved',
  0x0000000F : 'reserved',
  0x00000010 : 'reserved',
  0x00000011 : 'TPM_PT_PCR_NO_INCREMENT',
  0x00000012 : 'TPM_PT_PCR_DRTM_RESET',
  0x00000013 : 'TPM_PT_PCR_POLICY',
  0x00000014 : 'TPM_PT_PCR_AUTH',
  0x00000015 : 'reserved',
  0x00000016 : 'reserved',
  0x00000017 : 'reserved',
  0x00000211 : 'reserved',
  0x00000212 : 'reserved',
  0x00000213 : 'reserved',
  0x00000014 : 'TPM_PT_PCR_LAST',
}

TPM_2_ALG_ID_Constans = \
{
  0x0000 : 'TPM_ALG_ERROR',
  0x0001 : 'TPM_ALG_RSA',
  0x0003 : 'TPM_ALG_TDES',
  0x0004 : 'TPM_ALG_SHA',
  0x0005 : 'TPM_ALG_HMAC',
  0x0006 : 'TPM_ALG_AES',
  0x000B : 'TPM_ALG_SHA256',
  0x000C : 'TPM_ALG_SHA384',
  0x000D : 'TPM_ALG_SHA512',
  0x0010 : 'TPM_ALG_NULL',
  0x0013 : 'TPM_ALG_SM4',
  0x0014 : 'TPM_ALG_RSASSA',
  0x0015 : 'TPM_ALG_RSAES',
  0x0016 : 'TPM_ALG_RSAPSS',
  0x0017 : 'TPM_ALG_OAEP',
  0x0018 : 'TPM_ALG_ECDSA',
  0x0019 : 'TPM_ALG_ECDH',
  0x001A : 'TPM_ALG_ECDAA',
  0x001B : 'TPM_ALG_SM2',
  0x001C : 'TPM_ALG_ECSCHNORR',
  0x001D : 'TPM_ALG_ECMQV',
  0x0021 : 'TPM_ALG_KDF2',
  0x0023 : 'TPM_ALG_ECC',
  0x0025 : 'TPM_ALG_SYMCIPHER',
  0x0026 : 'TPM_ALG_CAMELLIA',
  0x0027 : 'TPM_ALG_SHA3_256',
  0x0028 : 'TPM_ALG_SHA3_384',
  0x0029 : 'TPM_ALG_SHA3_512',
  0x0040 : 'TPM_ALG_CTR',
  0x0041 : 'TPM_ALG_OFB',
  0x0042 : 'TPM_ALG_CBC',
  0x0043 : 'TPM_ALG_CFB',
  0x0044 : 'TPM_ALG_ECB',
}

TPM_2_COMMANDS_RESPONSE = \
{

  0x000 : 'TPM_RC_SUCCESS',
  0x01 : 'TPM_RC_BAD_TAG',
  30: 'TODO',
  0x100 : 'RC_VER1',
  0x9a2 : 'TODO',
  0x14c : 'TODO',
  0x910 : 'TPM_RC_REFERENCE_H0',
  2306: 'TODO',
  452: 'TODO',
  479: 'TODO',
  0x99d: 'TPM error PCR have changed',
  # TODO: found error code
  0xb0143 : 'RC_Unknown',
  0x18b: 'RC_Unknown',
}

def get_Parse_Command():
    return {
      'TPM_CC_PCR_Extend' : packet_TPM2_CC_PCR_Extend,
      'TPM_CC_GetRandom'  : packet_TPM2_CC_GetRandom,
      'TPM_CC_PCR_Read'   : packet_TPM2_CC_PCR_Read,


      'TPM_RC_SUCCESS'    : packet_TPM2_RC_SUCESS,
    }

def get_Parse_Resp_Command():
    return {
      'TPM_CC_GetRandom'  : packet_TPM2_CC_GetRandomResp,
    }


class packet_TPM():
    def __init__(self, size_command = 0, tag = "\x00" * 2, command = "\x00" * 4):
        self.size_command = size_command
        self.tag = tag
        self.command = command

    @classmethod
    def parse(cls, raw_message, type_, req=None):
        tag = struct.unpack(">H", raw_message[0:2])[0]
        size_command = struct.unpack(">I", raw_message[2:6])[0]
        command = struct.unpack(">I", raw_message[6:10])[0]
        tmp = packet_TPM(size_command, tag, command)
        if tag >= 0x00c1 and tag <= 0x00c7:
            return packet_TPM1.parse(raw_message, type_, tmp)
        elif tag >= 0x8001 and tag <= 0x8002:
            return packet_TPM2.parse(raw_message, type_, tmp, req=req)
        assert False, "Unknow TAG: " + hex(tag)

    def packed(self):
        data = b''
        data += struct.pack(">H", self.tag)
        data += struct.pack(">I", self.size_command)
        data += struct.pack(">I", self.command)
        return data


    def __str__(self):
        return f"Size Command : {self.size_command}\n" \

class packet_TPM1(packet_TPM):

    def __init__(self, type_, payload = None, parent = None):
        if parent:
            self.__dict__.update(parent.__dict__)
        self.version = "1.2"
        self.type_ = type_
        self.payload = payload

    @classmethod
    def parse(cls, raw_message, type_, parent = None, req=None):
        if parent is None:
            parent = super().parse(raw_message)
        return packet_TPM1(type_, raw_message[10:], parent)


    def get_command(self):
        return TPM_1_2_COMMANDS[self.command]

    def __str__(self):
        return f"Version TPM: {self.version} \n" + super().__str__() + \
               f"Command : {self.get_command()}\n"

class packet_TPM2(packet_TPM):

    def __init__(self, type_, payload = None, parent = None):
        if parent:
            self.__dict__.update(parent.__dict__)
        self.version = "2"
        self.session = ((self.tag & 0b10) == 0b10)
        self.type_ = type_
        self.payload = payload
        

    @classmethod
    def parse(cls, raw_message, type_, parent = None, req=None):
        if parent is None:
            parent = super().parse(raw_message)

        tmp = packet_TPM2(type_, raw_message[10:], parent)
        if tmp.get_command() in get_Parse_Command():
            if req:
                tmp = get_Parse_Command()[tmp.get_command()].parse(raw_message, tmp, req)
            else:
                tmp = get_Parse_Command()[tmp.get_command()].parse(raw_message, tmp)
        return tmp

    def get_command(self):
        if self.type_ == 0x1:
            return TPM_2_COMMANDS[self.command]
        else:
            return TPM_2_COMMANDS_RESPONSE[self.command]

    def show_payload(self):
        return " ".join(hex(x) for x in self.payload)

    def prepare_packed(self):
        self.size_command = 10 + len(self.payload)

    def packed(self):
        data_tpm = super().packed()
        data_tpm += self.payload
        data = b''
        data += struct.pack("<B", self.type_)
        data += struct.pack("<H", len(data_tpm))
        data += data_tpm
        return data



    def __str__(self):
        return f"Version TPM: {self.version} \n" \
               f"Session : {self.session}\n" + super().__str__() + \
               f"Command : {self.get_command()}\n" \
               f"Payload : {self.show_payload()}\n"

class packet_TPM2_CC_PCR_Extend(packet_TPM2):
    def __init__(self, pcrHandle = 0x00000000, count = -1, auth_handle = 0, parent = None):
        if parent:
            self.__dict__.update(parent.__dict__)
        self.pcrHandle = pcrHandle
        self.count = count
        self.auth_handle = auth_handle

    @classmethod
    def parse(cls, raw_message, parent = None, req = None):
        if parent is None:
            parent = super().parse(raw_message)
        pcrHandle = struct.unpack(">I", raw_message[10:14])[0]
        count = struct.unpack(">I", raw_message[14:18])[0]
        auth_handle = struct.unpack(">I", raw_message[18:22])[0]
        return packet_TPM2_CC_PCR_Extend(pcrHandle, count, auth_handle, parent)

    def get_pcrHandle(self):
        return (TPM_PT_PCR_Constants[self.pcrHandle], self.pcrHandle)

    def __str__(self):
        return super().__str__() + f"pcrHandle : {self.get_pcrHandle()}\n" \
                + f"number of register digest : {self.count}\n" \
                + f"auth handle : {TPM_RH_Constans[self.auth_handle]}\n"

class packet_TPM2_CC_GetRandom(packet_TPM2):
    def __init__(self, number, parent=None):
        if parent:
            self.__dict__.update(parent.__dict__)
        self.number = number

    @classmethod
    def parse(cls, raw_message, parent = None, req=None):
        if parent is None:
            parent = super().parse(raw_message)
        number = struct.unpack(">H", raw_message[10:12])[0]
        return packet_TPM2_CC_GetRandom(number, parent)

    def __str__(self):
        return super().__str__() + f"Number of bytes : {self.number}\n"

class packet_TPM2_CC_GetRandomResp(packet_TPM2):
    def __init__(self, random_bytes, parent=None):
        if parent:
            self.__dict__.update(parent.__dict__)
        self.random_bytes = random_bytes
    
    @classmethod
    def parse(cls, raw_message, parent = None, req=None):
        random_bytes = raw_message[10:]
        return packet_TPM2_CC_GetRandomResp(random_bytes, parent)
    
    def beautyrandombytes(self):
        return " ".join(hex(x) for x in self.random_bytes)

    def __str__(self):
        return super().__str__() + f"Bytes receive : {self.beautyrandombytes()}\n"

class packet_TPM2_CC_PCR_Read(packet_TPM2):
    def __init__(self, count, tpms, parent=None):
        if parent:
            self.__dict__.update(parent.__dict__)
        self.count = count
        self.tpms = tpms
    
    @classmethod
    def parse(cls, raw_message, parent = None, req=None):
        count = struct.unpack(">I", raw_message[10:14])[0]
        tpms = []
        cnt = 0
        for i in range(count):
            tpms.append(TPMS_PCR_SELECTION.parse(raw_message[14 + cnt:]))
            cnt += tpms[-1].size + 4
        return packet_TPM2_CC_PCR_Read(count, tpms, parent)

    def show_tpms(self):
        return "\n".join( str(x) for x in self.tpms)
    
    def __str__(self):
        return super().__str__() + f"count PCR : {self.count}\n" \
                + self.show_tpms()

class TPMS_PCR_SELECTION:
    def __init__(self, hash_, size, pcr):
        self.hash_ = hash_
        self.size = size
        self.pcr = pcr

    @classmethod
    def parse(cls, raw_message):
        hash_ = struct.unpack(">H", raw_message[0:2])[0]
        size = struct.unpack(">B", raw_message[2:3])[0]
        pcr = raw_message[3:3+size]
        return TPMS_PCR_SELECTION(hash_, size, pcr)

    def show_pcr(self):
        return "0x" + "".join(f"{x:02x}" for x in self.pcr)

    def __str__(self):
        return f"pcr={self.show_pcr()}, size={self.size}, hash = {TPM_2_ALG_ID_Constans[self.hash_]}"


class packet_TPM2_RC_SUCESS(packet_TPM2):
    def __init__(self, parent=None):
        if parent:
            self.__dict__.update(parent.__dict__)

    @classmethod
    def parse(cls, raw_message, parent = None, req=None):
        assert req != None, "request None"
        if req.get_command() in get_Parse_Resp_Command():
            return get_Parse_Resp_Command()[req.get_command()].parse(raw_message,
                    parent, req)
        return parent

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate

def process_beauty(data, req, writer=None):
    if data.type_ == 0x1:
        type_ = "WRITE"
    else:
        type_ = "READ"

    #info = InfoTpmPacket()
    #TAG = struct.unpack(">H", data.data[0:2])[0]
    #if TAG >= 0x00c1 and TAG <= 0x00c7:
    #    info.version = "1.2"
    #elif TAG >= 0x8001 and TAG <= 0x8002:
    #    info.version = "2"
    #    info.session = ((TAG & 0b10) == 0b10)


    #info.size_command = struct.unpack(">I", data.data[2:6])[0]
    #info.command = struct.unpack(">I", data.data[6:10])[0]
    direction = ""
    if type_ == "READ":
        if not writer is None:
            write_pcap(writer, data.data, 1)
        info = packet_TPM.parse(data.data, data.type_, req=req)
        direction = fg.red + "<== "
    else:
        if not writer is None:
            write_pcap(writer, data.data, 0)
        info = packet_TPM.parse(data.data, data.type_)
        direction = fg.blue + "==> "
    print(direction, info.get_command(), fg.rs)
    commands = [ 'TPM_CC_PCR_Read' ]
    if info.get_command() in commands or (not req is None and req.get_command() in commands):
        print(f"{type_} : {' '.join(hex(x) for x in data.data)}")
        print(info)
    if type_ == "WRITE":
        return info
    return None


def proxy(conn, data, req):
    ack(conn)


def ack(conn):
    conn.send(b"\x03\x00\x00")




@static_vars(req=None)
def listen_socket(arg, writer=None, proxy=proxy):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(socket_path)
        os.system("chmod o+w " + socket_path)
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            while True:
                #data = conn.recv(2048)
                #if not data: break
                tmp = packet_socket()
                ret = tmp.unpack(conn)
                if ret == -1:
                    break
                ret = None
                if arg == TypeShow.RAW:
                    ret = process_raw(tmp)
                elif arg == TypeShow.BEAUTY:
                    ret = process_beauty(tmp, listen_socket.req, writer)
                if not tmp is None and tmp.type_ == 0x1:
                    listen_socket.req = packet_TPM.parse(tmp.data, tmp.type_)
                #conn.sendall(data)
                proxy(conn, packet_TPM.parse(tmp.data, tmp.type_, listen_socket.req), listen_socket.req)

        os.system("rm " + socket_path)


def init_wireshark(filename):
    if False:
        os.mkfifo(filename)

    return PcapWriter(filename)

@static_vars(port=None)
def write_pcap(writer, data, direction):
    if direction == 0:
        write_pcap.port=randint(10024, 65535)
        writer.write(Ether()/IP()/TCP(sport=write_pcap.port, dport=2321)/data)
    else:
        writer.write(Ether()/IP()/TCP(sport=2321, dport=write_pcap.port)/data)
    writer.flush()
