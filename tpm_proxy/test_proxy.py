
from tpm_proxy.server import init_wireshark, listen_socket, TypeShow, ack

def proxy(conn, data, req):
    print("data:", data, "\nreq:", req)
    print(type(req))
    if data.type_ == 0x1: #WRITE
        if data.get_command() == "TPM_CC_NV_Write":
            print(data.get_command())
            data.payload = b'\x01\x02\x03'
            data.prepare_packed()
            conn.send(data.packed())
            return;
    if data.type_ == 0x0: #READ
        if req.get_command() == 'TPM_CC_GetRandom':
            data.payload = data.payload[0:2] + b'\x00' * (len(data.payload) - 2)
            conn.send(data.packed())
            return;
    ack(conn)

def main():
    #writer = init_wireshark("test.pcap")
    #write_pcap(writer, b"\x80\x01\x00\x00\x00\x0a\x00\x00\x01\x81")
    arg = TypeShow.BEAUTY
    listen_socket(arg, proxy=proxy)
    #writer.close()


if __name__ == "__main__":
    main()
