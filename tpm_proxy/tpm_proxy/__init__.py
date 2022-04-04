from tpm_proxy.server import init_wireshark, listen_socket, TypeShow

def main():
    writer = init_wireshark("test.pcap")
    #write_pcap(writer, b"\x80\x01\x00\x00\x00\x0a\x00\x00\x01\x81")
    arg = TypeShow.BEAUTY
    listen_socket(arg, writer)
    writer.close()
