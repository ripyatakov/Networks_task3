import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

public class PcapARP {

    public static void main(String[] args) {

        try {
            InetAddress addr = InetAddress.getByName(SendArpRequest.strSrcIpAddress);
            PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10000;
            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            while (true) {
                    Packet packet = handle.getNextPacketEx();
                    ArpPacket arpPacket = packet.get(ArpPacket.class);
                    if (arpPacket != null) {
                        System.out.println(arpPacket);
                }
            }
        }
        catch (Exception e){
            System.out.println("Error to start thread");
        }
    }
}
