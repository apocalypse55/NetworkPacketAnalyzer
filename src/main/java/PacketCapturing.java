import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.MacAddress;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.ArrayList;
import java.util.List;

public class PacketCapturing {

    private BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>();
    private List<Packet> capturedPackets = new ArrayList<>();
    private NetworkInterfaceInfo networkInfo;

    public PacketCapturing(NetworkInterfaceInfo networkInfo) {
        this.networkInfo = networkInfo;
    }

    public void startCapturing(PcapNetworkInterface device, JTable packetList) throws PcapNativeException, NotOpenException {
        int snapshotLength = 65536;
        int readTimeout = 50;

        final PcapHandle handle = new PcapHandle.Builder(device.getName())
                .snaplen(snapshotLength)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(readTimeout)
                .build();

        // Check if this is a wireless interface
        if (device.getLinkLayerAddresses() != null && !device.getLinkLayerAddresses().isEmpty()) {
            System.out.println("Link type: " + handle.getDlt());
            if (handle.getDlt() == DataLinkType.IEEE802_11) {
                System.out.println("Wireless interface detected");
            }
        }

        PcapDumper dumper = handle.dumpOpen("out.pcap");

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                try {
                    packetQueue.put(packet);
                    SwingUtilities.invokeLater(() -> updatePacketTable(packet, packetList));
                    dumper.dump(packet, handle.getTimestamp());
                } catch (InterruptedException | NotOpenException e) {
                    e.printStackTrace();
                }
            }
        };

        new Thread(() -> {
            try {
                int maxPackets = 500;
                handle.loop(maxPackets, listener);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (NotOpenException | PcapNativeException e) {
                throw new RuntimeException(e);
            }
        }).start();
    }

    private void updatePacketTable(Packet packet, JTable packetList) {
        capturedPackets.add(packet);

        String sourceAddress = "Unknown";
        String destAddress = "Unknown";
        String protocol = "Unknown";

        try {
            // First, check if it's a raw 802.11 frame
            if (packet instanceof EthernetPacket) {
                EthernetPacket ethernetPacket = (EthernetPacket) packet;
                sourceAddress = ethernetPacket.getHeader().getSrcAddr().toString();
                destAddress = ethernetPacket.getHeader().getDstAddr().toString();
                protocol = "802.11";

                // Try to get the encapsulated IP packet
                if (ethernetPacket.getPayload() instanceof IpPacket) {
                    IpPacket ipPacket = (IpPacket) ethernetPacket.getPayload();
                    sourceAddress = ipPacket.getHeader().getSrcAddr().getHostAddress();
                    destAddress = ipPacket.getHeader().getDstAddr().getHostAddress();
                    protocol = getEncapsulatedProtocol(ipPacket);
                }
            }
            // Handle IPv4 packets
            else if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                sourceAddress = ipPacket.getHeader().getSrcAddr().getHostAddress();
                destAddress = ipPacket.getHeader().getDstAddr().getHostAddress();
                protocol = getEncapsulatedProtocol(ipPacket);
            }
            // Handle IPv6 packets
            else if (packet.contains(IpV6Packet.class)) {
                IpV6Packet ipPacket = packet.get(IpV6Packet.class);
                sourceAddress = ipPacket.getHeader().getSrcAddr().getHostAddress();
                destAddress = ipPacket.getHeader().getDstAddr().getHostAddress();
                protocol = getEncapsulatedProtocol(ipPacket);
            }

            // Log packet details for debugging
            System.out.println("Packet type: " + packet.getClass().getSimpleName());
            System.out.println("Source: " + sourceAddress);
            System.out.println("Destination: " + destAddress);
            System.out.println("Protocol: " + protocol);

        } catch (Exception e) {
            System.out.println("Error processing packet: " + e.getMessage());
            e.printStackTrace();
        }

        DefaultTableModel model = (DefaultTableModel) packetList.getModel();
        Object[] row = {model.getRowCount() + 1, packet.length(), sourceAddress, destAddress, protocol};
        model.addRow(row);
    }

    private String getEncapsulatedProtocol(IpPacket ipPacket) {
        Packet payload = ipPacket.getPayload();
        if (payload instanceof TcpPacket) {
            return "TCP";
        } else if (payload instanceof UdpPacket) {
            return "UDP";
        } else if (ipPacket instanceof IpV4Packet &&
                ((IpV4Packet)ipPacket).getHeader().getProtocol().value() == 1) {
            return "ICMP";
        } else if (ipPacket instanceof IpV6Packet &&
                ((IpV6Packet)ipPacket).getHeader().getNextHeader().value() == 58) {
            return "ICMPv6";
        }
        return "IP";
    }

    private String getProtocolName(int protocolNumber) {
        switch (protocolNumber) {
            case 1: return "ICMP";
            case 2: return "IGMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 58: return "ICMPv6";
            case 89: return "OSPF";
            case 50: return "ESP";
            case 51: return "AH";
            case 47: return "GRE";
            case 132: return "SCTP";
            default: return "IP(" + protocolNumber + ")";
        }
    }

    public Packet getPacket(int index) {
        if (index >= 0 && index < capturedPackets.size()) {
            return capturedPackets.get(index);
        }
        return null;
    }
}