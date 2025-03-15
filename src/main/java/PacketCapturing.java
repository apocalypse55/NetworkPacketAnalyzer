import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.MacAddress;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.core.BpfProgram.BpfCompileMode;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.ArrayList;
import java.util.List;

public class PacketCapturing {

    private NetworkGraphGUI graphGUI;
    private BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>();
    private List<Packet> capturedPackets = new ArrayList<>();
    private NetworkInterfaceInfo networkInfo;
    private String protocolFilter = "All";
    private volatile boolean isRunning = false;
    private PcapHandle handle;
    private PcapDumper dumper;
    private PcapNetworkInterface currentDevice;
    private JTable currentPacketList;

    public PacketCapturing(NetworkInterfaceInfo networkInfo) {
        this.networkInfo = networkInfo;
        this.graphGUI = new NetworkGraphGUI(this);
    }

    public void startCapturing(PcapNetworkInterface device, JTable packetList, String filterExpression) throws PcapNativeException, NotOpenException {
        try {
            isRunning = true;
            currentDevice = device;
            currentPacketList = packetList;
            int snapshotLength = 65536;
            int readTimeout = 50;

            handle = new PcapHandle.Builder(device.getName())
                    .snaplen(snapshotLength)
                    .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                    .timeoutMillis(readTimeout)
                    .build();

            // Apply BPF filter if provided
            if (filterExpression != null && !filterExpression.isEmpty()) {
                handle.setFilter(filterExpression, BpfCompileMode.OPTIMIZE);
            }

            // Check if this is a wireless interface
            if (device.getLinkLayerAddresses() != null && !device.getLinkLayerAddresses().isEmpty()) {
                System.out.println("Link type: " + handle.getDlt());
                if (handle.getDlt() == DataLinkType.IEEE802_11) {
                    System.out.println("Wireless interface detected");
                }
            }

            dumper = handle.dumpOpen("out.pcap");

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
                    while (isRunning && handle.isOpen()) {
                        handle.loop(1, listener);  // Capture one packet at a time
                    }
                } catch (InterruptedException | NotOpenException | PcapNativeException e) {
                    e.printStackTrace();
                }
            }).start();
        } catch (PcapNativeException e) {
            stopCapturing();  // Clean up resources if initialization fails
            throw e;  // Re-throw the exception to be handled by the caller
        }
    }

    private void updatePacketTable(Packet packet, JTable packetList) {
        String sourceAddress = "Unknown";
        String destAddress = "Unknown";
        String protocol = "Unknown";

        try {
            // First, check if it's a raw 802.11 frame
            if (packet instanceof EthernetPacket) {
                EthernetPacket ethernetPacket = (EthernetPacket) packet;
                
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

            // Update the graph visualization with detailed packet info
            if (!sourceAddress.equals("Unknown") && !destAddress.equals("Unknown")) {
                graphGUI.updateTraffic(packet, sourceAddress, destAddress, protocol);
            }

            // Only add packets that match the filter
            if (shouldDisplayPacket(protocol)) {
                DefaultTableModel model = (DefaultTableModel) packetList.getModel();
                Object[] row = {model.getRowCount() + 1, packet.length(), sourceAddress, destAddress, protocol};
                model.addRow(row);
                capturedPackets.add(packet);
            }

        } catch (Exception e) {
            System.out.println("Error processing packet: " + e.getMessage());
            e.printStackTrace();
        }
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

    public void stopCapturing() {
        isRunning = false;
        if (dumper != null) {
            dumper.close();
        }
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    public void resumeCapturing() {
        try {
            if (currentDevice != null) {
                // Reopen the handle with the same settings
                handle = new PcapHandle.Builder(currentDevice.getName())
                        .snaplen(65536)
                        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                        .timeoutMillis(50)
                        .build();
                
                // Reapply any existing filter
                if (handle.getFilteringExpression() != null && !handle.getFilteringExpression().isEmpty()) {
                    handle.setFilter(handle.getFilteringExpression(), BpfCompileMode.OPTIMIZE);
                }

                // Create new dumper with append mode
                dumper = handle.dumpOpen("out.pcap");  // This will append to existing file
                
                isRunning = true;

                // Create packet listener outside the loop
                PacketListener listener = new PacketListener() {
                    @Override
                    public void gotPacket(Packet packet) {
                        try {
                            packetQueue.put(packet);
                            // Update both the table and graph
                            SwingUtilities.invokeLater(() -> updatePacketTable(packet, currentPacketList));
                            dumper.dump(packet, handle.getTimestamp());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                };

                // Start capture thread
                new Thread(() -> {
                    try {
                        while (isRunning && handle.isOpen()) {
                            handle.loop(1, listener);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            } else {
                throw new IllegalStateException("No network interface was previously captured");
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null,
                "Error resuming capture: " + e.getMessage(),
                "Resume Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    public void setProtocolFilter(String filter) {
        this.protocolFilter = filter;
    }

    private boolean shouldDisplayPacket(String protocol) {
        if (protocolFilter.equals("All")) {
            return true;
        }
        return protocol.equals(protocolFilter);
    }

    public void saveCapture() throws NotOpenException, PcapNativeException {
        if (dumper != null) {
            dumper.flush();  // Ensure all packets are written
        }
    }

    public boolean isCapturing() {
        return isRunning;
    }

    public String getPacketDetails(Packet packet) {
        if (packet == null) return "";
        
        StringBuilder details = new StringBuilder();
        
        // Frame information
        details.append(String.format("Frame: %d bytes on wire, %d bytes captured\n",
            packet.length(), packet.length()));
            
        // Ethernet information
        if (packet instanceof EthernetPacket) {
            EthernetPacket ethernetPacket = (EthernetPacket) packet;
            details.append("Ethernet II:\n");
            details.append(String.format("   Source MAC: %s\n", ethernetPacket.getHeader().getSrcAddr()));
            details.append(String.format("   Destination MAC: %s\n", ethernetPacket.getHeader().getDstAddr()));
        }
        
        // IP information
        if (packet.contains(IpPacket.class)) {
            IpPacket ipPacket = packet.get(IpPacket.class);
            details.append(String.format("Internet Protocol Version %d:\n",
                ipPacket instanceof IpV4Packet ? 4 : 6));
            details.append("   0100 .... = Version: " + (ipPacket instanceof IpV4Packet ? "4" : "6") + "\n");
            if (ipPacket instanceof IpV4Packet) {
                IpV4Packet ipv4Packet = (IpV4Packet) ipPacket;
                IpV4Header header = ipv4Packet.getHeader();
                details.append(String.format("   .... %d = Header Length: %d bytes\n", 
                    header.getIhlAsInt(), header.getIhlAsInt() * 4));
                details.append(String.format("   Differentiated Services Field: 0x%02x\n", 
                    header.getTos().value()));
                details.append(String.format("   Total Length: %d\n", header.getTotalLength()));
                details.append(String.format("   Identification: 0x%04x (%d)\n", 
                    header.getIdentification(), header.getIdentification()));
                details.append(String.format("   Flags: 0x%x\n", header.getFragmentOffset() >> 13));
                details.append(String.format("   Fragment Offset: %d\n", header.getFragmentOffset() & 0x1FFF));
                details.append(String.format("   Time to Live: %d\n", header.getTtl()));
                details.append(String.format("   Protocol: %s (%d)\n", 
                    getProtocolName(header.getProtocol().value()), header.getProtocol().value()));
                details.append(String.format("   Header Checksum: 0x%04x\n", header.getHeaderChecksum()));
                details.append(String.format("   Source Address: %s\n", header.getSrcAddr()));
                details.append(String.format("   Destination Address: %s\n", header.getDstAddr()));
            }
        }
        
        // TCP/UDP information
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            TcpHeader header = tcpPacket.getHeader();
            details.append("Transmission Control Protocol:\n");
            details.append(String.format("   Source Port: %d\n", header.getSrcPort().valueAsInt()));
            details.append(String.format("   Destination Port: %d\n", header.getDstPort().valueAsInt()));
            details.append(String.format("   Sequence Number: %d\n", header.getSequenceNumber()));
            details.append(String.format("   Acknowledgment Number: %d\n", header.getAcknowledgmentNumber()));
            details.append(String.format("   Header Length: %d bytes\n", header.getDataOffset() * 4));
            // TCP Flags
            details.append("   Flags: ");
            details.append(header.getUrg() ? "URG " : "");
            details.append(header.getAck() ? "ACK " : "");
            details.append(header.getPsh() ? "PSH " : "");
            details.append(header.getRst() ? "RST " : "");
            details.append(header.getSyn() ? "SYN " : "");
            details.append(header.getFin() ? "FIN " : "");
            details.append("\n");
            details.append(String.format("   Window Size: %d\n", header.getWindow()));
            details.append(String.format("   Checksum: 0x%04x\n", header.getChecksum()));
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpHeader header = udpPacket.getHeader();
            details.append("User Datagram Protocol:\n");
            details.append(String.format("   Source Port: %d\n", header.getSrcPort().valueAsInt()));
            details.append(String.format("   Destination Port: %d\n", header.getDstPort().valueAsInt()));
            details.append(String.format("   Length: %d\n", header.getLength()));
            details.append(String.format("   Checksum: 0x%04x\n", header.getChecksum()));
        }

        return details.toString();
    }

    public void showGraphVisualization() {
        graphGUI.setVisible(true);
    }
}