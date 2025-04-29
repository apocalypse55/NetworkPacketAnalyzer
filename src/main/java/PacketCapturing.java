import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.MacAddress;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;

public class PacketCapturing {

    private NetworkGraphGUI graphGUI;
    private BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>();
    private List<Packet> capturedPackets = new ArrayList<>();
    private NetworkInterfaceInfo networkInfo;
    private String protocolFilter = "All";
    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;
    private PcapHandle handle;
    private PcapDumper dumper;
    private PcapNetworkInterface currentDevice;
    private JTable currentPacketList;
    private volatile boolean dumperClosed = false;
    private InterfaceWindow interfaceWindow;

    public PacketCapturing(NetworkInterfaceInfo networkInfo, InterfaceWindow window) {
        this.networkInfo = networkInfo;
        this.graphGUI = new NetworkGraphGUI(this);
        this.interfaceWindow = window;
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

            dumperClosed = false;
            dumper = handle.dumpOpen("out.pcap");

            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    try {
                        packetQueue.put(packet);
                        SwingUtilities.invokeLater(() -> updatePacketTable(packet, packetList));
                        if (!dumperClosed && dumper != null) {
                            try {
                                // Use a try-catch block to handle timestamp errors
                                try {
                                    dumper.dump(packet, handle.getTimestamp());
                                } catch (IllegalArgumentException e) {
                                    // If there's a timestamp error, use a default timestamp
                                    System.out.println("Timestamp error, using default timestamp: " + e.getMessage());
                                    // Create a new timestamp with current time
                                    java.sql.Timestamp timestamp = new java.sql.Timestamp(System.currentTimeMillis());
                                    dumper.dump(packet, timestamp);
                                }
                            } catch (NotOpenException e) {
                                System.out.println("Dumper is closed, skipping packet dump");
                                dumperClosed = true;
                            }
                        }
                        // Integration: Try to extract HTTP payload from the packet
                        try {
                            String httpPayload = HttpPacketParser.extractHttpPayload(bytesToHex(packet.getRawData()));
                            if (httpPayload != null) {
                                System.out.println("[HTTP Detected]\n" + httpPayload);
                            }
                        } catch (Exception ex) {
                            // Ignore parsing errors
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            };

            // Use a more robust approach to packet capture
            new Thread(() -> {
                try {
                    while (isRunning && handle.isOpen()) {
                        try {
                            // Capture one packet at a time with error handling
                            handle.loop(1, listener);
                        } catch (InterruptedException e) {
                            // Handle interruption
                            Thread.currentThread().interrupt();
                            break;
                        } catch (NotOpenException e) {
                            // Handle closed handle
                            System.out.println("PcapHandle is closed, stopping capture");
                            break;
                        } catch (PcapNativeException e) {
                            // Handle native exceptions
                            System.out.println("PcapNativeException: " + e.getMessage());
                            // Try to recover by reopening the handle
                            try {
                                Thread.sleep(1000); // Wait a bit before retrying
                                if (isRunning) {
                                    handle = new PcapHandle.Builder(device.getName())
                                            .snaplen(snapshotLength)
                                            .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                                            .timeoutMillis(readTimeout)
                                            .build();
                                    if (filterExpression != null && !filterExpression.isEmpty()) {
                                        handle.setFilter(filterExpression, BpfCompileMode.OPTIMIZE);
                                    }
                                    dumperClosed = false;
                                    dumper = handle.dumpOpen("out.pcap");
                                }
                            } catch (Exception ex) {
                                System.out.println("Failed to recover from PcapNativeException: " + ex.getMessage());
                                break;
                            }
                        } catch (Error e) {
                            // Handle JVM errors like Invalid memory access
                            System.out.println("JVM Error during capture: " + e.getMessage());
                            // Try to recover by reopening the handle
                            try {
                                Thread.sleep(1000); // Wait a bit before retrying
                                if (isRunning) {
                                    handle = new PcapHandle.Builder(device.getName())
                                            .snaplen(snapshotLength)
                                            .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                                            .timeoutMillis(readTimeout)
                                            .build();
                                    if (filterExpression != null && !filterExpression.isEmpty()) {
                                        handle.setFilter(filterExpression, BpfCompileMode.OPTIMIZE);
                                    }
                                    dumperClosed = false;
                                    dumper = handle.dumpOpen("out.pcap");
                                }
                            } catch (Exception ex) {
                                System.out.println("Failed to recover from JVM Error: " + ex.getMessage());
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
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
        String httpContent = "";
        int payloadLength = 0;
        long timestamp = System.currentTimeMillis(); // Default to current time

        // Get timestamp from handle if available, with proper null checking
        if (handle != null && handle.isOpen()) {
            try {
                java.sql.Timestamp pcapTimestamp = handle.getTimestamp();
                if (pcapTimestamp != null) {
                    timestamp = pcapTimestamp.getTime();
                } else {
                    System.out.println("Warning: Null timestamp from PcapHandle, using system time");
                }
            } catch (NotOpenException e) {
                System.out.println("Warning: Handle not open for timestamp, using system time");
            } catch (Exception e) {
                System.out.println("Warning: Error getting timestamp: " + e.getMessage() + ", using system time");
            }
        }

        try {
            // Extract addresses and protocol
            if (packet instanceof EthernetPacket) {
                EthernetPacket ethernetPacket = (EthernetPacket) packet;
                if (ethernetPacket.getPayload() instanceof IpPacket) {
                    IpPacket ipPacket = (IpPacket) ethernetPacket.getPayload();
                    sourceAddress = ipPacket.getHeader().getSrcAddr().getHostAddress();
                    destAddress = ipPacket.getHeader().getDstAddr().getHostAddress();
                    protocol = getEncapsulatedProtocol(ipPacket);
                    
                    // Extract HTTP content if it's TCP
                    if (ipPacket.getPayload() instanceof TcpPacket) {
                        TcpPacket tcpPacket = (TcpPacket) ipPacket.getPayload();
                        if (tcpPacket.getPayload() != null) {
                            byte[] payload = tcpPacket.getPayload().getRawData();
                            payloadLength = payload.length;
                            String content = new String(payload, StandardCharsets.UTF_8);
                            if (isHttpContent(content)) {
                                httpContent = extractHttpInfo(content);
                                protocol = "HTTP";
                                // Update graph with HTTP details
                                graphGUI.updateTraffic(packet, sourceAddress, destAddress, protocol);
                            }
                        }
                    }
                }
            } else if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                sourceAddress = ipPacket.getHeader().getSrcAddr().getHostAddress();
                destAddress = ipPacket.getHeader().getDstAddr().getHostAddress();
                protocol = getEncapsulatedProtocol(ipPacket);
                
                // Extract HTTP content if it's TCP
                if (ipPacket.getPayload() instanceof TcpPacket) {
                    TcpPacket tcpPacket = (TcpPacket) ipPacket.getPayload();
                    if (tcpPacket.getPayload() != null) {
                        byte[] payload = tcpPacket.getPayload().getRawData();
                        payloadLength = payload.length;
                        String content = new String(payload, StandardCharsets.UTF_8);
                        if (isHttpContent(content)) {
                            httpContent = extractHttpInfo(content);
                            protocol = "HTTP";
                            // Update graph with HTTP details
                            graphGUI.updateTraffic(packet, sourceAddress, destAddress, protocol);
                        }
                    }
                }
            }

            // Only display packets that match the current filter
            if (shouldDisplayPacket(protocol)) {
                DefaultTableModel model = (DefaultTableModel) packetList.getModel();
                // Display "-" if no HTTP content was found
                String displayContent = httpContent.isEmpty() ? "-" : httpContent;
                model.addRow(new Object[]{
                    new java.util.Date(timestamp),
                    sourceAddress,
                    destAddress,
                    protocol,
                    payloadLength,
                    displayContent
                });
                
                // Keep the latest packet visible
                int lastRow = packetList.getRowCount() - 1;
                if (lastRow >= 0) {
                    packetList.scrollRectToVisible(packetList.getCellRect(lastRow, 0, true));
                }
            }

        } catch (Exception e) {
            System.err.println("Error processing packet: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private boolean isHttpContent(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }
        // Check for common HTTP methods
        String[] httpMethods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH"};
        for (String method : httpMethods) {
            if (content.startsWith(method + " ")) {
                return true;
            }
        }
        // Check for HTTP response
        return content.startsWith("HTTP/");
    }

    private String extractHttpInfo(String httpContent) {
        if (httpContent == null || httpContent.isEmpty()) {
            return "";
        }
        // Extract the first line and any important headers
        String[] lines = httpContent.split("\\r?\\n");
        StringBuilder result = new StringBuilder();
        
        // Add the first line (request/response line)
        if (lines.length > 0) {
            result.append(lines[0].trim());
        }
        
        // Look for important headers
        for (int i = 1; i < lines.length && i < 5; i++) {
            String line = lines[i].trim();
            if (line.startsWith("Host:") || 
                line.startsWith("Content-Type:") || 
                line.startsWith("Content-Length:") ||
                line.startsWith("Location:")) {
                result.append("\n").append(line);
            }
        }
        
        return result.toString();
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
            try {
                dumper.flush();
                dumper.close();
                dumperClosed = true;
            } catch (NotOpenException e) {
                // Ignore if already closed
            } catch (PcapNativeException e) {
                // Handle native exception
                e.printStackTrace();
            }
        }
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    public void pauseCapturing() {
        isPaused = true;
    }

    public void resumeCapturing() {
        try {
            if (currentDevice != null) {
                isPaused = false;
                isRunning = true;
                
                // Only recreate handle if it's closed
                if (handle == null || !handle.isOpen()) {
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

                    // Create new dumper with append mode if needed
                    if (dumper == null || dumperClosed) {
                        dumperClosed = false;
                        dumper = handle.dumpOpen("out.pcap");
                    }
                    
                    // Start a new capture thread
                    startCaptureThread();
                }
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

    public void saveCapture(String filePath) {
        try {
            PcapHandle saveHandle = new PcapHandle.Builder(currentDevice.getName())
                    .snaplen(65536)
                    .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                    .timeoutMillis(50)
                    .build();
            
            PcapDumper saveDumper = saveHandle.dumpOpen(filePath);
            for (Packet packet : capturedPackets) {
                saveDumper.dump(packet, new java.sql.Timestamp(System.currentTimeMillis()));
            }
            saveDumper.flush();
            saveDumper.close();
            saveHandle.close();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to save capture: " + e.getMessage());
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
            // If HTTP, append HTTP payload using improved extraction
            if (HttpPacketParser.isHttpPacket(packet)) {
                String httpPayload = HttpPacketParser.extractHttpContent(packet);
                if (httpPayload != null) {
                    details.append("\n--- HTTP Content ---\n");
                    details.append(httpPayload);
                    details.append("\n--------------------\n");
                }
            }
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private void updateStatistics(Packet packet) {
        if (interfaceWindow != null) {
            try {
                // Update statistics in the interface window
                SwingUtilities.invokeLater(() -> {
                    interfaceWindow.updatePacketStats(packet);
                });
            } catch (Exception e) {
                System.out.println("Error updating statistics: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    public void clearCapture() {
        capturedPackets.clear();
        if (currentPacketList != null) {
            SwingUtilities.invokeLater(() -> {
                DefaultTableModel model = (DefaultTableModel) currentPacketList.getModel();
                model.setRowCount(0);
            });
        }
        if (graphGUI != null) {
            graphGUI.updateTraffic(null, null, null, null);
        }
    }

    public boolean hasCapturedPackets() {
        return !capturedPackets.isEmpty();
    }

    private void startCaptureThread() {
        new Thread(() -> {
            try {
                while (isRunning && handle.isOpen()) {
                    if (!isPaused) {
                        try {
                            handle.loop(1, (PacketListener) packet -> {
                                try {
                                    capturedPackets.add(packet);
                                    packetQueue.put(packet);
                                    SwingUtilities.invokeLater(() -> {
                                        updatePacketTable(packet, currentPacketList);
                                        updateStatistics(packet);
                                    });
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                }
                            });
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        } catch (NotOpenException e) {
                            System.out.println("PcapHandle is closed");
                            break;
                        }
                    } else {
                        Thread.sleep(100); // Sleep while paused
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
}