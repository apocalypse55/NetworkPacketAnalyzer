import org.pcap4j.packet.*;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.Arrays;

public class HttpPacketParser {
    // Add TCP stream reassembly support
    private static final Map<String, TreeMap<Long, byte[]>> tcpStreams = new HashMap<>();
    private static final Map<String, String> httpHeaders = new HashMap<>();
    private static final Map<String, ByteArrayOutputStream> contentBuffers = new HashMap<>();
    private static final Map<String, Integer> contentLengths = new HashMap<>();
    private static final Map<String, Integer> expectedContentLengths = new HashMap<>();
    
    /**
     * Creates a unique key for a TCP stream
     */
    private static String getTcpStreamKey(TcpPacket tcpPacket, IpPacket ipPacket) {
        String sourceIP = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String destIP = ipPacket.getHeader().getDstAddr().getHostAddress();
        int sourcePort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        int destPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        return String.format("%s:%d-%s:%d", sourceIP, sourcePort, destIP, destPort);
    }

    /**
     * Reassembles TCP segments for a given stream
     */
    private static byte[] reassembleTcpStream(String streamKey, TcpPacket tcpPacket, byte[] payload) {
        TreeMap<Long, byte[]> segments = tcpStreams.computeIfAbsent(streamKey, k -> new TreeMap<>());
        long seq = tcpPacket.getHeader().getSequenceNumber() & 0xFFFFFFFFL; // Convert to unsigned
        segments.put(seq, payload);

        ByteArrayOutputStream assembled = new ByteArrayOutputStream();
        ByteArrayOutputStream contentBuffer = contentBuffers.computeIfAbsent(streamKey, k -> new ByteArrayOutputStream());
        
        // Process segments in order
        Long currentSeq = segments.firstKey();
        while (segments.containsKey(currentSeq)) {
            byte[] segment = segments.get(currentSeq);
            assembled.write(segment, 0, segment.length);
            contentBuffer.write(segment, 0, segment.length);
            currentSeq += segment.length;
            segments.remove(currentSeq - segment.length);
        }

        // Get the expected content length for this stream
        Integer expectedLength = expectedContentLengths.get(streamKey);
        
        // If we have all the data, return it
        if (expectedLength != null && contentBuffer.size() >= expectedLength) {
            byte[] completeContent = contentBuffer.toByteArray();
            // Clean up
            contentBuffers.remove(streamKey);
            expectedContentLengths.remove(streamKey);
            tcpStreams.remove(streamKey);
            return Arrays.copyOf(completeContent, expectedLength);
        }

        return null;
    }

    /**
     * Converts a hex dump string to a byte array.
     */
    public static byte[] hexStringToByteArray(String s) {
        s = s.replaceAll("\\s", ""); // Remove all whitespace
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Parses the byte array as a packet and extracts HTTP payload if present.
     * @param hexDumpString The hex dump string.
     * @return HTTP payload as a string, or null if not found.
     */
    public static String extractHttpPayload(String hexDumpString) {
        byte[] rawData = hexStringToByteArray(hexDumpString);
        // Try to parse as Ethernet first
        Packet packet = null;
        try {
            packet = PacketFactories.getFactory(Packet.class, EtherType.class)
                    .newInstance(rawData, 0, rawData.length);
        } catch (Exception e) {
            // Fallback: try as IPv4
            try {
                packet = IpV4Packet.newPacket(rawData, 0, rawData.length);
            } catch (Exception ex) {
                return null;
            }
        }
        if (packet == null) return null;

        // Traverse to TCP payload
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            Packet payload = tcpPacket.getPayload();
            if (payload != null) {
                byte[] appData = payload.getRawData();
                String http = new String(appData, StandardCharsets.US_ASCII);
                // Basic check for HTTP
                if (http.startsWith("GET") || http.startsWith("POST") || http.startsWith("HTTP/")) {
                    return http;
                }
            }
        }
        return null;
    }

    /**
     * Checks if the given packet contains an HTTP payload by port and content.
     * @param packet The packet to check.
     * @return true if the packet is HTTP, false otherwise.
     */
    public static boolean isHttpPacket(Packet packet) {
        if (packet == null) return false;
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            // Common HTTP ports
            boolean isHttpPort = srcPort == 80 || dstPort == 80 ||
                                 srcPort == 8080 || dstPort == 8080 ||
                                 srcPort == 8000 || dstPort == 8000 ||
                                 srcPort == 8008 || dstPort == 8008;
            Packet payload = tcpPacket.getPayload();
            if (payload != null) {
                String dataStr = new String(payload.getRawData(), StandardCharsets.US_ASCII);
                boolean isHttpContent = dataStr.startsWith("GET ") || dataStr.startsWith("POST ") ||
                       dataStr.startsWith("HEAD ") || dataStr.startsWith("PUT ") ||
                       dataStr.startsWith("DELETE ") || dataStr.startsWith("HTTP/") ||
                       dataStr.contains("Content-Type:") || dataStr.contains("User-Agent:");
                return isHttpPort || isHttpContent;
            }
            return isHttpPort;
        }
        return false;
    }

    /**
     * Extracts and decodes HTTP content from a TCP packet if present.
     */
    public static String extractHttpContent(Packet packet) {
        if (!isHttpPacket(packet)) return null;
        
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        IpPacket ipPacket = packet.get(IpPacket.class);
        
        if (tcpPacket == null || tcpPacket.getPayload() == null) return null;
        
        String streamKey = getTcpStreamKey(tcpPacket, ipPacket);
        byte[] payload = tcpPacket.getPayload().getRawData();
        
        try {
            String content = new String(payload, StandardCharsets.ISO_8859_1);
            
            // If this is the start of an HTTP message
            if (content.startsWith("HTTP/")) {
                httpHeaders.put(streamKey, content);
                
                // Extract Content-Length
                int contentLengthIndex = content.indexOf("Content-Length: ");
                if (contentLengthIndex != -1) {
                    int endIndex = content.indexOf("\r\n", contentLengthIndex);
                    if (endIndex != -1) {
                        String lengthStr = content.substring(contentLengthIndex + 16, endIndex).trim();
                        try {
                            int contentLength = Integer.parseInt(lengthStr);
                            expectedContentLengths.put(streamKey, contentLength);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid Content-Length: " + lengthStr);
                        }
                    }
                }
            }
            
            // Show current packet content instead of waiting for complete stream
            return content;
            
        } catch (Exception e) {
            System.err.println("Error processing HTTP content: " + e.getMessage());
            e.printStackTrace();
            return "Error decoding HTTP content: " + e.getMessage();
        }
    }
} 