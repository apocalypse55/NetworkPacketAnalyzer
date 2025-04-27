import org.pcap4j.packet.*;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import java.nio.charset.StandardCharsets;

public class HttpPacketParser {

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
     * @param packet The packet to extract from.
     * @return Decoded HTTP content as a string, or null if not HTTP or no content.
     */
    public static String extractHttpContent(Packet packet) {
        if (!isHttpPacket(packet)) return null;
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket == null || tcpPacket.getPayload() == null) return null;
        byte[] payload = tcpPacket.getPayload().getRawData();
        try {
            return new String(payload, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error decoding HTTP content: " + e.getMessage();
        }
    }
} 