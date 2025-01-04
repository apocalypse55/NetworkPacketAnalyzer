import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

public class NetworkInterfaceInfo {
    // Method to fetch all active network interfaces
    public List<String> getNetworkInterfaces() throws SocketException {
        List<String> interfaceNames = new ArrayList<>();
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            if (iface.isUp()) {
                interfaceNames.add(iface.getName());
            }
        }
        return interfaceNames;
    }

    // Method to fetch detailed information about a specific interface
    public String getInterfaceDetails(String interfaceName) throws SocketException {
        NetworkInterface iface = NetworkInterface.getByName(interfaceName);
        if (iface == null) {
            return "Interface not found.";
        }

        StringBuilder details = new StringBuilder();
        details.append("Interface Name: ").append(iface.getName()).append("\n");
        details.append("Display Name: ").append(iface.getDisplayName()).append("\n");
        details.append("Hardware Address: ").append(Arrays.toString(iface.getHardwareAddress())).append("\n");
        details.append("MTU: ").append(iface.getMTU()).append("\n");
        details.append("Supports Multicast: ").append(iface.supportsMulticast()).append("\n");

        details.append("\nInetAddresses:\n");
        Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
        while (inetAddresses.hasMoreElements()) {
            details.append("\t").append(inetAddresses.nextElement().toString()).append("\n");
        }

        details.append("\nInterface Addresses:\n");
        for (InterfaceAddress addr : iface.getInterfaceAddresses()) {
            details.append("\t").append(addr.getAddress().toString()).append("\n");
        }

        return details.toString();
    }
}
