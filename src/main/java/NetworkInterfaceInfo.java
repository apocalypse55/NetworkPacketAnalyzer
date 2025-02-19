import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapAddress;

import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class NetworkInterfaceInfo {
    private String selectedInterface;
    private List<InetAddress> interfaceAddresses;

    public NetworkInterfaceInfo() {
        interfaceAddresses = new ArrayList<>();
    }

    // Method to fetch all active network interfaces
    public List<String> getNetworkInterfaces() throws SocketException, PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
//        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        List<String> interfaceNames = new ArrayList<>();
        for (int i = 0; i < devices.size(); i++) {
            PcapNetworkInterface iface = devices.get(i);
            if (iface.isUp()) {
                interfaceNames.add(iface.getDescription());
            }
        }
//        while (devices.hasMoreElements()) {
//            NetworkInterface iface = interfaces.nextElement();
//            if (iface.isUp()) {
//                interfaceNames.add(iface.getName());
//            }
//        }
        return interfaceNames;
    }

    // Method to fetch detailed information about a specific interface
    public String getInterfaceDetails(String interfaceName) throws SocketException, PcapNativeException {
        PcapNetworkInterface iface = getDevice(interfaceName);
        if (iface == null) {
            return "Interface not found.";
        }

        StringBuilder details = new StringBuilder();
        details.append("Interface Name: ").append(iface.getName()).append("\n");
        details.append("Description: ").append(iface.getDescription()).append("\n\n");
        
        details.append("IPv4 Addresses:\n");
        details.append("---------------\n");
        for (PcapAddress addr : iface.getAddresses()) {
            if (addr.getAddress().getHostAddress().contains(":")) continue; // Skip IPv6
            details.append("Address: ").append(addr.getAddress().getHostAddress()).append("\n");
            details.append("Netmask: ").append(addr.getNetmask().getHostAddress()).append("\n");
            if (addr.getBroadcastAddress() != null) {
                details.append("Broadcast: ").append(addr.getBroadcastAddress().getHostAddress()).append("\n");
            }
            details.append("\n");
        }

        details.append("IPv6 Addresses:\n");
        details.append("---------------\n");
        for (PcapAddress addr : iface.getAddresses()) {
            if (!addr.getAddress().getHostAddress().contains(":")) continue; // Skip IPv4
            details.append("Address: ").append(addr.getAddress().getHostAddress()).append("\n");
            details.append("Netmask: ").append(addr.getNetmask().getHostAddress()).append("\n");
            if (addr.getBroadcastAddress() != null) {
                details.append("Broadcast: ").append(addr.getBroadcastAddress().getHostAddress()).append("\n");
            }
            details.append("\n");
        }

        details.append("MAC Address: ");
        ArrayList<LinkLayerAddress> macAddresses = iface.getLinkLayerAddresses();
        if (!macAddresses.isEmpty()) {
            details.append(macAddresses.get(0).toString());
        }

        return details.toString();
    }

    public PcapNetworkInterface getDevice(String name) throws PcapNativeException {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

        for (int i = 0; i < devices.size(); i++) {
            PcapNetworkInterface iface = devices.get(i);
            if (iface.getDescription().equals(name)){
                System.out.println(name);
                return iface;

            }
        }
        return null;
    }

    public void setSelectedInterface(String interfaceName) {
        this.selectedInterface = interfaceName;
    }

    public String getSelectedInterface() {
        return selectedInterface;
    }

    // Add this method to get interface addresses
    public List<InetAddress> getInterfaceAddresses() {
        List<InetAddress> addresses = new ArrayList<>();
        try {
            PcapNetworkInterface device = getDevice(selectedInterface);
            if (device != null) {
                for (PcapAddress addr : device.getAddresses()) {
                    if (addr.getAddress() != null) {
                        addresses.add(addr.getAddress());
                    }
                }
            }
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
        return addresses;
    }
}
