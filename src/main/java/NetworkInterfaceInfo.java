import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

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
        details.append("Description Name: ").append(iface.getDescription()).append("\n");
        details.append("Address Name: ").append(iface.getAddresses()).append("\n");
        details.append("LinklayerAddress Name: ").append(iface.getLinkLayerAddresses()).append("\n");




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
}
