import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.List;

public class InterfaceWindow extends JFrame implements ActionListener {
    private JComboBox<String> networkList; // Dropdown for network interfaces
    private JTextArea textInterfaceInfo;  // Area to display interface details
    private NetworkInterfaceInfo backEnd;
    private PacketCapturing packetCapturing;// Backend instance
    private JTable packetList;
    private JTextArea hexdataInfo;
    private JTextArea packetInformation;


    public InterfaceWindow() {
        // Create a panel to hold components
        JPanel panel = new JPanel();
        panel.setLayout(null); // Use null layout for manual positioning
        panel.setBounds(0, 0, 1200, 1000);
        add(panel);

        // Instantiate Backend
        backEnd = new NetworkInterfaceInfo();
        packetCapturing = new PacketCapturing(backEnd);



        // Top JComboBox (Network List)
        JLabel networkLabel = new JLabel("Select Network:");
        networkLabel.setBounds(30, 20, 100, 20); // Positioned on the left
        panel.add(networkLabel);

        networkList = new JComboBox<>(); // Initialize as class-level variable
        networkList.setBounds(150, 20, 300, 20); // Positioned on the left
        panel.add(networkList);

        // Add ActionListener to networkList
        networkList.addActionListener(this); // Register 'this' as the ActionListener

        // Filter Label and Protocol List (Moved to the right)
        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setBounds(500, 20, 50, 20); // Positioned on the right
        panel.add(filterLabel);

        JComboBox<String> protocolList = new JComboBox<>();
        protocolList.addItem("All");
        protocolList.addItem("TCP");
        protocolList.addItem("UDP");
        protocolList.setBounds(560, 20, 150, 20);
        protocolList.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedProtocol = (String) protocolList.getSelectedItem();
                packetCapturing.setProtocolFilter(selectedProtocol);
            }
        });
        panel.add(protocolList);

        // Button
        JButton capture = new JButton("Capture");
        capture.setBounds(720, 20, 100, 20);
        capture.setBackground(Color.BLUE);
        capture.setForeground(Color.WHITE);
        capture.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Get the selected network
                String selectedNetwork = (String) networkList.getSelectedItem();
                if(selectedNetwork == null){
                    return;
                }
                try {
                    PcapNetworkInterface device = backEnd.getDevice(selectedNetwork);
                    if (device != null) {
                        // Start capturing packets
                        packetCapturing.startCapturing(device, packetList);
                        System.out.println("Captured list");
                    } else {
                        JOptionPane.showMessageDialog(InterfaceWindow.this, "No device found.");
                    }
                } catch (NotOpenException ex) {
                    throw new RuntimeException(ex);
                } catch (PcapNativeException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });

        panel.add(capture);

        JButton start = new JButton("Stop");
        start.setBounds(825, 20, 100, 20);
        start.setBackground(Color.RED);
        start.setForeground(Color.WHITE);
        start.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                packetCapturing.stopCapturing();
            }
        });
        panel.add(start);

        JButton save = new JButton("Save");
        save.setBounds(930, 20, 100, 20);
        save.setBackground(Color.GREEN);
        save.setForeground(Color.WHITE);
        save.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (!packetCapturing.isCapturing()) {  // Use the new method
                        JOptionPane.showMessageDialog(InterfaceWindow.this,
                            "Please start capturing packets first",
                            "No Capture Active",
                            JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    
                    packetCapturing.saveCapture();
                    JOptionPane.showMessageDialog(InterfaceWindow.this, 
                        "Packets saved to out.pcap file", 
                        "Save Successful", 
                        JOptionPane.INFORMATION_MESSAGE);
                } catch (NotOpenException ex) {
                    JOptionPane.showMessageDialog(InterfaceWindow.this,
                        ex.getMessage(),
                        "Save Error",
                        JOptionPane.ERROR_MESSAGE);
                } catch (PcapNativeException ex) {
                    JOptionPane.showMessageDialog(InterfaceWindow.this,
                        "Error accessing network interface: " + ex.getMessage(),
                        "Save Error",
                        JOptionPane.ERROR_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(InterfaceWindow.this,
                        "Unexpected error while saving: " + ex.getMessage(),
                        "Save Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        panel.add(save);

        // JTable
        String[] columns = {"No.", "Length", "Source", "Destination", "Protocol"};
        DefaultTableModel model = new DefaultTableModel(columns, 0);
        packetList = new JTable(model);
        packetList.setBounds(30, 50, 1030, 400);
        
        // Add selection listener to the table
        packetList.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {  // Only react to the final event
                int selectedRow = packetList.getSelectedRow();
                if (selectedRow >= 0) {
                    Packet packet = packetCapturing.getPacket(selectedRow);
                    if (packet != null) {
                        // Update both hex and packet information
                        hexdataInfo.setText(byteArrayToHex(packet.getRawData()));
                        packetInformation.setText(packetCapturing.getPacketDetails(packet));
                    }
                }
            }
        });
        
        JScrollPane scroll = new JScrollPane(packetList);
        scroll.setBounds(30, 60, 1030, 400);
        panel.add(scroll);


        // Text areas
        JLabel interfaceInfo = new JLabel("Interface Info");
        interfaceInfo.setFont(interfaceInfo.getFont().deriveFont(Font.BOLD, 14f));
        interfaceInfo.setBounds(55, 470, 100, 30);
        panel.add(interfaceInfo);

        textInterfaceInfo = new JTextArea(); // Class-level variable
        textInterfaceInfo.setBounds(50, 500, 300, 250);
        textInterfaceInfo.setEditable(false);
        JScrollPane textScroll = new JScrollPane(textInterfaceInfo);
        textScroll.setBounds(50, 500, 300, 250);
        panel.add(textScroll);
//        panel.add(textInterfaceInfo);

        JLabel packetInfo = new JLabel("Packet Information");
        packetInfo.setFont(packetInfo.getFont().deriveFont(Font.BOLD, 14f));
        packetInfo.setBounds(405, 470, 150, 30);
        panel.add(packetInfo);

        packetInformation = new JTextArea();
        packetInformation.setEditable(false);
        JScrollPane packetScroll = new JScrollPane(packetInformation);
        packetScroll.setBounds(400, 500, 300, 250);
        panel.add(packetScroll);


        JLabel hexData = new JLabel("Hex Data");
        hexData.setFont(hexData.getFont().deriveFont(Font.BOLD, 14f));
        hexData.setBounds(755, 470, 100, 30);
        panel.add(hexData);

        hexdataInfo = new JTextArea();
        hexdataInfo.setBounds(750, 500, 300, 250);
        hexdataInfo.setEditable(false);
        JScrollPane hexScroll = new JScrollPane(hexdataInfo);
        hexScroll.setBounds(750, 500, 300, 250);
        panel.add(hexScroll);

        // Frame settings
        setSize(1200, 800); // Adjusted to match content
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(null);
        setVisible(true);

        // Populate Network List from Backend
        populateNetworkList();
    }

    private void populateNetworkList() {
        try {
            // Use Backend to fetch network interfaces
            List<String> interfaces = backEnd.getNetworkInterfaces();
            for (String iface : interfaces) {
                networkList.addItem(iface); // Add each interface to the dropdown
            }
        } catch (SocketException | PcapNativeException ex) {
            JOptionPane.showMessageDialog(this, "Error fetching network interfaces: " + ex.getMessage());
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == networkList) {
            String selectedNetwork = (String) networkList.getSelectedItem();
            try {
                backEnd.setSelectedInterface(selectedNetwork);
                String details = backEnd.getInterfaceDetails(selectedNetwork);
                textInterfaceInfo.setText(details);
            } catch (SocketException | PcapNativeException ex) {
                JOptionPane.showMessageDialog(this, "Error fetching interface details: " + ex.getMessage());
            }
        }
    }

    private String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i % 2 == 1) sb.append(" ");  // Space between every 2 bytes
            if (i % 16 == 15) sb.append("\n");  // New line every 16 bytes
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        new InterfaceWindow();
    }
}