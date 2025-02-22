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
    private JTextArea interfaceInfo;  // Add this field
    private JTextField filterTextField;  // Add this field
    private JPanel panel;  // Add this field

    public InterfaceWindow() {
        super("Network Packet Analyzer");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1300, 800);  // Adjusted height
        setLocationRelativeTo(null);

        panel = new JPanel();
        panel.setLayout(null);
        
        // Network Interface Selection
        JLabel networkLabel = new JLabel("Select Network:");
        networkLabel.setBounds(10, 20, 100, 20);
        panel.add(networkLabel);

        networkList = new JComboBox<>();
        networkList.setBounds(110, 20, 250, 20);
        panel.add(networkList);

        // Protocol Filter
        JLabel protocolFilterLabel = new JLabel("Protocol Filter:");
        protocolFilterLabel.setBounds(370, 20, 100, 20);
        panel.add(protocolFilterLabel);

        JComboBox<String> protocolList = new JComboBox<>();
        protocolList.addItem("All");
        protocolList.addItem("TCP");
        protocolList.addItem("UDP");
        protocolList.setBounds(470, 20, 100, 20);
        protocolList.addActionListener(e -> {
            String selectedProtocol = (String) protocolList.getSelectedItem();
            packetCapturing.setProtocolFilter(selectedProtocol);
        });
        panel.add(protocolList);

        // BPF Filter
        JLabel bpfFilterLabel = new JLabel("BPF Filter:");
        bpfFilterLabel.setBounds(580, 20, 70, 20);
        panel.add(bpfFilterLabel);

        filterTextField = new JTextField();
        filterTextField.setBounds(650, 20, 150, 20);
        filterTextField.setToolTipText("Enter BPF filter (e.g., 'tcp port 80' or 'host 192.168.1.1')");
        panel.add(filterTextField);

        // Help button
        JButton helpButton = new JButton("?");
        helpButton.setBounds(805, 20, 45, 20);
        helpButton.addActionListener(e -> showFilterHelp());
        panel.add(helpButton);

        // Capture button
        JButton capture = new JButton("Capture");
        capture.setBounds(860, 20, 100, 20);
        capture.setBackground(Color.BLUE);
        capture.setForeground(Color.WHITE);
        capture.addActionListener(e -> {
            try {
                String filterExpression = filterTextField.getText().trim();
                PcapNetworkInterface device = backEnd.getDevice(networkList.getSelectedItem().toString());
                if (device != null) {
                    packetCapturing.startCapturing(device, packetList, filterExpression);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                    "Error starting capture: " + ex.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        });
        panel.add(capture);

        // Stop button
        JButton stop = new JButton("Stop");
        stop.setBounds(970, 20, 100, 20);
        stop.setBackground(Color.RED);
        stop.setForeground(Color.WHITE);
        stop.addActionListener(e -> packetCapturing.stopCapturing());
        panel.add(stop);

        // Save button
        JButton save = new JButton("Save");
        save.setBounds(1080, 20, 100, 20);
        save.setBackground(Color.GREEN);
        save.setForeground(Color.WHITE);
        save.addActionListener(e -> {
            try {
                if (!packetCapturing.isCapturing()) {
                    JOptionPane.showMessageDialog(this,
                        "Please start capturing packets first",
                        "No Capture Active",
                        JOptionPane.WARNING_MESSAGE);
                    return;
                }
                
                packetCapturing.saveCapture();
                JOptionPane.showMessageDialog(this, 
                    "Packets saved to out.pcap file", 
                    "Save Successful", 
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                    "Error saving packets: " + ex.getMessage(),
                    "Save Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        });
        panel.add(save);

        // Packet List Table
        String[] columnNames = {"No.", "Length", "Source", "Destination", "Protocol"};
        DefaultTableModel model = new DefaultTableModel(columnNames, 0);
        packetList = new JTable(model);
        JScrollPane scrollPane = new JScrollPane(packetList);
        scrollPane.setBounds(10, 50, 1260, 400);  // Adjusted width
        panel.add(scrollPane);

        // All information panels will start at the same y-coordinate
        int infoStartY = 460;
        int infoPanelHeight = 250;

        // Interface Information (Left)
        JLabel interfaceLabel = new JLabel("Interface Information:");
        interfaceLabel.setBounds(10, infoStartY, 150, 20);
        panel.add(interfaceLabel);

        interfaceInfo = new JTextArea();
        interfaceInfo.setEditable(false);
        JScrollPane interfaceScroll = new JScrollPane(interfaceInfo);
        interfaceScroll.setBounds(10, infoStartY + 20, 400, infoPanelHeight);
        panel.add(interfaceScroll);

        // Packet Information (Middle)
        JLabel packetInfoLabel = new JLabel("Packet Information:");
        packetInfoLabel.setBounds(420, infoStartY, 150, 20);
        panel.add(packetInfoLabel);

        packetInformation = new JTextArea();
        packetInformation.setEditable(false);
        JScrollPane packetScroll = new JScrollPane(packetInformation);
        packetScroll.setBounds(420, infoStartY + 20, 430, infoPanelHeight);
        panel.add(packetScroll);

        // Hex Data (Right)
        JLabel hexLabel = new JLabel("Hex Data:");
        hexLabel.setBounds(860, infoStartY, 100, 20);
        panel.add(hexLabel);

        hexdataInfo = new JTextArea();
        hexdataInfo.setEditable(false);
        JScrollPane hexScroll = new JScrollPane(hexdataInfo);
        hexScroll.setBounds(860, infoStartY + 20, 410, infoPanelHeight);
        panel.add(hexScroll);

        // Table Selection Listener
        packetList.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = packetList.getSelectedRow();
                if (selectedRow >= 0) {
                    Packet packet = packetCapturing.getPacket(selectedRow);
                    if (packet != null) {
                        hexdataInfo.setText(byteArrayToHex(packet.getRawData()));
                        packetInformation.setText(packetCapturing.getPacketDetails(packet));
                    }
                }
            }
        });

        // Network List Selection Listener
        networkList.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedInterface = (String) networkList.getSelectedItem();
                try {
                    PcapNetworkInterface device = backEnd.getDevice(selectedInterface);
                    if (device != null) {
                        StringBuilder info = new StringBuilder();
                        
                        // MAC Address
                        if (!device.getLinkLayerAddresses().isEmpty()) {
                            info.append(String.format("Interface MacAddress --> %s\n", 
                                device.getLinkLayerAddresses().get(0)));
                        }

                        // IP Addresses and Network Information
                        for (PcapAddress addr : device.getAddresses()) {
                            if (addr.getAddress() != null) {
                                // IP Address
                                info.append(String.format("Interface Address --> %s\n", 
                                    addr.getAddress().getHostAddress()));
                                
                                // Subnet Mask
                                if (addr.getNetmask() != null) {
                                    info.append(String.format("Interface Subnet --> %s\n", 
                                        addr.getNetmask().getHostAddress()));
                                }
                                
                                // Broadcast Address
                                if (addr.getBroadcastAddress() != null) {
                                    info.append(String.format("Interface Broadcast --> %s\n", 
                                        addr.getBroadcastAddress().getHostAddress()));
                                }
                            }
                        }

                        // Additional Interface Information
                        info.append(String.format("Interface Description: %s\n", device.getDescription()));
                        info.append(String.format("Interface Type: %s\n", 
                            device.getLinkLayerAddresses().isEmpty() ? "Unknown" : "Ethernet"));
                        info.append(String.format("Loopback: %s\n", device.isLoopBack() ? "Yes" : "No"));
                        info.append(String.format("Up and Running: %s\n", device.isRunning() ? "Yes" : "No"));

                        interfaceInfo.setText(info.toString());
                    }
                } catch (Exception ex) {
                    interfaceInfo.setText("Error getting interface information: " + ex.getMessage());
                }
            }
        });

        add(panel);
        setVisible(true);

        // Instantiate Backend
        backEnd = new NetworkInterfaceInfo();
        packetCapturing = new PacketCapturing(backEnd);

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

    private void showFilterHelp() {
        String helpText = 
            "BPF Filter Examples:\n\n" +
            "- tcp port 80                 (HTTP traffic)\n" +
            "- host 192.168.1.1           (Traffic to/from specific host)\n" +
            "- src host 192.168.1.1       (Traffic from specific host)\n" +
            "- dst port 443               (HTTPS destination traffic)\n" +
            "- tcp or udp                 (TCP or UDP traffic)\n" +
            "- ip proto \\icmp             (ICMP traffic)\n" +
            "- net 192.168.0.0/24         (Traffic in subnet)\n" +
            "- port 53                    (DNS traffic)\n" +
            "- tcp[tcpflags] & tcp-syn != 0   (TCP SYN packets)\n\n" +
            "Operators: and, or, not\n" +
            "You can combine filters using parentheses";

        JTextArea textArea = new JTextArea(helpText);
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(400, 300));

        JOptionPane.showMessageDialog(this,
            scrollPane,
            "BPF Filter Syntax Help",
            JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        new InterfaceWindow();
    }
}