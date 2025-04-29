import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.List;
import java.io.File;

public class
InterfaceWindow extends JFrame implements ActionListener {
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
    
    // Statistics Panel Components
    private JPanel statsPanel;
    private JLabel totalPacketsLabel;
    private JLabel tcpPacketsLabel;
    private JLabel udpPacketsLabel;
    private JLabel httpPacketsLabel;
    private JLabel bandwidthLabel;
    private JLabel activeConnectionsLabel;
    private Timer statsUpdateTimer;
    private int totalPackets = 0;
    private int tcpPackets = 0;
    private int udpPackets = 0;
    private int httpPackets = 0;
    private long lastUpdateTime = System.currentTimeMillis();
    private long totalBytes = 0;

    public InterfaceWindow() {
        super("Network Packet Analyzer");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1300, 800);  // Adjusted height
        setLocationRelativeTo(null);

        panel = new JPanel();
        panel.setLayout(null);

        // Initialize Statistics Panel
        initializeStatsPanel();

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
        JButton capture = new JButton("Start Capture");
        capture.setBounds(860, 20, 120, 25);
        capture.setBackground(new Color(46, 204, 64));  // Green color
        capture.setForeground(Color.WHITE);
        capture.setFocusPainted(false);
        
        // Pause/Resume button
        JButton pauseResume = new JButton("Pause");
        pauseResume.setBounds(990, 20, 100, 25);
        pauseResume.setBackground(new Color(255, 133, 27));  // Orange color
        pauseResume.setForeground(Color.WHITE);
        pauseResume.setEnabled(false);
        pauseResume.setFocusPainted(false);

        // Clear button
        JButton clear = new JButton("Clear");
        clear.setBounds(1100, 20, 80, 25);
        clear.setBackground(new Color(255, 65, 54));  // Red color
        clear.setForeground(Color.WHITE);
        clear.setFocusPainted(false);

        // Save button
        JButton save = new JButton("Save");
        save.setBounds(1100, 20, 80, 25);
        save.setBackground(new Color(0, 116, 217));  // Blue color
        save.setForeground(Color.WHITE);
        save.setFocusPainted(false);

        // Add Graph Visualization button
        JButton graphButton = new JButton("Show Traffic Graph");
        graphButton.setBounds(1190, 20, 150, 25);  // Adjusted width and position
        graphButton.setBackground(new Color(147, 112, 219)); // Purple color
        graphButton.setForeground(Color.WHITE);
        graphButton.setFocusPainted(false);
        graphButton.addActionListener(e -> packetCapturing.showGraphVisualization());

        // Add action listeners
        capture.addActionListener(e -> {
            try {
                if (!packetCapturing.isCapturing()) {
                    // Start capture
                    String filterExpression = filterTextField.getText().trim();
                    PcapNetworkInterface device = backEnd.getDevice(networkList.getSelectedItem().toString());
                    if (device != null) {
                        packetCapturing.startCapturing(device, packetList, filterExpression);
                        capture.setText("Stop Capture");
                        capture.setBackground(new Color(255, 65, 54));  // Red color
                        pauseResume.setEnabled(true);
                        clear.setEnabled(false);
                    }
                } else {
                    // Stop capture
                    packetCapturing.stopCapturing();
                    capture.setText("Start Capture");
                    capture.setBackground(new Color(46, 204, 64));  // Green color
                    pauseResume.setText("Pause");
                    pauseResume.setEnabled(false);
                    clear.setEnabled(true);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error: " + ex.getMessage(),
                        "Capture Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        pauseResume.addActionListener(e -> {
            if (packetCapturing.isCapturing()) {
                if (pauseResume.getText().equals("Pause")) {
                    packetCapturing.pauseCapturing();
                    pauseResume.setText("Resume");
                    pauseResume.setBackground(new Color(46, 204, 64)); // Green for resume
                    capture.setEnabled(false);
                } else {
                    packetCapturing.resumeCapturing();
                    pauseResume.setText("Pause");
                    pauseResume.setBackground(new Color(255, 133, 27)); // Back to orange for pause
                    capture.setEnabled(true);
                }
            }
        });

        clear.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(this,
                    "Are you sure you want to clear all captured data?",
                    "Clear Confirmation",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                // Clear the packet list
                DefaultTableModel model = (DefaultTableModel) packetList.getModel();
                model.setRowCount(0);
                
                // Reset statistics
                totalPackets = 0;
                tcpPackets = 0;
                udpPackets = 0;
                httpPackets = 0;
                totalBytes = 0;
                updateStatistics();
                
                // Clear packet information and hex data
                packetInformation.setText("");
                hexdataInfo.setText("");
                
                // Reset graph if visible
                packetCapturing.clearCapture();
            }
        });

        save.addActionListener(e -> {
            try {
                if (packetCapturing.hasCapturedPackets()) {
                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setDialogTitle("Save Capture File");
                    fileChooser.setSelectedFile(new File("capture.pcap"));
                    
                    if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        packetCapturing.saveCapture(file.getAbsolutePath());
                        JOptionPane.showMessageDialog(this,
                                "Capture saved successfully to: " + file.getAbsolutePath(),
                                "Save Successful",
                                JOptionPane.INFORMATION_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(this,
                            "No packets captured yet",
                            "Save Error",
                            JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error saving capture: " + ex.getMessage(),
                        "Save Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        panel.add(capture);
        panel.add(pauseResume);
        panel.add(clear);
        panel.add(save);
        panel.add(graphButton);

        // Packet List Table
        String[] columnNames = {"No.", "Source", "Destination", "Protocol", "Length"};
        DefaultTableModel model = new DefaultTableModel(columnNames, 0);
        packetList = new JTable(model);
        JScrollPane scrollPane = new JScrollPane(packetList);
        scrollPane.setBounds(10, 50, 950, 400);  // Reduced width to make room for stats panel
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
        interfaceScroll.setBounds(10, infoStartY + 20, 300, infoPanelHeight);
        panel.add(interfaceScroll);

        // Packet Information (Middle)
        JLabel packetInfoLabel = new JLabel("Packet Information:");
        packetInfoLabel.setBounds(320, infoStartY, 150, 20);
        panel.add(packetInfoLabel);

        packetInformation = new JTextArea();
        packetInformation.setEditable(false);
        JScrollPane packetScroll = new JScrollPane(packetInformation);
        packetScroll.setBounds(320, infoStartY + 20, 320, infoPanelHeight);
        panel.add(packetScroll);

        // Hex Data (Right)
        JLabel hexLabel = new JLabel("Hex Data:");
        hexLabel.setBounds(650, infoStartY, 100, 20);
        panel.add(hexLabel);

        hexdataInfo = new JTextArea();
        hexdataInfo.setEditable(false);
        JScrollPane hexScroll = new JScrollPane(hexdataInfo);
        hexScroll.setBounds(650, infoStartY + 20, 300, infoPanelHeight);
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
        packetCapturing = new PacketCapturing(backEnd, this);  // Pass 'this' reference

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

    private void initializeStatsPanel() {
        statsPanel = new JPanel();
        statsPanel.setLayout(new GridLayout(6, 1, 5, 5));
        statsPanel.setBorder(BorderFactory.createTitledBorder("Statistics"));
        
        // Position the stats panel on the far right, spanning the full height
        statsPanel.setBounds(970, 50, 300, 660);  // Full height from below controls to bottom
        statsPanel.setBackground(new Color(245, 245, 245));  // Light gray background
        
        // Initialize labels with default values
        totalPacketsLabel = new JLabel("Total Packets: 0");
        tcpPacketsLabel = new JLabel("TCP Packets: 0");
        udpPacketsLabel = new JLabel("UDP Packets: 0");
        httpPacketsLabel = new JLabel("HTTP Packets: 0");
        bandwidthLabel = new JLabel("Bandwidth: 0.00 KB/s");
        activeConnectionsLabel = new JLabel("Active Connections: 0");
        
        // Style the labels
        Font labelFont = new Font("Arial", Font.BOLD, 12);
        Color labelColor = new Color(50, 50, 50);  // Dark gray text
        
        JLabel[] labels = {totalPacketsLabel, tcpPacketsLabel, udpPacketsLabel, 
                          httpPacketsLabel, bandwidthLabel, activeConnectionsLabel};
        
        for (JLabel label : labels) {
            label.setFont(labelFont);
            label.setForeground(labelColor);
            label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(200, 200, 200)),  // Bottom border
                BorderFactory.createEmptyBorder(10, 10, 10, 10)  // Padding
            ));
            label.setOpaque(true);
            label.setBackground(new Color(250, 250, 250));  // Slightly lighter than panel
        }
        
        // Create a panel for each statistic with a title
        for (JLabel label : labels) {
            JPanel statPanel = new JPanel(new BorderLayout());
            statPanel.setBackground(label.getBackground());
            statPanel.add(label, BorderLayout.CENTER);
            statsPanel.add(statPanel);
        }
        
        // Add stats panel to main panel
        panel.add(statsPanel);
        
        // Initialize timer for updating statistics
        statsUpdateTimer = new Timer(1000, e -> updateStatistics());
        statsUpdateTimer.start();
    }
    
    private void updateStatistics() {
        SwingUtilities.invokeLater(() -> {
            // Update bandwidth calculation
            long currentTime = System.currentTimeMillis();
            long timeDiff = currentTime - lastUpdateTime;
            if (timeDiff > 0) {
                double bandwidth = (totalBytes * 1000.0) / (timeDiff * 1024.0); // Convert to KB/s
                bandwidthLabel.setText(String.format("Bandwidth: %.2f KB/s", bandwidth));
                totalBytes = 0; // Reset for next interval
                lastUpdateTime = currentTime;
            }
            
            // Update packet counts with animations
            updateLabelWithAnimation(totalPacketsLabel, "Total Packets: " + totalPackets);
            updateLabelWithAnimation(tcpPacketsLabel, "TCP Packets: " + tcpPackets);
            updateLabelWithAnimation(udpPacketsLabel, "UDP Packets: " + udpPackets);
            updateLabelWithAnimation(httpPacketsLabel, "HTTP Packets: " + httpPackets);
            updateLabelWithAnimation(activeConnectionsLabel, "Active Connections: " + calculateActiveConnections());
        });
    }
    
    private void updateLabelWithAnimation(JLabel label, String newText) {
        if (!label.getText().equals(newText)) {
            label.setForeground(new Color(0, 150, 0));  // Green color for updates
            label.setText(newText);
            
            // Reset color after a short delay
            Timer timer = new Timer(500, e -> {
                label.setForeground(new Color(50, 50, 50));  // Back to dark gray
                ((Timer) e.getSource()).stop();
            });
            timer.setRepeats(false);
            timer.start();
        }
    }
    
    private int calculateActiveConnections() {
        // This is a placeholder - you would need to implement actual connection tracking
        return tcpPackets + udpPackets;
    }
    
    public void updatePacketStats(Packet packet) {
        SwingUtilities.invokeLater(() -> {
            totalPackets++;
            totalBytes += packet.length();
            
            // Determine packet type and update counters
            if (packet.contains(org.pcap4j.packet.TcpPacket.class)) {
                tcpPackets++;
            } else if (packet.contains(org.pcap4j.packet.UdpPacket.class)) {
                udpPackets++;
            }
            
            // Check for HTTP packets
            if (HttpPacketParser.isHttpPacket(packet)) {
                httpPackets++;
            }
        });
    }

    public static void main(String[] args) {
        new InterfaceWindow();
    }
}