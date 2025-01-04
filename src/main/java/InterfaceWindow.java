import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.SocketException;
import java.util.List;

public class InterfaceWindow extends JFrame implements ActionListener {
    private JComboBox<String> networkList; // Dropdown for network interfaces
    private JTextArea textInterfaceInfo;  // Area to display interface details
    private NetworkInterfaceInfo backEnd;              // Backend instance

    public InterfaceWindow() {
        // Create a panel to hold components
        JPanel panel = new JPanel();
        panel.setLayout(null); // Use null layout for manual positioning
        panel.setBounds(0, 0, 1200, 1000);
        add(panel);

        // Instantiate Backend
        backEnd = new NetworkInterfaceInfo();

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
        protocolList.addItem("TCP");
        protocolList.addItem("UDP");
        protocolList.setBounds(560, 20, 150, 20); // Positioned to the right of the filter label
        panel.add(protocolList);

        // Button
        JButton capture = new JButton("Capture");
        capture.setBounds(720, 20, 100, 20);
        capture.setBackground(Color.BLUE);
        capture.setForeground(Color.WHITE);
        panel.add(capture);

        JButton start = new JButton("Start");
        start.setBounds(825, 20, 100, 20);
        start.setBackground(Color.GREEN);
        start.setForeground(Color.WHITE);
        panel.add(start);

        JButton stop = new JButton("Stop");
        stop.setBounds(930, 20, 100, 20);
        stop.setBackground(Color.RED);
        stop.setForeground(Color.WHITE);
        panel.add(stop);

        // JTable
        String[][] row = {};
        String[] columns = {"No.", "Length", "Source", "Destination", "Protocol"};
        JTable packetList = new JTable(row, columns);
        packetList.setBounds(30, 50, 1030, 400);
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

        JTextArea packetInformation = new JTextArea();
        packetInformation.setBounds(400, 500, 300, 250);
        packetInformation.setEditable(false);
        JScrollPane packetScroll = new JScrollPane(packetInformation);
        packetScroll.setBounds(400, 500, 300, 250);
        panel.add(packetScroll);


        JLabel hexData = new JLabel("Hex Data");
        hexData.setFont(hexData.getFont().deriveFont(Font.BOLD, 14f));
        hexData.setBounds(755, 470, 100, 30);
        panel.add(hexData);

        JTextArea hexdataInfo = new JTextArea();
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
        } catch (SocketException ex) {
            JOptionPane.showMessageDialog(this, "Error fetching network interfaces: " + ex.getMessage());
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == networkList) { // Check if event is from networkList
            String selectedNetwork = (String) networkList.getSelectedItem();
            try {
                // Fetch details from backend
                String details = backEnd.getInterfaceDetails(selectedNetwork);
                textInterfaceInfo.setText(details); // Update Interface Info
            } catch (SocketException ex) {
                JOptionPane.showMessageDialog(this, "Error fetching interface details: " + ex.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        new InterfaceWindow();
    }
}