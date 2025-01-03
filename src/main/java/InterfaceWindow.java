import javax.swing.*;
import java.awt.*;

public class InterfaceWindow extends JFrame {
    public InterfaceWindow() {
        // Create a panel to hold components
        JPanel panel = new JPanel();
        panel.setLayout(null); // Use null layout for manual positioning
        panel.setBounds(0, 0, 1200, 1000);
        add(panel);

        // Top JComboBox (Network List)
        JLabel networkLabel = new JLabel("Select Network:");
        networkLabel.setBounds(30, 20, 100, 20); // Positioned on the left
        panel.add(networkLabel);

        JComboBox<String> networkList = new JComboBox<>();
        networkList.setBounds(150, 20, 300, 20); // Positioned on the left
        panel.add(networkList);

        // Filter Label and Protocol List (Moved to the right)
        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setBounds(500, 20, 50, 20); // Positioned on the right
        panel.add(filterLabel);


        JComboBox<String> protocolList = new JComboBox<>();
        protocolList.addItem("TCP");
        protocolList.addItem("UDP");

        protocolList.setBounds(560, 20, 150, 20); // Positioned to the right of the filter label
        panel.add(protocolList);

        //Button
        JButton capture = new JButton();
        capture.setText("Capture");
        capture.setBounds(720, 20, 100, 20);
        capture.setBackground(Color.BLUE);
        capture.setForeground(Color.WHITE);
        panel.add(capture);

        JButton start = new JButton();
        start.setText("Start");
        start.setBounds(825, 20, 100, 20);
        start.setBackground(Color.green);
        start.setForeground(Color.WHITE);
        panel.add(start);

        JButton stop = new JButton();
        stop.setText("Stop");
        stop.setBounds(930, 20, 100, 20);
        stop.setBackground(Color.red);
        stop.setForeground(Color.WHITE);
        panel.add(stop);

        //JTable
        String[][] row = {};
        String[] columns = {"No.", "Length", "Source", "Destination", "Protocol"};
        JTable packetlList = new JTable(row, columns);
        packetlList.setBounds(30, 50, 1030, 400);
        JScrollPane scroll = new JScrollPane(packetlList);
        scroll.setBounds(30,60,1030,400);
        panel.add(scroll);

        //Text areas
        JLabel interfaceInfo = new JLabel("Interface Info");
        interfaceInfo.setFont(interfaceInfo.getFont().deriveFont(Font.BOLD, 14f));
        interfaceInfo.setBounds(55, 470, 100, 30);
        panel.add(interfaceInfo);

        JTextArea textInterfaceInfo = new JTextArea();
        textInterfaceInfo.setBounds(50, 500, 300, 250);
        textInterfaceInfo.setEditable(false);
        textInterfaceInfo.setText("");
        panel.add(textInterfaceInfo);

        JLabel packetInfo = new JLabel("Packet Information");
        packetInfo.setFont(packetInfo.getFont().deriveFont(Font.BOLD, 14f));
        packetInfo.setBounds(405, 470, 150, 30);
        panel.add(packetInfo);

        JTextArea packetInformation = new JTextArea();
        packetInformation.setBounds(400, 500, 300, 250);
        packetInformation.setEditable(false);
        packetInformation.setText("");
        panel.add(packetInformation);

        JLabel hexData = new JLabel("Hex Data");
        hexData.setFont(hexData.getFont().deriveFont(Font.BOLD, 14f));
        hexData.setBounds(755, 470, 100, 30);
        panel.add(hexData);

        JTextArea hexdataInfo = new JTextArea();
        hexdataInfo.setBounds(750, 500, 300, 250);
        hexdataInfo.setEditable(false);
        hexdataInfo.setText("");
        JScrollPane hexScroll = new JScrollPane(hexdataInfo);
        hexScroll.setBounds(750, 500, 300, 250);
        panel.add(hexScroll);



        // Frame settings
        setSize(800, 400); // Increased width to accommodate right-side placement
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(null);
        setVisible(true);
    }

    public static void main(String[] args) {
        new InterfaceWindow();
    }
}