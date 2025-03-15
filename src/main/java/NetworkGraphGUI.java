import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Path2D;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import org.pcap4j.packet.Packet;

public class NetworkGraphGUI extends JFrame {
    private final List<Integer> packetCounts;
    private final List<String> timeLabels;
    private final List<PacketInfo> packetInfoList;  // Store packet information
    private int MAX_POINTS = 30;  // Default to 30 seconds
    private final javax.swing.Timer updateTimer;
    private int currentPacketCount = 0;
    private final JPanel graphPanel;
    private final JLabel statsLabel;
    private int totalPackets = 0;
    private static final int UPDATE_INTERVAL = 1000;
    private Point mousePosition = null;
    private final Color LOW_TRAFFIC = new Color(46, 204, 113);     // Green
    private final Color MEDIUM_TRAFFIC = new Color(241, 196, 15);  // Yellow
    private final Color HIGH_TRAFFIC = new Color(231, 76, 60);     // Red
    private final int TRAFFIC_THRESHOLD_MEDIUM = 100;  // packets/sec
    private final int TRAFFIC_THRESHOLD_HIGH = 500;    // packets/sec
    private PacketCapturing packetCapturing;  // Reference to PacketCapturing
    private JButton captureButton;  // Add this field
    private boolean isPaused = false;  // Add this field
    private List<Integer> pausedPacketCounts;  // Add this field
    private List<String> pausedTimeLabels;     // Add this field
    private List<PacketInfo> pausedPacketInfoList;  // Add this field

    // Inner class to store packet information
    private static class PacketInfo {
        int count;
        Map<String, Integer> protocolCounts;
        Map<String, Integer> sourceCounts;
        Map<String, Integer> destCounts;

        PacketInfo() {
            count = 0;
            protocolCounts = new HashMap<>();
            sourceCounts = new HashMap<>();
            destCounts = new HashMap<>();
        }
    }

    public NetworkGraphGUI(PacketCapturing packetCapturing) {
        super("Network Traffic Flow Analysis");
        this.packetCapturing = packetCapturing;
        packetCounts = new ArrayList<>();
        timeLabels = new ArrayList<>();
        packetInfoList = new ArrayList<>();
        pausedPacketCounts = new ArrayList<>();
        pausedTimeLabels = new ArrayList<>();
        pausedPacketInfoList = new ArrayList<>();
        
        setSize(1000, 700);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        // Create main panel with mouse listener for tooltips
        graphPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                drawGraph(g);
            }
        };
        graphPanel.setBackground(Color.WHITE);
        
        // Add mouse motion listener for tooltips
        graphPanel.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                mousePosition = e.getPoint();
                graphPanel.repaint();
            }
        });
        
        // Create control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        // Time range selector
        String[] timeRanges = {"10 sec", "30 sec", "1 min", "2 min", "5 min"};
        JComboBox<String> timeRangeCombo = new JComboBox<>(timeRanges);
        timeRangeCombo.setSelectedIndex(1);
        timeRangeCombo.addActionListener(e -> {
            String selected = (String)timeRangeCombo.getSelectedItem();
            switch(selected) {
                case "10 sec": MAX_POINTS = 10; break;
                case "30 sec": MAX_POINTS = 30; break;
                case "1 min": MAX_POINTS = 60; break;
                case "2 min": MAX_POINTS = 120; break;
                case "5 min": MAX_POINTS = 300; break;
            }
        });
        
        // Toggle Capture button
        captureButton = new JButton("Stop Capture");
        captureButton.setBackground(Color.RED);
        captureButton.setForeground(Color.WHITE);
        captureButton.addActionListener(e -> toggleCapture());

        controlPanel.add(new JLabel("Time Range: "));
        controlPanel.add(timeRangeCombo);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(captureButton);

        // Create statistics panel
        JPanel statsPanel = new JPanel(new BorderLayout());
        statsLabel = new JLabel("Total Packets: 0 | Current Rate: 0 packets/sec | Average Rate: 0 packets/sec");
        statsLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        statsPanel.add(statsLabel, BorderLayout.WEST);

        // Layout
        setLayout(new BorderLayout());
        add(controlPanel, BorderLayout.NORTH);
        add(graphPanel, BorderLayout.CENTER);
        add(statsPanel, BorderLayout.SOUTH);

        // Initialize timer
        updateTimer = new javax.swing.Timer(UPDATE_INTERVAL, e -> updateGraph());
        updateTimer.start();
    }

    private void drawGraph(Graphics g) {
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int width = graphPanel.getWidth();
        int height = graphPanel.getHeight();
        int padding = 60;
        
        // Draw title
        g2.setFont(new Font("Arial", Font.BOLD, 16));
        g2.setColor(Color.BLACK);
        g2.drawString("Network Traffic Flow Analysis", width/2 - 100, 25);

        // Draw axes
        g2.setColor(Color.BLACK);
        g2.drawLine(padding, height - padding, width - padding, height - padding); // X-axis
        g2.drawLine(padding, height - padding, padding, padding); // Y-axis

        // Draw axis labels
        g2.setFont(new Font("Arial", Font.PLAIN, 12));
        g2.drawString("Time", width/2 - 20, height - 10);
        g2.rotate(-Math.PI/2);
        g2.drawString("Packets per Second", -height/2 + 50, 20);
        g2.rotate(Math.PI/2);

        if (packetCounts.isEmpty()) return;

        // Find max value for scaling
        int maxCount = Collections.max(packetCounts);
        maxCount = Math.max(maxCount, TRAFFIC_THRESHOLD_MEDIUM); // Ensure scale shows at least medium traffic threshold

        // Draw grid lines and labels
        g2.setColor(Color.LIGHT_GRAY);
        int gridLines = 10;
        for (int i = 0; i <= gridLines; i++) {
            int y = height - padding - (i * (height - 2 * padding) / gridLines);
            g2.drawLine(padding, y, width - padding, y);
            g2.setColor(Color.BLACK);
            g2.drawString(String.valueOf(i * maxCount / gridLines), padding - 40, y + 5);
            g2.setColor(Color.LIGHT_GRAY);
        }

        // Draw time labels
        g2.setColor(Color.BLACK);
        int xStep = (width - 2 * padding) / (Math.max(1, timeLabels.size() - 1));
        for (int i = 0; i < timeLabels.size(); i++) {
            int x = padding + i * xStep;
            if (i % 2 == 0) { // Show every other label to prevent overcrowding
                g2.drawString(timeLabels.get(i), x - 25, height - padding + 20);
            }
        }

        // Draw the traffic thresholds
        drawTrafficThresholds(g2, width, height, padding, maxCount);

        // Draw the line graph with color gradients
        drawTrafficLine(g2, width, height, padding, maxCount, xStep);

        // Draw legend
        drawLegend(g2, width);

        // Draw tooltip if mouse is over a data point
        if (mousePosition != null) {
            drawTooltip(g2, xStep, height, padding, maxCount);
        }
    }

    private void drawTrafficThresholds(Graphics2D g2, int width, int height, int padding, int maxCount) {
        // Draw threshold lines
        float[] dash = {5f};
        g2.setStroke(new BasicStroke(1f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10.0f, dash, 0.0f));
        
        // Medium traffic threshold
        int y = height - padding - (TRAFFIC_THRESHOLD_MEDIUM * (height - 2 * padding) / maxCount);
        g2.setColor(MEDIUM_TRAFFIC);
        g2.drawLine(padding, y, width - padding, y);
        
        // High traffic threshold
        y = height - padding - (TRAFFIC_THRESHOLD_HIGH * (height - 2 * padding) / maxCount);
        g2.setColor(HIGH_TRAFFIC);
        g2.drawLine(padding, y, width - padding, y);
        
        g2.setStroke(new BasicStroke(1f)); // Reset stroke
    }

    private void drawTrafficLine(Graphics2D g2, int width, int height, int padding, int maxCount, int xStep) {
        Path2D.Float path = new Path2D.Float();
        boolean first = true;

        for (int i = 0; i < packetCounts.size(); i++) {
            int x = padding + i * xStep;
            int y = height - padding - (packetCounts.get(i) * (height - 2 * padding) / maxCount);
            
            if (first) {
                path.moveTo(x, y);
                first = false;
            } else {
                path.lineTo(x, y);
            }

            // Draw points with color based on traffic level
            int count = packetCounts.get(i);
            if (count >= TRAFFIC_THRESHOLD_HIGH) {
                g2.setColor(HIGH_TRAFFIC);
            } else if (count >= TRAFFIC_THRESHOLD_MEDIUM) {
                g2.setColor(MEDIUM_TRAFFIC);
            } else {
                g2.setColor(LOW_TRAFFIC);
            }
            g2.fillOval(x - 4, y - 4, 8, 8);
        }

        // Draw lines with gradient color
        g2.setStroke(new BasicStroke(2f));
        g2.draw(path);
    }

    private void drawLegend(Graphics2D g2, int width) {
        int legendX = width - 150;
        int legendY = 50;
        int boxSize = 15;
        
        g2.setFont(new Font("Arial", Font.PLAIN, 12));
        
        // Low traffic
        g2.setColor(LOW_TRAFFIC);
        g2.fillRect(legendX, legendY, boxSize, boxSize);
        g2.setColor(Color.BLACK);
        g2.drawString("Low Traffic", legendX + boxSize + 5, legendY + 12);
        
        // Medium traffic
        g2.setColor(MEDIUM_TRAFFIC);
        g2.fillRect(legendX, legendY + 20, boxSize, boxSize);
        g2.setColor(Color.BLACK);
        g2.drawString("Medium Traffic", legendX + boxSize + 5, legendY + 32);
        
        // High traffic
        g2.setColor(HIGH_TRAFFIC);
        g2.fillRect(legendX, legendY + 40, boxSize, boxSize);
        g2.setColor(Color.BLACK);
        g2.drawString("High Traffic", legendX + boxSize + 5, legendY + 52);
    }

    private void drawTooltip(Graphics2D g2, int xStep, int height, int padding, int maxCount) {
        for (int i = 0; i < packetCounts.size(); i++) {
            int x = padding + i * xStep;
            int y = height - padding - (packetCounts.get(i) * (height - 2 * padding) / maxCount);
            
            // Check if mouse is near this point
            if (mousePosition.distance(x, y) < 10 && i < packetInfoList.size()) {
                PacketInfo info = packetInfoList.get(i);
                
                // Create detailed tooltip text
                StringBuilder tooltip = new StringBuilder();
                tooltip.append(String.format("Time: %s%n", timeLabels.get(i)));
                tooltip.append(String.format("Total Packets: %d/sec%n%n", packetCounts.get(i)));
                
                // Protocol distribution
                tooltip.append("Protocols:%n");
                info.protocolCounts.entrySet().stream()
                    .sorted((e1, e2) -> e2.getValue().compareTo(e1.getValue()))
                    .limit(3)  // Show top 3 protocols
                    .forEach(e -> tooltip.append(String.format("  %s: %d%n", e.getKey(), e.getValue())));
                
                tooltip.append("%nTop Sources:%n");
                info.sourceCounts.entrySet().stream()
                    .sorted((e1, e2) -> e2.getValue().compareTo(e1.getValue()))
                    .limit(2)  // Show top 2 sources
                    .forEach(e -> tooltip.append(String.format("  %s: %d%n", e.getKey(), e.getValue())));
                
                tooltip.append("%nTop Destinations:%n");
                info.destCounts.entrySet().stream()
                    .sorted((e1, e2) -> e2.getValue().compareTo(e1.getValue()))
                    .limit(2)  // Show top 2 destinations
                    .forEach(e -> tooltip.append(String.format("  %s: %d%n", e.getKey(), e.getValue())));
                
                // Draw tooltip background
                g2.setColor(new Color(255, 255, 220, 230));  // Slightly transparent background
                FontMetrics fm = g2.getFontMetrics();
                String[] lines = tooltip.toString().split("\n");
                int tooltipWidth = Arrays.stream(lines)
                    .mapToInt(fm::stringWidth)
                    .max()
                    .orElse(0) + 20;
                int tooltipHeight = fm.getHeight() * lines.length + 10;
                
                // Adjust position to keep tooltip visible
                int tooltipX = Math.min(x + 10, getWidth() - tooltipWidth - 10);
                int tooltipY = Math.min(y - 20, getHeight() - tooltipHeight - 10);
                
                // Draw tooltip box with rounded corners
                g2.fillRoundRect(tooltipX, tooltipY, tooltipWidth, tooltipHeight, 10, 10);
                g2.setColor(Color.GRAY);
                g2.drawRoundRect(tooltipX, tooltipY, tooltipWidth, tooltipHeight, 10, 10);
                
                // Draw tooltip text
                g2.setColor(Color.BLACK);
                int textY = tooltipY + fm.getAscent() + 5;
                for (String line : lines) {
                    g2.drawString(line, tooltipX + 10, textY);
                    textY += fm.getHeight();
                }
                break;
            }
        }
    }

    private void toggleCapture() {
        if (!isPaused) {
            // Stopping capture
            packetCapturing.stopCapturing();
            captureButton.setText("Resume Capture");
            captureButton.setBackground(new Color(46, 204, 113)); // Green
            isPaused = true;

            // Store current data
            pausedPacketCounts.clear();
            pausedTimeLabels.clear();
            pausedPacketInfoList.clear();
            pausedPacketCounts.addAll(packetCounts);
            pausedTimeLabels.addAll(timeLabels);
            pausedPacketInfoList.addAll(packetInfoList);

        } else {
            // Resuming capture
            packetCapturing.resumeCapturing();
            captureButton.setText("Stop Capture");
            captureButton.setBackground(Color.RED);
            isPaused = false;

            // Restore previous data
            packetCounts.clear();
            timeLabels.clear();
            packetInfoList.clear();
            packetCounts.addAll(pausedPacketCounts);
            timeLabels.addAll(pausedTimeLabels);
            packetInfoList.addAll(pausedPacketInfoList);
        }
    }

    private void updateGraph() {
        if (!isPaused) {
            // Create new PacketInfo for this interval
            PacketInfo currentInfo = new PacketInfo();
            currentInfo.count = currentPacketCount;
            packetInfoList.add(currentInfo);
            
            // Add new data point
            packetCounts.add(currentPacketCount);
            timeLabels.add(LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")));

            // Keep only last MAX_POINTS
            while (packetCounts.size() > MAX_POINTS) {
                packetCounts.remove(0);
                timeLabels.remove(0);
                packetInfoList.remove(0);
            }

            // Calculate average rate
            double avgRate = packetCounts.stream().mapToInt(Integer::intValue).average().orElse(0.0);

            // Update statistics
            totalPackets += currentPacketCount;
            statsLabel.setText(String.format("Total Packets: %d | Current Rate: %d packets/sec | Average Rate: %.2f packets/sec", 
                totalPackets, currentPacketCount, avgRate));

            // Reset counter for next interval
            currentPacketCount = 0;

            // Repaint
            graphPanel.repaint();
        }
    }

    public void updateTraffic(Packet packet, String sourceAddress, String destAddress, String protocol) {
        currentPacketCount++;
        
        // Update current interval's packet information
        if (!packetInfoList.isEmpty()) {
            PacketInfo currentInfo = packetInfoList.get(packetInfoList.size() - 1);
            currentInfo.protocolCounts.merge(protocol, 1, Integer::sum);
            currentInfo.sourceCounts.merge(sourceAddress, 1, Integer::sum);
            currentInfo.destCounts.merge(destAddress, 1, Integer::sum);
        }
    }

    public void clearGraph() {
        packetCounts.clear();
        timeLabels.clear();
        packetInfoList.clear();
        pausedPacketCounts.clear();
        pausedTimeLabels.clear();
        pausedPacketInfoList.clear();
        currentPacketCount = 0;
        totalPackets = 0;
        isPaused = false;
        captureButton.setText("Stop Capture");
        captureButton.setBackground(Color.RED);
        statsLabel.setText("Total Packets: 0 | Current Rate: 0 packets/sec | Average Rate: 0 packets/sec");
        graphPanel.repaint();
    }

    @Override
    public void dispose() {
        if (updateTimer != null) {
            updateTimer.stop();
        }
        super.dispose();
    }
} 