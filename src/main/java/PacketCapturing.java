import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.net.NetworkInterface;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class PacketCapturing {

    private BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>();

    public void startCapturing(PcapNetworkInterface device, JTable packetList) throws PcapNativeException, NotOpenException {
        int snapshotLength = 65536;
        int readTimeout = 50;
        final PcapHandle handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        PcapDumper dumper = handle.dumpOpen("out.pcap");

        String filter = "tcp port 80";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Create a listener that will capture packets and add them to the queue
        PacketListener listener = packet -> {
            try {
                packetQueue.put(packet); // Add packet to the queue
                // Update the packet list table (on the EDT)
                SwingUtilities.invokeLater(() -> updatePacketTable(packet, packetList));
                dumper.dump(packet, handle.getTimestamp());
            } catch (InterruptedException | NotOpenException e) {
                e.printStackTrace();
            }
        };

        // Start capturing packets in a separate thread
        new Thread(() -> {
            try {
                int maxPackets = 20;
                handle.loop(maxPackets, listener);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (NotOpenException | PcapNativeException e) {
                throw new RuntimeException(e);
            }
        }).start();
    }

    private void updatePacketTable(Packet packet, JTable packetList) {
        System.out.println(packet);
        // You can adjust the packet details here to display in the table (e.g., length, source, etc.)
//        DefaultTableModel model = (DefaultTableModel) packetList.getModel();
//        Object[] row = {model.getRowCount() + 1, packet.length(), packet.getPayload().toString(), "Destination", "TCP"};
//        model.addRow(row);
    }
}
