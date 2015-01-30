package cryptography.sniffer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sniffs the network connection
 * @author Dominik Scholz
 * @version 0.1
 */
public class Sniffer {

    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final Logger logger = LogManager.getLogger(Sniffer.class);

    public static void main(String[] args) throws InterruptedException {
        List<PcapIf> networkInterfaces = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();

        // getting all network interfaces and aborting if there aren't any
        if (Pcap.findAllDevs(networkInterfaces, errorBuffer) == Pcap.NOT_OK || networkInterfaces.isEmpty()) {
            logger.error("Error reading list of network interfaces: " + errorBuffer.toString());
            return;
        }

        logger.info("Found network interfaces:");

        // printing network interfaces
        AtomicInteger counter = new AtomicInteger(0);
        networkInterfaces.forEach(e -> logger.info("#" + counter.getAndIncrement()
                + ": " + e.getName()
                + " " + ((e.getDescription() != null) ? e.getDescription() : "No description available")));

        // waiting for user input
        PcapIf selectedInterface = null;
        logger.info("Please enter the id of the device you like to sniff:");
        Scanner scanner = new Scanner(System.in);
        do {
            try {
                selectedInterface = networkInterfaces.get(Integer.parseInt(scanner.nextLine()));
            } catch (Exception e) {
                logger.error(e.getMessage());
                selectedInterface = null;
            }
        } while (selectedInterface == null);
        scanner.close();

        // display selected interface
        logger.info("Selected interface " + ((selectedInterface.getDescription() != null)
                ? selectedInterface.getDescription() : "No description available") + " reading...");

        // capture the network interface
        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis
        Pcap pcap = Pcap.openLive(selectedInterface.getName(), snaplen, flags, timeout, errorBuffer);

        if (pcap == null) {
            logger.error("Error while opening interface for capture: " + errorBuffer.toString());
            return;
        }

        // handler to receive the packets
        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
            String[] parsedPacket = packet.toString().split("Payload");
            if(parsedPacket.length < 2) return;

            logger.info(
                    "Received packet at " + new Date(packet.getCaptureHeader().timestampInMillis()) +
                            " caplen=" + packet.getCaptureHeader().caplen() +
                            " len=" + packet.getCaptureHeader().wirelen() +
                            " content1: " + ANSI_YELLOW + parsedPacket[1].toString());
        };

        // tells the thread to read
        AtomicBoolean read = new AtomicBoolean(true);

        // looping
        new Thread(() -> {
            while(read.get()) {
                pcap.loop(1, jpacketHandler, "Sniffer");
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                }
            }
        }).start();

        // close the capturing on shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            pcap.close();
            read.set(false);
        }));
    }

}
