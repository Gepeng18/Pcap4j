package org.example;

import org.apache.commons.lang3.StringUtils;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class Pcap4jUtil {

    public static final int SNAP_LEN = 65536;
    public static final int MAX_PACKETS = 50;

    public static void grabPackage(String host, Integer port) throws Exception {
        InetAddress addr = InetAddress.getByName(host);
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        PcapHandle handle = nif.openLive(SNAP_LEN, mode, 10000);

        String filter = "tcp port " + port;
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        // 让handle使用创建的listener，且指定抓50个包
        try {
            handle.loop(MAX_PACKETS, Pcap4jUtil::handleEachPackage);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        handle.close();
    }

    private static void handleEachPackage(Packet packet) {
        // if (packet == null || ! packet.contains(TcpPacket.class)) {
        //     return;
        // }
        // TcpPacket tcpPacket = packet.get(TcpPacket.class);
        // if (!"HTTP".equals(tcpPacket.getHeader().getDstPort().name())) {
        //     return;
        // }
        // Packet payloadPackage = tcpPacket.getPayload();
        // if (payloadPackage == null) {
        //     return;
        // }
        // byte[] payload = payloadPackage.getRawData();
        // String httpHeader = extractHttpHeader(payload);
        // if (httpHeader != null && !httpHeader.isEmpty()) {
        //     System.out.println("HTTP Header:\n" + httpHeader);
        // }

        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        if (ethernetPacket == null) {
            return;
        }

        Packet payload = ethernetPacket.getPayload();
        if (payload == null) {
            return;
        }

        byte[] rawData = payload.getRawData();
        if (rawData == null) {
            return;
        }
        String httpHeader = extractHttpHeader(rawData);
        if (StringUtils.isEmpty(httpHeader)) {
            return;
        }
        if (!httpHeader.contains("HTTP")) {
            return;
        }
        System.out.println("------------------------------------------------------------------------------------");
        System.out.println("httpHeader is : " + httpHeader);

        IpV4Packet ipv4Packet =  payload.get(IpV4Packet.class);
        if (ipv4Packet != null ) {
            // 获取源 IP 和目标 IP
            String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
            // 打印源 IP、目标 IP 和目标端口
            System.out.println("Source IP: " + srcIp);
            System.out.println("Destination IP: " + dstIp);
        }
    }


    private static String extractHttpHeader(byte[] payload) {
        Charset charset = StandardCharsets.UTF_8; // 使用 UTF-8 编码
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        CharBuffer charBuffer = charset.decode(buffer);
        String data = charBuffer.toString();
        int headerEndIndex = data.indexOf("\r\n\r\n");
        if (headerEndIndex != -1) {
            return data.substring(0, headerEndIndex + 4);
        }
        return null;
    }


}
