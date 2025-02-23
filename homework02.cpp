/*
 * To compile and run this program: g++ homework02.cpp -std=c++14 -o homework02 && ./homework02
 *
 * **第一个问题**，为什么有些行IP地址是空的呢？这里面有几个原因，我看大家作业回答的基本差不多了，我再总结一下：
 * 1. 在tshark中，-e ip.src -e ip.dst参数输出的是IPv4的源IP和目的IP，
 *    而如果遇到的是一个IPv6的数据报文，tshark输出的就会变成空了。
 *    想要解决这个问题，就需要同时指定 `-e ip.src -e ipv6.src -e ip.dst ipv6.dst`。
 *    然后在解析的时候，两个字段都要解析，哪个不为空，就取哪个作为数据包的源地址。
 * 2. 有些数据包本身就没有网络层的，比如ARP，当然也就没有IP地址了。
*/
#include <iostream>
#include <cstdio>
#include <vector>
#include <sstream>
// RapidJSON is a header-only C++ library. Just copy the include/rapidjson folder to system or project's include path.
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"


struct Packet {
    int frame_number;            // 数据包编号
    std::string time;            // 数据包的时间戳
    std::string src_ip;          // 源IP地址
    std::string dst_ip;          // 目的IP地址
    int src_port;        // 源Port
    int dst_port;        // 目的Port
    std::string protocol;        // 协议
    std::string info;            // 数据包的概要信息
};
void parseLine(std::string line, Packet& packet);
void printPacket(const Packet &packet);


int main() {
    // To get the capture file, in linux os, run: `sudo tshark -i Mihomo -c 50 -w - | tee capture.pcap`
    // or `sudo tshark -i Mihomo -c 50 -w - |& tee capture.pcap`
    // const char* command = "tshark -r capture.pcap";
    const char* command = "tshark -r capture.pcap  -T fields -e frame.number -e frame.time -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    // char buffer[4096];
    // while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    //     std::cout << buffer;
    // }

    std::vector<Packet> packets;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        parseLine(buffer, packet);
        packets.push_back(packet);
    }

    for (auto &p : packets) {
        // printf("frame_number: %d  time: %s  src_ip: %s  dst_ip: %s  protocol: %s  info: %s\n",
        //     p.frame_number,
        //     p.time.c_str(),
        //     p.src_ip.c_str(),
        //     p.dst_ip.c_str(),
        //     p.protocol.c_str(),
        //     p.info.c_str());
        printPacket(p);
    }

    pclose(pipe);
    return 0;
}


void parseLine(std::string line, Packet& packet) {

    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    while (std::getline(ss, field, '\t')) {  // 假设字段用 tab 分隔
        fields.push_back(field);
    }

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time
    // 2: ip.src
    // 3: ipv6.src
    // 4: ip.dst
    // 5: ipv6.dst
    // 6: tcp.srcport
    // 7: udp.srcport
    // 8: tcp.dstport
    // 9: udp.dstport
    // 10: _ws.col.Protocol
    // 11: _ws.col.Info

    if (fields.size() >= 12) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.src_ip = fields[2].empty() ? fields[3] : fields[2];
        packet.dst_ip = fields[4].empty() ? fields[5] : fields[4];
        if (!fields[6].empty() || !fields[7].empty()) {
            packet.src_port = std::stoi(fields[6].empty() ? fields[7] : fields[6]);
        }

        if (!fields[8].empty() || !fields[9].empty()) {
            packet.dst_port = std::stoi(fields[8].empty() ? fields[9] : fields[8]);
        }
        packet.protocol = fields[10];
        packet.info = fields[11];
    }
}


void printPacket(const Packet &packet) {

    // 构建JSON对象
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    // 设置JSON为Object对象类型
    pktObj.SetObject();

    // 添加JSON字段
    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}
