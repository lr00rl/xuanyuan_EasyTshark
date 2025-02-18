/*
 * To compile and run this program: g++ homework02.cpp -o homework02 && ./homework02
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
    std::string protocol;        // 协议
    std::string info;            // 数据包的概要信息
};
void parseLine(std::string line, Packet& packet);
void printPacket(const Packet &packet);


int main() {
    // To get the capture file, in linux os, run: `sudo tshark -i Mihomo -c 50 -w - | tee capture.pcap`
    // or `sudo tshark -i Mihomo -c 50 -w - |& tee capture.pcap`
    // const char* command = "tshark -r capture.pcap";
    const char* command = "tshark -r capture.pcap -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info";
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

    if (fields.size() >= 6) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.src_ip = fields[2];
        packet.dst_ip = fields[3];
        packet.protocol = fields[4];
        packet.info = fields[5];
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
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}
