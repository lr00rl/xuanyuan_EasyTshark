/*
 * To compile and run this program: g++ homework03.cpp -std=c++14 -o homework03 -Iinclude && ./homework03
*/
#include <iostream>
#include <cstdio>
#include <vector>
#include <sstream>
#include <fstream>
// RapidJSON is a header-only C++ library. Just copy the include/rapidjson folder to system or project's include path.
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"


struct Packet {
    int frame_number;            // 数据包编号
    std::string time;            // 数据包的时间戳
    uint32_t cap_len;            // 数据包的长度
    std::string src_ip;          // 源IP地址
    int src_port;                // 源Port
    std::string dst_ip;          // 目的IP地址
    int dst_port;                // 目的Port
    std::string protocol;        // 协议
    std::string info;            // 数据包的概要信息
    uint32_t file_offset;        // 数据包在文件中的偏移
};

// PCAP全局文件头
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

bool parseLine(std::string line, Packet& packet);
void printPacket(const Packet &packet);
bool readPacketHex(const std::string& filePath, uint32_t offset, uint32_t length, std::vector<unsigned char> &buffer);

int main() {
    // To get the capture file, in linux os, run: `sudo tshark -i Mihomo -c 50 -w - | tee capture.pcap`
    // or `sudo tshark -i Mihomo -c 50 -w - |& tee capture.pcap`
    // const char* command = "tshark -r capture.pcap";
    const char* command = "tshark -r capture_pcapHead.pcap  -T fields -e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    std::vector<Packet> packets;
    char buffer[4096];
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        if (parseLine(buffer, packet)) {
            // 计算当前报文的偏移，然后记录在Packet对象中
            packet.file_offset = file_offset + sizeof(PacketHeader);

            // 更新偏移游标
            file_offset = file_offset + sizeof(PacketHeader) + packet.cap_len;

            packets.push_back(packet);
        }
        else {
            assert(false);
        }
    }

    const char* packet_file = "capture_pcapHead.pcap";
    for (auto &p : packets) {
        printPacket(p);

        // 读取这个报文的原始十六进制数据
        std::vector<unsigned char> buffer;
        readPacketHex(packet_file, p.file_offset, p.cap_len, buffer);

        // 打印读取到的数据：
        printf("Packet Hex: ");
        for (unsigned char byte : buffer) {
            printf("%02X ", byte);
        }
        printf("\n\n");
    }

    pclose(pipe);
    return 0;
}


bool parseLine(std::string line, Packet& packet) {

    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 很多人反馈，它们打印数据包的时候，发现编号相同的数据包，而且数据包十六进制数据和wireshark打开的对不上
    // 经过调试排查，发现问题出现在parseLine函数：
    // while (std::getline(ss, field, '\t')) {  // 假设字段用 tab 分隔
    //     fields.push_back(field);
    // }
    // 部分版本的tshark在分析一些数据包的时候，Info字段会出现空白，这样上面while循环拆分出来的字段数量就会不足，在这个if判断就会失败，不会走到if分支里面去。这样一来，后续的数据包就会全部对不上。
    // 为了解决这个问题，我们需要调整拆分字段的方式，不选用getline来实现，而是自己实现通过\t来拆分字符串，类似与其他编程语言里面的split函数功能：

    // 自己实现字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time
    // 2: frame.cap_len
    // 3: ip.src
    // 4: ipv6.src
    // 5: ip.dst
    // 6: ipv6.dst
    // 7: tcp.srcport
    // 8: udp.srcport
    // 9: tcp.dstport
    // 10: udp.dstport
    // 11: _ws.col.Protocol
    // 12: _ws.col.Info

    if (fields.size() >= 13) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.cap_len = std::stoi(fields[2]);
        packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
        packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
        if (!fields[7].empty() || !fields[8].empty()) {
            packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
        }

        if (!fields[9].empty() || !fields[10].empty()) {
            packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
        }
        packet.protocol = fields[11];
        packet.info = fields[12];
        return true;
    }
    else {
        printf("error!\n");
        return false;
    }
}

bool readPacketHex(const std::string& filePath, uint32_t offset, uint32_t length, std::vector<unsigned char> &buffer) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "无法打开文件！\n";
        return false;
    }
    
    // 将文件指针定位到指定偏移位置
    file.seekg(offset);
    if (!file) {
        std::cerr << "文件定位失败！\n";
        return false;
    }
    
    // 调整buffer大小以容纳数据
    buffer.resize(length);
    
    // 读取指定长度的数据到buffer中
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    
    // 检查是否成功读取了所有请求的字节
    if (file.gcount() != length) {
        std::cerr << "读取数据不完整，预期:" << length << "，实际:" << file.gcount() << std::endl;
        return false;
    }
    
    file.close();
    return true;
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
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);
    pktObj.AddMember("file_offset", packet.file_offset, allocator);
    pktObj.AddMember("cap_len", packet.cap_len, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}
