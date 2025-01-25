#include "libs/libpcap-1.10.5/pcap.h"
#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fstream>
#include <ctime>

#define BUFSIZE 16777216 //Буффер для захвата пакетов
// Структура для хранения данных о потоке
struct Flow {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string prot;
    uint32_t packet_count = 0;
    uint32_t byte_count = 0;

    bool operator==(const Flow& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port;
               prot == other.prot;
    }
};

// Хэш-функция для сопоставления\
 Нужна для оптимизации поиска пакета для определенного потока приводя процесс к сложности О(1)
namespace std {
    template <>
    struct hash<Flow> {
        size_t operator()(const Flow& flow) const {
            return hash<string>()(flow.src_ip) ^ hash<string>()(flow.dst_ip) ^
                   hash<uint16_t>()(flow.src_port) ^ hash<uint16_t>()(flow.dst_port);
                   hash<string>()(flow.prot);
        }
    };
}

// Преобразование IP-адреса в строку
std::string ipToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

void temp_file_generate(const std::string& output_file) {
    const std::string temp_file = "tmp.txt";

    // Создаем временный файл и записываем в него имя выходного файла
    std::ofstream temp(temp_file, std::ios::out);
    if (!temp) {
        std::cerr << "Ошибка: не удалось создать временный файл " << temp_file << std::endl;
        return;
    }

    temp << output_file; // Записываем имя выходного файла в temp.txt
    temp.close();        
    // Передаем управление второй программе
    int result = std::system("python3 ../postprocessing.py");

    if (result != 0) {
        std::cerr << "Ошибка: не удалось выполнить postprocessing.py, код ошибки: " << result << std::endl;
    }
}

// Чтение порта из заголовка TCP/UDP
uint16_t readPort(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}
// Класс для обработки пакетов
class PacketProcessor {
    std::unordered_map<Flow, Flow> flows; // Хранилище потоков с ключами

 static void staticProcessPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) { // Статическая функция обратного вызова\
 нужна для возврата из loop, так как там возврат только в статические методы
        auto* processor = reinterpret_cast<PacketProcessor*>(args);
        processor->processPacket(header, packet);
    }

// Метод обработки пакета
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
        // Ethernet заголовок (пропускаем 14 байт)
        const uint8_t* ip_header = packet + 14;
        struct ip* iph = (struct ip*)ip_header;

        // Обрабатываем только IPv4
        if (iph->ip_v != 4) {
            return;
        }

        // Чтение IP-адреса и протокола 
        uint32_t src_ip = ntohl(*(uint32_t*)&iph->ip_src);
        uint32_t dst_ip = ntohl(*(uint32_t*)&iph->ip_dst);
        uint8_t protocol = iph->ip_p;

        uint16_t src_port = 0, dst_port = 0;

        // Смещение для заголовка TCP/UDP
        const uint8_t* transport_header = ip_header + (iph->ip_hl * 4);
        std::string protocol_name;
        if (protocol == IPPROTO_TCP) { // Для ТСР
            src_port = readPort(transport_header);
            dst_port = readPort(transport_header + 2);
            protocol_name = "TCP";
        } else if (protocol == IPPROTO_UDP) { // Для UDP
            src_port = readPort(transport_header);
            dst_port = readPort(transport_header + 2);
            protocol_name = "UDP";
        } else {
            return; 
        }

        // Создаем и обновляем поток
        Flow flow{ipToString(src_ip), ipToString(dst_ip), src_port, dst_port};
        if (flows.find(flow) == flows.end()) {
            flows[flow] = flow;
        }
        flows[flow].packet_count++;
        flows[flow].byte_count += header->len;
        flows[flow].prot = protocol_name;
    }
public:
// Метод по чтению РСАР файла
    void readPcapFile(const std::string& filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf); // Открываем файл
        if (!handle) {
            throw std::runtime_error("Error opening pcap file: " + std::string(errbuf));
        }

        struct pcap_pkthdr* header;
        const u_char* packet;
        int result;

        while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) { // Перебираем каждую запись 
            if (result == 0) continue;  
            processPacket(header, packet); // Обработка пакета 
        }

        if (result == -1) {
            throw std::runtime_error("Error reading pcap file: " + std::string(pcap_geterr(handle)));
        }

        pcap_close(handle);
    }

    // Метод записи потоков в СSV-файл
    void writeToCSV(const std::string& output_filename) const {
        std::ofstream csv_file(output_filename);
        if (!csv_file.is_open()) {
            throw std::runtime_error("Failed to open CSV file: " + output_filename);
        }

        csv_file << "Source IP,Destination IP,Source Port,Destination Port,Packet Count,Byte Count,Protocol\n";
        for (const auto& [key, flow] : flows) {
            csv_file << flow.src_ip << ","
                     << flow.dst_ip << ","
                     << flow.src_port << ","
                     << flow.dst_port << ","
                     << flow.packet_count << ","
                     << flow.byte_count <<","
                     << flow.prot << "\n";
        }
    }

    // Метод захвата пакетов с выбранного устройства
    void devSniff(std::string device, int bytestocatch, int timetosniff) {
    char errbuf[256];
    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZE, 0, 1000, errbuf); // Захват пакетов в реальном времени в разборчивом режиме
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device.c_str(), errbuf);
        return;
    }

    // Берем начальное время
    auto start_time = std::time(nullptr);

    // Указатель на структуру с данными
    struct CallbackData {
        PacketProcessor* processor;
        pcap_t* handle;
        time_t start_time;
        int timetosniff;
    } callback_data = {this, handle, start_time, timetosniff};

    // Статическая функция обратного вызова
    static auto staticProcessPacketWithTimer = [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        auto* data = reinterpret_cast<CallbackData*>(args);
        auto current_time = std::time(nullptr);

        // Проверяем, истекло ли заданное время
        if (std::difftime(current_time, data->start_time) >= data->timetosniff) {
            pcap_breakloop(data->handle); // Прерываем pcap_loop
            return;
        }

        // Обрабатываем пакет
        data->processor->processPacket(header, packet);
    };

    // Запуск цикла захвата пакетов
    pcap_loop(handle, -1, staticProcessPacketWithTimer, reinterpret_cast<u_char*>(&callback_data));
    // Закрытие хэндла
    pcap_close(handle);
}


};

int main(int argc, char* argv[]) {
  
   if(argc==3){ // Режим чтения PCAP файла
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    std::string path_data = "data/";
    input_file.insert(0, path_data); // Добавляем папку с данными в начало
    output_file.insert(0, path_data);
    try {
        PacketProcessor processor;
        processor.readPcapFile(input_file);
        processor.writeToCSV(output_file);
        std::cout << "Processing completed. Data written to " << output_file << "\n";
        temp_file_generate(output_file);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
   }
   else if (argc == 4){ // Режим чтения с устройства 
   std::string output_file = argv[1];
   std::string device = argv[2];
   std::string time_str = argv[3];
   std::string path_data = "data/";
    output_file.insert(0, path_data);

    int timetosniff=atoi(time_str.c_str());
    try{
        PacketProcessor processor;
        processor.devSniff(device,BUFSIZE,timetosniff);
        //printf("exited devsniff");
        processor.writeToCSV(output_file);
        std::cout << "Processing completed. Data written to " << output_file << "\n";
        temp_file_generate(output_file);
    }catch (const std::exception& e){
         std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
   }
   else {
     std::cerr << "Usage:\n " << argv[0] << " <input.pcap> <output.csv>\n"<< "OR\n"<< argv[0]<< "<output.csv> <device name> <time to sniff device>\n";
        return 1;
   }
    return 0;
}
