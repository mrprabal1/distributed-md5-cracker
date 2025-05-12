#include <iostream>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include "md5.hpp"

#define PORT 8080
#define HEARTBEAT_INTERVAL 5

std::atomic<bool> found(false);
int password_length;
std::string charset, target_hash;

void send_heartbeat(int client_socket) {
    while (!found) {
        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL));
        std::string heartbeat = "HEARTBEAT\n";
        send(client_socket, heartbeat.c_str(), heartbeat.size(), 0);
    }
}

// Fixed index_to_password to generate correct strings
std::string index_to_password(int index, int length, const std::string& charset) {
    std::string result;
    int base = charset.size();
    for (int i = 0; i < length; i++) {
        result = charset[index % base] + result;
        index /= base;
    }
    return result;
}

void process_task(int client_socket) {
    char buffer[2048];
    while (!found) {
        memset(buffer, 0, sizeof(buffer));
        int valread = read(client_socket, buffer, sizeof(buffer));
        if (valread <= 0) {
            std::cerr << "Connection lost.\n";
            break;
        }

        std::string msg(buffer);
        if (msg.find("TASK:") == 0) {
            int start_index, end_index;
            size_t pos = msg.find(":") + 1;
            std::string data = msg.substr(pos);

            std::stringstream ss(data);
            std::string token;

            std::getline(ss, token, ',');
            start_index = std::stoi(token);
            std::getline(ss, token, ',');
            end_index = std::stoi(token);
            std::getline(ss, token, ',');
            password_length = std::stoi(token);
            std::getline(ss, token, ',');
            target_hash = token;
            std::getline(ss, token, ',');
            charset = token;

            std::cout << "[*] Received task: " << start_index << " to " << end_index << std::endl;
            std::cout << "[*] Charset: " << charset << ", Length: " << password_length << std::endl;
            std::cout << "[*] Target Hash: " << target_hash << std::endl;

            for (int i = start_index; i <= end_index && !found; i++) {
                std::string candidate = index_to_password(i, password_length, charset);
                std::string hash = MD5::hash(candidate);
                std::cout << "Trying: " << candidate << " -> " << hash << std::endl;
                if (hash == target_hash) {
                    std::cout << "[+] Password found: " << candidate << std::endl;
                    std::string found_msg = "FOUND:" + candidate + "\n";
                    send(client_socket, found_msg.c_str(), found_msg.size(), 0);
                    found = true;
                    break;
                }
            }
        } else if (msg.find("STOP") == 0) {
            std::cout << "[*] Received STOP. Exiting...\n";
            found = true;
            break;
        }
    }
}


int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket error");
        return 1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connect error");
        return 1;
    }

    std::cout << "Connected to server.\n";

    std::thread heartbeat_thread(send_heartbeat, sock);
    process_task(sock);
    heartbeat_thread.join();
    close(sock);
    return 0;
}
