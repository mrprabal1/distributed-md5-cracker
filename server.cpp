// server.cpp
#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <ctime>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include "md5.hpp"

#define PORT 8080
#define MAX_CLIENTS 10
#define CHUNK_SIZE 20000

struct ClientInfo {
    int socket;
    int start_index = -1;
    int end_index = -1;
    time_t last_heartbeat;
    bool active = false;
};

std::map<int, ClientInfo> clients;
std::mutex client_mutex;

std::string target_password = "password";
std::string target_hash = MD5::hash(target_password);
std::string charset = "abcdefghigklmnopqrtsuvwxyz";
int password_length = 8;
long long total_tasks;
long long next_task_index = 0;
bool found = false;
std::string found_password;

long long totalCombinations(const std::string& charset, int length) {
    long long total = 1;
    for (long long i = 0; i < length; i++)
        total *= charset.size();
    return total;
}

void send_task(int client_socket, long long start_index, long long end_index) {
    std::string task = "TASK:" + std::to_string(start_index) + "," +
                       std::to_string(end_index) + "," +
                       std::to_string(password_length) + "," +
                       target_hash + "," + charset + "\n";
    send(client_socket, task.c_str(), task.size(), 0);
}

bool assign_task_to_client(int client_id) {
    if (next_task_index >= total_tasks || found) return false;

    ClientInfo& client = clients[client_id];
    client.start_index = next_task_index;
    client.end_index = std::min(next_task_index + CHUNK_SIZE - 1, total_tasks - 1);
    client.last_heartbeat = time(0);
    client.active = true;

    send_task(client.socket, client.start_index, client.end_index);
    std::cout << "[*] Assigned task to client " << client_id << ": "
              << client.start_index << " to " << client.end_index << std::endl;

    next_task_index = client.end_index + 1;
    return true;
}

void handle_client(int client_socket, int client_id) {
    char buffer[1024];

    {
        std::lock_guard<std::mutex> lock(client_mutex);
        assign_task_to_client(client_id);
    }

    while (!found) {
        memset(buffer, 0, sizeof(buffer));
        int valread = read(client_socket, buffer, sizeof(buffer));
        if (valread <= 0) break;

        std::string msg(buffer);

        if (msg.find("HEARTBEAT") != std::string::npos) {
            std::lock_guard<std::mutex> lock(client_mutex);
            clients[client_id].last_heartbeat = time(0);
        } else if (msg.find("FOUND:") == 0) {
            std::string password = msg.substr(6);
            found = true;
            found_password = password;
            std::cout << "\nPassword found by client " << client_id << ": " << password << std::endl;

            std::lock_guard<std::mutex> lock(client_mutex);
            for (auto& [id, info] : clients) {
                std::string stop_msg = "STOP\n";
                send(info.socket, stop_msg.c_str(), stop_msg.size(), 0);
            }
            return;
        } else if (msg.find("DONE") == 0) {
            std::lock_guard<std::mutex> lock(client_mutex);
            clients[client_id].active = false;

            // Assign new task only if available
            assign_task_to_client(client_id);
        }
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    int opt = 1;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // address.sin_family = AF_INET;
    // address.sin_addr.s_addr = INADDR_ANY;
    // address.sin_port = htons(PORT);

    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    const char* my_IP = "192.168.0.171";
    address.sin_addr.s_addr = inet_addr(my_IP);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, MAX_CLIENTS);

    std::cout << "[*] Server started on port " << PORT << "\n";
    total_tasks = totalCombinations(charset, password_length);

    int client_id = 0;
    while (!found) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) continue;

        {
            std::lock_guard<std::mutex> lock(client_mutex);
            clients[client_id] = {new_socket};
        }

        std::thread t(handle_client, new_socket, client_id);
        t.detach();

        std::cout << "[+] Client " << client_id << " connected.\n";
        client_id++;
    }

    close(server_fd);
    return 0;
}

