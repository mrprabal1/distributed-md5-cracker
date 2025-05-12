#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <ctime>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include "md5.hpp"
#include <algorithm>

#define PORT 8080                       // 11
#define MAX_CLIENTS 10                  // 12
#define CHUNK_SIZE 100                // 13
#define HEARTBEAT_INTERVAL 5            // 14
#define HEARTBEAT_TIMEOUT 15            // 15
#define INACTIVE_TIMEOUT 30             // 16

struct ClientInfo {                     // 18
    int socket;                         // 19
    int start_index;                   // 20
    int end_index;                     // 21
    time_t last_heartbeat;            // 22
    bool active;                       // 23
    std::thread* thread;              // 24 <-- pointer to avoid copy errors
};                                      // 25

std::map<int, ClientInfo> clients;      // 27
std::vector<int> standby_clients;       // 28
std::mutex client_mutex;                // 29

std::string target_password = "legal";
std::string target_hash = MD5::hash(target_password); // Corrected
std::string charset = "abcdefghigkl";            // 32
int password_length = 5;                                       // 33
int total_tasks;                                               // 34
int next_task_index = 0;                                       // 35
bool found = false;                                            // 36
std::string found_password;                                    // 37

// ----------------------- Utility: totalCombinations ------------------ //
int totalCombinations(const std::string& charset, int length) {        // 40
    int total = 1;                                                     // 41
    for (int i = 0; i < length; i++)                                   // 42
        total *= charset.size();                                       // 43
    return total;                                                      // 44
}                                                                      // 45

// ------------------------ Send Task to Client ------------------------ //
void send_task(int client_socket, int start_index, int end_index) {    // 47
    std::string task = "TASK:" + std::to_string(start_index) + "," +
                       std::to_string(end_index) + "," +
                       std::to_string(password_length) + "," +
                       target_hash + "," + charset + "\n";
    send(client_socket, task.c_str(), task.size(), 0);  // Fixed here
}                                                                      // 53


                                                                      // 53

// --------------------- Assign Task to Client ------------------------ //
void assign_task_to_client(int client_id, bool is_standby) {           // 55
    std::lock_guard<std::mutex> lock(client_mutex);                    // 56

    if (is_standby) {                                                  // 57
        standby_clients.erase(std::remove(standby_clients.begin(),     // 58
            standby_clients.end(), client_id), standby_clients.end()); // 59
    }                                                                  // 60

    if (clients.find(client_id) != clients.end() && next_task_index < total_tasks) { // 61
        clients[client_id].start_index = next_task_index;              // 62
        clients[client_id].end_index = next_task_index + CHUNK_SIZE - 1; // 63
        clients[client_id].last_heartbeat = time(0);                   // 64
        clients[client_id].active = true;                              // 65
        send_task(clients[client_id].socket, clients[client_id].start_index, clients[client_id].end_index); // 66
        next_task_index += CHUNK_SIZE;                                 // 67
        std::cout << "[*] Assigned task to client " << client_id << "\n"; // 68
    }                                                                  // 69
}

// -------------------------- Heartbeat Monitor ----------------------- //
void heartbeat_monitor() {                                             // 71
    while (!found) {                                                   // 72
        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL)); // 73
        std::lock_guard<std::mutex> lock(client_mutex);                // 74

        for (auto& [id, client] : clients) {                           // 75
            if (client.active && time(0) - client.last_heartbeat > INACTIVE_TIMEOUT) { // 76
                client.active = false;                                 // 77
                standby_clients.push_back(id);                         // 78
                std::cout << "[!] Client " << id << " is now INACTIVE.\n"; // 79
            }                                                          // 80
        }

        for (int id : standby_clients) {                               // 82
            if (next_task_index < total_tasks)                         // 83
                assign_task_to_client(id, true);                       // 84
        }                                                              // 85
    }                                                                  // 86
}

// -------------------------- Handle Client --------------------------- //
void handle_client(int client_socket, int client_id) {                 // 88
    char buffer[1024];                                                 // 89
    while (!found) {                                                   // 90
        memset(buffer, 0, sizeof(buffer));                             // 91
        int valread = read(client_socket, buffer, sizeof(buffer));     // 92

        if (valread <= 0) {                                            // 93
            std::cerr << "[!] Client " << client_id << " disconnected.\n"; // 94
            close(client_socket);                                      // 95
            std::lock_guard<std::mutex> lock(client_mutex);            // 96
            clients[client_id].active = false;                         // 97
            standby_clients.push_back(client_id);                      // 98
            break;                                                     // 99
        }

        std::string msg(buffer);                                       // 101

        if (msg.find("HEARTBEAT") != std::string::npos) {              // 102
            std::lock_guard<std::mutex> lock(client_mutex);            // 103
            clients[client_id].last_heartbeat = time(0);               // 104
        }

        if (msg.find("FOUND:") == 0) {                                  // 107
            std::string password = msg.substr(6);                       // 108
            found = true;                                               // 109
            found_password = password;                                  // 110

            std::cout << "\n✅ Password found by client " << client_id << ": " << password << "\n"; // 111

            for (auto& [id, info] : clients) {                          // 113
                std::string stop_msg = "STOP\n";                        // 114
                send(info.socket, stop_msg.c_str(), stop_msg.size(), 0); // 115
            }
            break;
        }
    }
}

// ----------------------------- Main ---------------------------------- //
int main() {                                                           // 121
    int server_fd, new_socket;                                         // 122
    struct sockaddr_in address;                                        // 123
    int addrlen = sizeof(address);                                     // 124

    server_fd = socket(AF_INET, SOCK_STREAM, 0);                       // 126
    if (server_fd == 0) { perror("socket failed"); exit(EXIT_FAILURE); } // 127

    address.sin_family = AF_INET;                                      // 129
    address.sin_addr.s_addr = INADDR_ANY;                              // 130
    address.sin_port = htons(PORT);                                    // 131

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { // 133
        perror("bind failed"); exit(EXIT_FAILURE);                     // 134
    }
    if (listen(server_fd, MAX_CLIENTS) < 0) { perror("listen"); exit(EXIT_FAILURE); } // 136

    std::cout << "[*] Server started on port " << PORT << "\n";        // 138
    std::thread monitor_thread(heartbeat_monitor);                     // 139

    total_tasks = totalCombinations(charset, password_length);         // 141

    int client_id = 0;                                                 // 143
    while (!found) {                                                   // 144
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen); // 145
        if (new_socket < 0) { perror("accept"); exit(EXIT_FAILURE); }  // 146

        std::lock_guard<std::mutex> lock(client_mutex);                // 148
        if (clients.size() < MAX_CLIENTS) {                            // 149
            ClientInfo info;                                           // 150
            info.socket = new_socket;                                  // 151
            info.start_index = next_task_index;                        // 152
            info.end_index = std::min(info.start_index + CHUNK_SIZE - 1, total_tasks - 1);
         // 153
            info.last_heartbeat = time(0);                             // 154
            info.active = true;                                        // 155
            info.thread = new std::thread(handle_client, new_socket, client_id); // 156
            info.thread->detach();                                     // 157

            clients[client_id] = info;                                 // 159
            send_task(new_socket, info.start_index, info.end_index);   // 160
	    next_task_index = info.end_index + 1;

            std::cout << "[+] Client " << client_id << " connected and assigned task.\n"; // 162
            client_id++;                                               // 163
        } else {                                                       // 164
            std::cout << "[!] Max clients reached.\n";                 // 165
        }
    }

    close(server_fd);                                                  // 168
    return 0;                                                          // 169
}
