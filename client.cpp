// client.cpp
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include "md5.hpp"

#define PORT 8080
#define HEARTBEAT_INTERVAL 5

using namespace std;

atomic<bool> found(false);
int password_length;
string charset, target_hash;

void send_heartbeat(int sock) {
    while (!found) {
        this_thread::sleep_for(chrono::seconds(HEARTBEAT_INTERVAL));
        string heartbeat = "HEARTBEAT\n";
        send(sock, heartbeat.c_str(), heartbeat.size(), 0);
    }
}

string index_to_password(long long index, int length, const string& charset) {
    string result(length, charset[0]);
    int base = charset.size();
    for (long long i = length - 1; i >= 0; --i) {
        result[i] = charset[index % base];
        index /= base;
    }
    return result;
}

void process_task(int sock) {
    char buffer[2048];
    string partial_msg;

    while (!found) {
        memset(buffer, 0, sizeof(buffer));
        int valread = recv(sock, buffer, sizeof(buffer), 0);
        if (valread <= 0) break;

        partial_msg += string(buffer, valread);
        size_t newline_pos;
        while ((newline_pos = partial_msg.find('\n')) != string::npos) {
            string msg = partial_msg.substr(0, newline_pos);
            partial_msg.erase(0, newline_pos + 1);

            if (msg.find("TASK:") == 0) {
                stringstream ss(msg.substr(5));
                long long start, end;
                string token;

                getline(ss, token, ','); start = stoll(token);
                getline(ss, token, ','); end = stoll(token);
                getline(ss, token, ','); password_length = stoll(token);
                getline(ss, token, ','); target_hash = token;
                getline(ss, token, ','); charset = token;

                cout << "[*] Received task: " << start << " to " << end << endl;

                for (long long i = start; i <= end && !found; ++i) {
                    string pwd = index_to_password(i, password_length, charset);
                    cout << "[-] Trying: " << pwd << endl;
                    if (MD5::hash(pwd) == target_hash) {
                        string found_msg = "FOUND:" + pwd + "\n";
                        send(sock, found_msg.c_str(), found_msg.size(), 0);
                        cout << "[+] Found password: " << pwd << endl;
                        found = true;
                        break;
                    }
                    this_thread::sleep_for(chrono::milliseconds(1)); // Optional
                }

                if (!found) {
                    string done_msg = "DONE\n";
                    send(sock, done_msg.c_str(), done_msg.size(), 0);
                }
            } else if (msg.find("STOP") == 0) {
                found = true;
                break;
            }
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    const char* my_IP = "192.168.1.48";
    serv_addr.sin_addr.s_addr = inet_addr(my_IP);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection failed\n";
        return 1;
    }

    cout << "Connected to server.\n";

    thread hb(send_heartbeat, sock);
    process_task(sock);
    hb.join();

    close(sock);
    return 0;
}
