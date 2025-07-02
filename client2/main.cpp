#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <string>
#include <openssl/applink.c>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

using namespace std;

// Initialize the OpenSSL context for client
SSL_CTX* InitClientCTX() {
    SSL_library_init(); // Load SSL algorithms
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method(); // Use TLS client method
    return SSL_CTX_new(method);
}

int main() {

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed.\n";
        return 1;
    }

    // Create and initialize the SSL context
    SSL_CTX* ctx = InitClientCTX();
    SSL* ssl;

    // Create a socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cerr << "Socket creation failed.\n";
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Fill in server address structure
    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12546);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Convert IP to binary

    // Attempt to connect to the server
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        cerr << "Connection to server failed.\n";
        closesocket(sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Establish TLS over the existing TCP connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL error info
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    cout << "Secure connection established!\n";

    // Prompt for user chat name
    cout << "Enter Your Chat Name: ";
    string name;
    getline(cin, name);

    // Create a thread to receive messages from the server
    thread recvThread([&]() {
        char buffer[4096]; // Buffer to store incoming messages
        while (true) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            cout << string(buffer, bytes) << endl;
        }
        });

    // Loop for sending messages to the server
    string input;
    while (true) {
        getline(cin, input);
        if (input == "/exit") break;

        string fullMsg = name + " : " + input;
        SSL_write(ssl, fullMsg.c_str(), (int)fullMsg.length()); // Send encrypted message
    }

    // Clean up and close the connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    WSACleanup();

    recvThread.join(); // Wait for the receive thread to finish
    return 0;
}
