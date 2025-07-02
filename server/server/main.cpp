#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>              // For sockaddr_in and IP conversion
#include <thread>                  // For multithreading support
#include <vector>                  // For storing connected clients
#include <mutex>                   // For thread-safe access to client list
#include <openssl/ssl.h>          // OpenSSL main SSL/TLS API
#include <openssl/err.h>          // OpenSSL error reporting
#include <algorithm>              // For removing disconnected clients
#include <openssl/applink.c>      // Fix for OPENSSL_Uplink error on Windows

#pragma comment(lib, "ws2_32.lib") // Link with Winsock library
#pragma comment(lib, "libssl.lib") // Link with OpenSSL SSL library
#pragma comment(lib, "libcrypto.lib") // Link with OpenSSL crypto library

using namespace std;

mutex client_mutex; // Protects access to the clients vector across threads
vector<pair<SOCKET, SSL*>> clients; // Stores connected client sockets and their SSL contexts

// Function to initialize OpenSSL server context
SSL_CTX* InitServerCTX() {
    SSL_library_init();                  // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();       // Load encryption & digest algorithms
    SSL_load_error_strings();           // Load error strings for OpenSSL
    const SSL_METHOD* method = TLS_server_method(); // Use TLS server method
    return SSL_CTX_new(method);         // Create a new SSL context
}

// Load certificate and private key into the SSL context
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);    // Print OpenSSL error messages
        exit(1);
    }
}

// Function to interact with the connected client using SSL
void InteractWithClient(SSL* ssl, SOCKET clientSocket) {
    cout << "Client Connected with encryption" << endl;

    char buffer[4096]; // Buffer to store incoming data

    while (true) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer)); // Receive data over TLS
        if (bytes <= 0) {
            cout << "Client disconnected or SSL_read failed" << endl;
            break; // Exit on failure or disconnection
        }

        string msg(buffer, bytes); // Convert received data to string
        cout << "Message: " << msg << endl;

        // Broadcast securely to all other clients
        lock_guard<mutex> lock(client_mutex); // Lock for thread safety
        for (auto& client : clients) {
            if (client.first != clientSocket) {
                SSL_write(client.second, msg.c_str(), static_cast<int>(msg.length())); // Send encrypted message
            }
        }
    }

    // Cleanup SSL and socket after client disconnects
    SSL_shutdown(ssl);   // Perform SSL/TLS shutdown
    SSL_free(ssl);       // Free SSL object
    closesocket(clientSocket); // Close client socket

    // Remove disconnected client from the list
    lock_guard<mutex> lock(client_mutex);
    clients.erase(remove_if(clients.begin(), clients.end(),
        [clientSocket](const pair<SOCKET, SSL*>& p) { return p.first == clientSocket; }),
        clients.end());
}

int main() {
    WSAData data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) { // Initialize Winsock
        cerr << "Winsock Init Failed\n";
        return 1;
    }

    SSL_CTX* ctx = InitServerCTX(); // Initialize SSL server context
    LoadCertificates(ctx,
        "C:/Users/AMAN TRIPATHI/source/repos/server/x64/Debug/server.crt", // Path to server certificate
        "C:/Users/AMAN TRIPATHI/source/repos/server/x64/Debug/server.key"); // Path to server private key

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0); // Create a TCP socket
    if (listenSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed\n";
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Create address structure and bind to port
    sockaddr_in serveraddr = {};
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(12546);         // Port number
    serveraddr.sin_addr.s_addr = INADDR_ANY;    // Accept connections on all local interfaces

    if (bind(listenSocket, (sockaddr*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR) {
        cerr << "Bind failed\n";
        closesocket(listenSocket);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) { // Listen for incoming connections
        cerr << "Listen failed\n";
        closesocket(listenSocket);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    cout << "Secure Server listening on port 12546...\n";

    while (true) {
        // Accept new incoming connection
        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "Accept failed\n";
            continue;
        }

        // Create a new SSL object for the client
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSocket); // Bind SSL object to socket

        if (SSL_accept(ssl) <= 0) { // Perform TLS handshake
            ERR_print_errors_fp(stderr); // Print handshake errors
            closesocket(clientSocket);
            SSL_free(ssl);
            continue;
        }

        {
            lock_guard<mutex> lock(client_mutex); // Add new client to list
            clients.emplace_back(clientSocket, ssl);
        }

        // Spawn a new thread for this client
        thread t(InteractWithClient, ssl, clientSocket);
        t.detach(); // Let thread run independently
    }

    closesocket(listenSocket); // Close listening socket
    SSL_CTX_free(ctx);         // Free SSL context
    WSACleanup();              // Cleanup Winsock
    return 0;
}
