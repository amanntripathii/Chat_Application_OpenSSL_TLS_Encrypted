#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h> // For sockaddr_in and other socket-related structures
#include <tchar.h> // For _T macro to handle Unicode and non-Unicode builds
#include <thread> // thread support 
#include <vector> 
#include <algorithm> // For remove/find
#include <mutex> // For thread-safe access to client list

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c> // Fix for OPENSSL_Uplink error on Windows

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib,"ws2_32.lib") // Link with the Winsock library

using namespace std;

bool Initialize() {
	WSADATA data;
	return WSAStartup(MAKEWORD(2, 2), &data) == 0; // Winsock Initialization Successful ( Using version 2.2 )
}

// Function to initialize OpenSSL server context
SSL_CTX* InitServerCTX() {
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	const SSL_METHOD* method = TLS_server_method(); // Use TLS server method
	return SSL_CTX_new(method);
}

// Load certificate and private key into the SSL context
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ||
		SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr); // Print OpenSSL error messages
		exit(1);
	}
}

void InteractWithClient(SSL* clientSSL, vector<SSL*>& clients, std::mutex& clientsMutex) {
	// Function to interact with the client to free main thread for receiving data
	cout << "Client Connected with encryption" << endl;

	char buffer[4096];// Buffer to store incoming data

	while (1) {
		// bytesrecvd will contain the number of bytes received
		int bytesrecvd = SSL_read(clientSSL, buffer, sizeof(buffer));

		if (bytesrecvd <= 0) {
			cout << "Client disconnected or error occurred" << endl;
			break; // Exit the loop if no data is received or an error occurs
		}

		string message(buffer, bytesrecvd); // Convert the received data to a string
		cout << "Message from Client : " << message << endl;

		// Lock the mutex for thread safety before broadcasting to other clients
		{
			lock_guard<mutex> lock(clientsMutex);
			for (auto client : clients) {
				if (client != clientSSL) {
					SSL_write(client, message.c_str(), message.length()); //message.c_str() returns a pointer to the character array
				}
			}
		}
	}

	// Lock the mutex before modifying the vector to remove the disconnected client
	{
		lock_guard<mutex> lock(clientsMutex);
		auto it = find(clients.begin(), clients.end(), clientSSL);
		if (it != clients.end()) {
			clients.erase(it);
		}
	}

	// Retrieve original socket, clean up OpenSSL, and close socket
	int clientSocket = SSL_get_fd(clientSSL);
	SSL_shutdown(clientSSL);
	SSL_free(clientSSL);
	closesocket(clientSocket); // Close the client socket after use
}

int main() {
	if (!Initialize()) {
		cout << "Winsock Initialization Failed" << endl;
		return 1;
	}

	cout << "Server Program" << endl;

	SSL_CTX* ctx = InitServerCTX(); // Initialize SSL server context

	// Load your specific certificates
	LoadCertificates(ctx,
		"C:/Users/AMAN TRIPATHI/source/repos/server/x64/Debug/server.crt",
		"C:/Users/AMAN TRIPATHI/source/repos/server/x64/Debug/server.key");

	SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0); // Create a socket
	// AF_INET: IPv4, SOCK_STREAM: TCP, 0: Default protocol

	if (listenSocket == INVALID_SOCKET) { // Check if the socket was created successfully
		cout << "Socket Creation Failed" << endl;
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	//create address structure for the server
	int port = 12546;
	sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET; // Address family: IPv4
	serveraddr.sin_port = htons(port); // Port number (converted to network byte order)

	//convert the IP address (0.0.0.0) put it inside sin_family in binary form
	if (InetPton(AF_INET, _T("0.0.0.0"), &serveraddr.sin_addr) != 1) {
		// _T macro is used for compatibility with both Unicode and non-Unicode builds
		cout << "IP address conversion failed" << endl;
		closesocket(listenSocket); // Close the socket if conversion fails
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	//bind the socket to the address and port
	if (bind(listenSocket, reinterpret_cast<sockaddr*>(&serveraddr), sizeof(serveraddr)) == SOCKET_ERROR) {
		// reinterpret_cast is used to cast sockaddr_in to sockaddr
		cout << "bind failed" << endl;
		closesocket(listenSocket);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	//listen for incoming connections
	if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
		// SOMAXCONN is the maximum number of pending connections
		cout << "listen failed" << endl;
		closesocket(listenSocket);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	cout << "Secure Server has started listening on port : " << port << endl;

	vector<SSL*> clients;
	mutex clientsMutex; // Protects access to the clients vector across threads

	while (1) {
		// Accept incoming connections (this is a blocking call)
		SOCKET clientSocket = accept(listenSocket, nullptr, nullptr); // Accept a connection from a client
		// The parameters are set to nullptr since we don't need the client's address information
		if (clientSocket == INVALID_SOCKET) {
			cout << "Invalid Client Socket" << endl;
			continue;
		}

		// Create a new SSL object for the client
		SSL* ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);

		// Perform TLS handshake
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			closesocket(clientSocket);
			SSL_free(ssl);
			continue;
		}

		// Lock the mutex before adding a new client
		{
			lock_guard<mutex> lock(clientsMutex);
			clients.push_back(ssl); // Store the client SSL context in the vector
		}

		thread t1(InteractWithClient, ssl, std::ref(clients), std::ref(clientsMutex)); //std::ref is used to pass the vector by reference
		// Create a new thread to handle the client interaction
		t1.detach(); // Detach the thread to allow it to run independently
	}

	closesocket(listenSocket); // Close the listening socket after use
	SSL_CTX_free(ctx);         // Free SSL context
	WSACleanup();              // Cleanup Winsock resources
	return 0;
}
