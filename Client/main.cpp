#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <string>
#include <openssl/applink.c>

using namespace std;

#pragma comment(lib , "ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

bool Initialize() {
	WSADATA data;
	return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

// Initialize the OpenSSL context for client
SSL_CTX* InitClientCTX() {
	SSL_library_init(); // Load SSL algorithms
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	const SSL_METHOD* method = TLS_client_method(); // Use TLS client method
	return SSL_CTX_new(method);
}

void SendMsg(SSL* ssl, SOCKET s) {

	cout << "Enter Your Chat Name : " << endl;
	string name;
	getline(cin, name);
	string message;

	while (1) {
		getline(cin, message);

		if (message == "quit" || message == "exit") {
			cout << "Exiting..." << endl;
			break;
		}

		string msg = name + " : " + message;
		// Send the encrypted message using SSL_write
		int bytesent = SSL_write(ssl, msg.c_str(), msg.length());
		if (bytesent <= 0) {
			cout << "Send Failed" << endl;
			break;
		}
	}

	// Gracefully shut down the SEND half of the socket.
	// This signals the server that we are done sending, naturally unblocking our ReceiveMsg thread.
	shutdown(s, SD_SEND);
}

void ReceiveMsg(SSL* ssl) {

	char buffer[4096]; // Buffer to store incoming messages
	int recvlength;
	string msg = "";

	while (1) {
		// Read incoming encrypted messages using SSL_read
		recvlength = SSL_read(ssl, buffer, sizeof(buffer));
		if (recvlength <= 0) {
			cout << "Connection closed or error occurred" << endl;
			break;
		}
		else {
			msg = string(buffer, recvlength); // Convert buffer to string
			cout << msg << endl;
		}
	}
}

int main() {

	if (!Initialize()) {
		cout << "Winsock Initialization Failed" << endl;
		return 1;
	}

	// Create and initialize the SSL context
	SSL_CTX* ctx = InitClientCTX();

	SOCKET s;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		cout << "Invalid Socket Created" << endl;
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	int port = 12546;
	string serveraddress = "127.0.0.1"; // Localhost
	sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	inet_pton(AF_INET, serveraddress.c_str(), &(serveraddr.sin_addr));
	// Attempt to connect to the server , serveeraddress.c_str() is used to convert string to char*

	if (connect(s, reinterpret_cast<sockaddr*>(&serveraddr), sizeof(serveraddr)) == SOCKET_ERROR) {
		cout << "Not able to connect to server" << endl;
		cout << ": " << WSAGetLastError(); // Print the error code
		closesocket(s);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	// Establish TLS over the existing TCP connection
	SSL* ssl = SSL_new(ctx);
	SSL_set_fd(ssl, s);

	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr); // Print SSL error info
		SSL_free(ssl);
		closesocket(s);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	cout << "Successfully connected to server (TLS Encrypted)" << endl;

	thread senderthread(SendMsg, ssl, s);
	thread reciverthread(ReceiveMsg, ssl);

	senderthread.join(); // Wait for the sender thread to finish
	reciverthread.join(); // Wait for the receiver thread to finish

	// Clean up OpenSSL and Winsock resources after threads are done
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(s);
	SSL_CTX_free(ctx);
	WSACleanup();

	return 0;
}
