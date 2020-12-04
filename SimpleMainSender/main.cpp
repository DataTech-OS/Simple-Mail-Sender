#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#pragma comment (lib, "libssl.lib")
#pragma comment (lib, "libcrypto.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;

// Insist on at least Winsock v1.1
const int VERSION_MAJOR = 1;
const int VERSION_MINOR = 1;

#define CRLF "\r\n"                 // carriage-return/line feed pair

char *Base64Encode(unsigned char *data, int size);

void ShowUsage(void)
{
	cout << "Usage: SENDMAIL mailserv to_addr from_addr messagefile" << endl
		<< "Example: SENDMAIL smtp.myisp.com rcvr@elsewhere.com my_id@mydomain.com message.txt" << endl;

	exit(1);
}

// Basic error checking for send() and recv() functions
void Check(int iStatus, const char *szFunction)
{
	if ((iStatus != SOCKET_ERROR) && (iStatus))
		return;

	cerr << "Error during call to " << szFunction << ": " << iStatus << " - " << GetLastError() << endl;
}

int main(int argc, char *argv[])
{
	int         iProtocolPort = 0;
	char        szSmtpServerName[64] = "";
	char        szToAddr[64] = "";
	char        szFromAddr[64] = "";
	char        szBuffer[4096] = "";
	char        szLine[255] = "";
	char        szMsgLine[255] = "";
	SOCKET      hServer;
	WSADATA     WSData;
	LPHOSTENT   lpHostEntry;
	LPSERVENT   lpServEntry;
	SOCKADDR_IN SockAddr;

	SSL_CTX *ctx;
	const SSL_METHOD *method;
	SSL *ssl;

	INT ret;

	// Check for four command-line args
	if (argc != 5)
		ShowUsage();

	/* initiate ssl library */
	SSL_library_init();
	/* add all algorithms */
	OpenSSL_add_all_algorithms();
	/* load error messages */
	SSL_load_error_strings();
	/* select method */
	method = TLSv1_2_client_method();
	/* create a new context */
	ctx = SSL_CTX_new(method);

	// Load command-line args
	lstrcpy(szSmtpServerName, argv[1]);
	lstrcpy(szToAddr, argv[2]);
	lstrcpy(szFromAddr, argv[3]);

	// Create input stream for reading email message file
	//ifstream MsgFile(argv[4]);

	// Attempt to intialize WinSock (1.1 or later)
	if (WSAStartup(MAKEWORD(VERSION_MAJOR, VERSION_MINOR), &WSData))
	{
		cout << "Cannot find Winsock v" << VERSION_MAJOR << "." << VERSION_MINOR << " or later!" << endl;

		return 1;
	}

	// Lookup email server's IP address.
	lpHostEntry = gethostbyname(szSmtpServerName);
	if (!lpHostEntry)
	{
		cout << "Cannot find SMTP mail server " << szSmtpServerName << endl;

		return 1;
	}

	// Create a TCP/IP socket, no specific protocol
	hServer = socket(PF_INET, SOCK_STREAM, 0);
	if (hServer == INVALID_SOCKET)
	{
		cout << "Cannot open mail server socket" << endl;

		return 1;
	}

	iProtocolPort = htons(465/*IPPORT_SMTP*/);

	// Setup a Socket Address structure
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = iProtocolPort;
	SockAddr.sin_addr = *((LPIN_ADDR)*lpHostEntry->h_addr_list);

	// Connect the Socket
	if (connect(hServer, (PSOCKADDR)&SockAddr, sizeof(SockAddr)))
	{
		cout << "Error connecting to Server socket" << endl;

		return 1;
	}

	/* create a new ssl connection state */
	ssl = SSL_new(ctx);
	/* attach ssl session to socket file descriptor */
	SSL_set_fd(ssl, hServer);
	/* perform the connection */
	if ((ret = SSL_connect(ssl)) != 1) {
		int i = SSL_get_error(ssl, ret);
		return -1;
	}
	
	// Receive initial response from SMTP server
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() Reply");

	// Send HELO server.com
	sprintf(szMsgLine, "HELO %s%s", szSmtpServerName, CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() HELO");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() HELO");

	sprintf(szMsgLine, "AUTH LOGIN%s", CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() HELO");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() HELO");

	memset(szMsgLine, 0, 255);
	char * encoded = Base64Encode((PUCHAR)"matteo.urni@gmail.com", 21);
	sprintf(szMsgLine, "%s%s", Base64Encode((PUCHAR)"matteo.urni@gmail.com", strlen("matteo.urni@gmail.com")), CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() HELO");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() HELO");

	sprintf(szMsgLine, "%s%s", Base64Encode((PUCHAR)"zxcvbnmfgh9056_!", strlen("zxcvbnmfgh9056_!")), CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() HELO");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() HELO");

	// Send MAIL FROM: <sender@mydomain.com>
	sprintf(szMsgLine, "MAIL FROM:<%s>%s", szFromAddr, CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() MAIL FROM");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() MAIL FROM");

	// Send RCPT TO: <receiver@domain.com>
	sprintf(szMsgLine, "RCPT TO:<%s>%s", szToAddr, CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() RCPT TO");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() RCPT TO");

	// Send DATA
	sprintf(szMsgLine, "DATA%s", CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() DATA");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() DATA");

	// Send all lines of message body (using supplied text file)
	//MsgFile.getline(szLine, sizeof(szLine));             // Get first line

	/*do         // for each line of message text...
	{
		sprintf(szMsgLine, "%s%s", szLine, CRLF);
		Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() message-line");
		MsgFile.getline(szLine, sizeof(szLine)); // get next line.
	} while (MsgFile.good());*/

	DWORD n, error;
	HANDLE fileHandle = CreateFileA(argv[4], FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(fileHandle == INVALID_HANDLE_VALUE)
		error = GetLastError();
	DWORD size = GetFileSize(fileHandle, NULL);
	CHAR *file = (PCHAR)malloc(size);
	ReadFile(fileHandle, file, size, &n, NULL);
	CHAR *base64EncodedAttachment = Base64Encode((unsigned char *)file, size);

	SSL_write(ssl, base64EncodedAttachment, (size / 3) * 4 + 5);
	SSL_write(ssl, "\r\n", 2);

	INT k = 0;

	/*do         // for each line of message text...
	{
		strncpy(szMsgLine, base64EncodedAttachment + k, 253);
		snprintf(szMsgLine + 253, 2, "%s", CRLF);
		Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() message-line");
		k += 253;
	} while (k < strlen(base64EncodedAttachment));*/

	// Send blank line and a period
	sprintf(szMsgLine, "%s.%s", CRLF, CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() end-message");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() end-message");

	// Send QUIT
	sprintf(szMsgLine, "QUIT%s", CRLF);
	Check(SSL_write(ssl, szMsgLine, strlen(szMsgLine)), "send() QUIT");
	Check(SSL_read(ssl, szBuffer, sizeof(szBuffer)), "recv() QUIT");

	// Report message has been sent
	cout << "Sent " << argv[4] << " as email message to " << szToAddr << endl;

	// Close server socket and prepare to exit.
	SSL_free(ssl);
	closesocket(hServer);
	SSL_CTX_free(ctx);

	WSACleanup();

	return 0;
}

char *Base64Encode(unsigned char *data, int size) {

	int equal = 0, i = 0, count = 0;
	char base64EncodingString[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned char *output = (unsigned char *)malloc((size / 3) * 4 + 5), intrans[4], outtrans[5];

	memset(output, 0, (64 / 3) * 4 + 5);
	while (count < size) {
		equal = 0;
		for (int k = 0; k < 3; k++) {
			if (count < size) {
				intrans[k] = *data++;
				equal++;
				count++;
			}
			else {
				intrans[k] = 0;
				break;
			}
		}
		outtrans[0] = intrans[0] >> 2;
		outtrans[1] = intrans[1] >> 4 | ((intrans[0] << 4) & 0x3f);
		outtrans[2] = intrans[2] >> 6 | ((intrans[1] << 2) & 0x3f);
		outtrans[3] = intrans[2] & 0x3f;
		if (equal == 3) {
			output[i++] = base64EncodingString[outtrans[0]];
			output[i++] = base64EncodingString[outtrans[1]];
			output[i++] = base64EncodingString[outtrans[2]];
			output[i++] = base64EncodingString[outtrans[3]];
		}
		else if (equal == 2) {
			output[i++] = base64EncodingString[outtrans[0]];
			output[i++] = base64EncodingString[outtrans[1]];
			output[i++] = base64EncodingString[outtrans[2]];
			output[i++] = '=';
		}
		else if (equal == 1) {
			output[i++] = base64EncodingString[outtrans[0]];
			output[i++] = base64EncodingString[outtrans[1]];
			output[i++] = '=';
			output[i++] = '=';
		}
	}
	return (char *)output;
}