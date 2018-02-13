#include "Socket.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define WINDOWS

#ifdef WINDOWS
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma  comment(lib,"ws2_32.lib") 
#else
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#endif

#ifdef ANDROID
#include "API.h"
#define printf LOGI
#endif

Socket::Socket(const char *Server,unsigned short Port,bool IsUDP)
: SS(-1), IsBlocking(true), IsNoDelay(false)
{
  // If server and port given, connect right away
  if(Server && Port) Connect(Server,Port,IsUDP);
  curID = 0;
  SSLenable = 0;
}

Socket::~Socket()
{
  // Close socket, if open
  Close(SS);
}

bool Socket::SetBlocking(bool Switch)
{
  if(SS<0) return(false);
  if(Switch==IsBlocking) return(true);

  // Make communication socket blocking/non-blocking
#ifdef WINDOWS
   unsigned long J = Switch? 0:1;
  if(ioctlsocket(SS,FIONBIO,&J)<0) return(false);
#else
    int J = Switch? 0:1;
  if(ioctl(SS,FIONBIO,&J)<0) return(false);
#endif
  IsBlocking = Switch;
  return(true);
}

bool Socket::SetNoDelay(bool Switch)
{
  if(SS<0) return(false);
  if(Switch==IsNoDelay) return(true);

  // Enable/disable Nagle algorithm
  #ifdef WINDOWS
  const char J = Switch? 1:0;
    if(setsockopt(SS,IPPROTO_TCP,TCP_NODELAY,&J,sizeof(J))<0) return(false);
#else
  int J = Switch? 1:0;
  if(setsockopt(SS,SOL_TCP,TCP_NODELAY,&J,sizeof(J))<0) return(false);
#endif
  IsNoDelay = Switch;
  return(true);
}

bool Socket::SetRecvBuffer(int BufLeng)
{
  return setsockopt(SS,SOL_SOCKET,SO_RCVBUF,(const char*)&BufLeng,sizeof(int));
}

int Socket::GetRecvBuffer()
{
  int opt;
  socklen_t len=sizeof(int); 
  if (getsockopt(SS,SOL_SOCKET,SO_RCVBUF,(char *)&opt,&len)<0)
  {
    printf("getsockopt() Error. errno=%d\n", errno);
    return -1;
  }
  return opt;
}

void Socket::Close(int SS)
{
	if (SSLenable)
	{
		for (int i=0; i<curID; i++)
		{
			SSL_shutdown(ssl_client_list[i]);
			SSL_free(ssl_client_list[i]);
		}
		curID = 0;
	}

#ifdef WINDOWS
	if(SS>=0) { closesocket(SS);SS=-1; }
#else
  if(SS>=0) { close(SS);SS=-1; }
#endif
}

void Socket::Close()
{
	if (SSLenable)
	{
		for (int i=0; i<curID; i++)
		{
			SSL_shutdown(ssl_client_list[i]);
			SSL_free(ssl_client_list[i]);
		}
		curID = 0;
	}

#ifdef WINDOWS
	if(SS>=0) { closesocket(SS);SS=-1; }
#else
  if(SS>=0) { close(SS);SS=-1; }
#endif
}

bool Socket::Connect(const char *Server,unsigned short Port,bool IsUDP)
{
  struct sockaddr_in Addr;
  struct hostent *Host;
  socklen_t AddrLength;
  int SSocket;
  struct timeval TV;
  fd_set FDs;

  PPort = Port;

#ifdef WINDOWS
  WORD sockVersion = MAKEWORD(2,2);  
  WSADATA data;   
  if(WSAStartup(sockVersion, &data) != 0)  
  {  
      return 0;  
  }  
#endif
  
  // If socket open, close it
  Close(SS);

  // Clear the address structure
  memset(&Addr,0,sizeof(Addr));

  // If connecting to a server...
  if(Server)
  {
    // Look up server address
    if(!(Host=gethostbyname(Server)))
    {
#ifdef WINDOWS
      printf("Socket::Connect(): Failed address lookup\n");
#else
      printf("Socket::Connect(): Failed address lookup for '%s' (%s)\n",Server,strerror(errno));
#endif
      return(false);
    }

    // Set fields of the address structure
    memcpy(&Addr.sin_addr,Host->h_addr,Host->h_length);
    Addr.sin_family = AF_INET;
    Addr.sin_port   = htons(Port);

    // Create a socket
    if((SSocket=socket(AF_INET,IsUDP? SOCK_DGRAM:SOCK_STREAM,IsUDP? IPPROTO_UDP:IPPROTO_TCP))<0)
    {
#ifdef WINDOWS
      printf("Socket::Connect(): Failed creating socket\n");
#else
      printf("Socket::Connect(): Failed creating socket (%s)\n",strerror(errno));
#endif
      return(false);
    }

	printf("Socket::Connecting...\n");
    // Connecting...
    if(connect(SSocket,(struct sockaddr *)&Addr,sizeof(Addr))<0)
    {
#ifdef WINDOWS
    printf("Socket::Connect(): Failed to connect to the server\n");
	closesocket(SSocket);
#else
    printf("Socket::Connect(): Failed to connect to the server (%s)\n",strerror(errno));
    close(SSocket);
#endif
      return(false);
    }
  }
  else
  {
    //
    // No server address given, becoming a server
    //

    // Set fields of the address structure
    Addr.sin_addr.s_addr = htonl(INADDR_ANY);
    Addr.sin_family      = AF_INET;
    Addr.sin_port        = htons(Port);

    // Create a listening socket
    if((LSocket=socket(AF_INET,SOCK_STREAM,0))<0)
    {
#ifdef WINDOWS
      printf("Socket::Connect(): Failed creating listening socket %d\n", LSocket);
#else
      printf("Socket::Connect(): Failed creating listening socket (%s)\n",strerror(errno));
#endif
      return(false);
    }

    // Bind listening socket
    if(bind(LSocket,(struct sockaddr *)&Addr,sizeof(Addr))<0)
    {
#ifdef WINDOWS
    printf("Socket::Connect(): Failed binding listening socket\n");
	closesocket(LSocket);
#else
    printf("Socket::Connect(): Failed binding listening socket (%s)\n",strerror(errno));
    close(LSocket);
#endif
      return(false);
    }

    // Listen for one client
    if(listen(LSocket,1)<0)
    {
#ifdef WINDOWS
    printf("Socket::Connect(): Failed listen() call\n");
	closesocket(LSocket);
#else
    printf("Socket::Connect(): Failed listen() call (%s)\n",strerror(errno));
    close(LSocket);
#endif
      return(false);
    }

    // We will need address length
    AddrLength=sizeof(Addr);

    // No sockets yet

	SSocket = 1;
    // Accepting calls...
    /*for(SSocket=-1;SSocket<0;)
    {
      // Prepare data for select()
      FD_SET(LSocket,&FDs);
      TV.tv_sec  = 0;
      TV.tv_usec = 100000;
      // Listen and accept connection
      if(select(LSocket+1,&FDs,0,0,&TV)>0)
        SSocket=accept(LSocket,(struct sockaddr *)&Addr,&AddrLength);
    }

    // Done listening
#ifdef WINDOWS
	closesocket(LSocket);
#else
    close(LSocket);
#endif

    // Client failed to connect
    if(SSocket<0)
    {
#ifdef WINDOWS
      printf("Socket::Connect(): Failed to connect to a client\n");
#else
      printf("Socket::Connect(): Failed to connect to a client (%s)\n",strerror(errno));
#endif
      return(false);
    }*/
  }

  // Connected socket
  SS=SSocket;
  if(!IsBlocking) { IsBlocking=true;SetBlocking(false); }
  if(IsNoDelay)   { IsNoDelay=false;SetNoDelay(true); }
  return(true);
}

int Socket::Accept()
{
	int SSocket = -1;
	struct sockaddr_in Addr;
	socklen_t AddrLength;

	// Set fields of the address structure
    Addr.sin_addr.s_addr = htonl(INADDR_ANY);
    Addr.sin_family      = AF_INET;
    Addr.sin_port        = htons(PPort);
    // We will need address length
    AddrLength=sizeof(Addr);
	
    SSocket=accept(LSocket,(struct sockaddr *)&Addr,&AddrLength);
	return SSocket;
}

int Socket::GetSockfd()
{
	return SS;
}

SSL *Socket::findSSLCtx(int socket_fd)
{
	for (int i=0; i<MAXPAIRNUM; i++)
	{
		if (socket_fd == client_socket_fd_list[i])
			return ssl_client_list[i];
	}

	return 0;
}

int Socket::setSSLenable(bool enable)
{
	SSLenable = enable;
	return 1;
}

int Socket::setSSLpair(SSL *ssl, int socket_fd)
{
	ssl_client_list[curID] = ssl;
	client_socket_fd_list[curID] = socket_fd;
	curID++;

	return 1;
}

int Socket::Send(int SS, const void *Buf,int Size)
{
	if (!SSLenable)
	{
		int pos = 0;
		while (pos < Size)
		{
			pos += send(SS,(const char *)Buf+pos,Size-pos,0);
		}
		return pos;
	}
	else
	{
		SSL *ssl = findSSLCtx(SS);
		int pos = 0;
		while (pos < Size)
		{
			pos += SSL_write(ssl,(const char *)Buf+pos,Size-pos);
		}
  
	  return pos;
	}
}

int Socket::Recv(int SS, void *Buf,int Size)
{
	if (!SSLenable)
	{
		int Result = SS<0? -1:recv(SS,(char *)Buf,Size,0);

		return(Result>0? Result:0);
	}
	else
	{
		SSL *ssl = findSSLCtx(SS);
		int Result = SSL_read(ssl,(char *)Buf,Size);

		return Result;
	}
}

int Socket::Send(const void *Buf,int Size)
{
	int tempSize;
	int tempPos;
	int sizeLeft = Size;
	int sendLength;
	if (!SSLenable)
	{
		int pos = 0;
		while (pos < Size)
		{
			tempSize = 1340 < sizeLeft ? 1340 : sizeLeft;
			tempPos = 0;
			while (tempPos < tempSize)
			{
				sendLength = send(SS,(const char *)Buf+pos+tempPos,tempSize-tempPos,0);
				if (sendLength < 0)
				{
					printf("Send Error! Error code: %i\n", GetLastError());
					exit(-1);
				}
				tempPos += sendLength;
			}
			pos += tempPos;
			sizeLeft = Size - pos;
			//printf("\r %.2f %%", pos/(double)Size*100);
		}
		//printf("\n");
		return pos;
	}
	else
	{
		SSL *ssl = findSSLCtx(SS);
		int pos = 0;
		while (pos < Size)
		{
			tempSize = 1340 < sizeLeft ? 1340 : sizeLeft;
			tempPos = 0;
			while (tempPos < tempSize)
			{
				sendLength = SSL_write(ssl,(const char *)Buf+pos+tempPos,tempSize-tempPos);
				if (sendLength < 0)
				{
					printf("Send Error! Error code: %i\n", GetLastError());
					exit(-1);
				}
				tempPos += sendLength;
			}
			pos += tempPos;
			sizeLeft = Size - pos;
			//printf("\r %.2f %%", pos/(double)Size*100);
		}
		//printf("\n");
		return pos;
	}
}

int Socket::Recv(void *Buf,int Size)
{
	if (!SSLenable)
	{
		int Result = SS<0? -1:recv(SS,(char *)Buf,Size,0);

		return Result;
	}
	else
	{
		SSL *ssl = findSSLCtx(SS);
		int Result = SSL_read(ssl,(char *)Buf,Size);

		return Result;
	}
}

int Socket::SendInitInfo(int SS, const void *Buf,int Size)
{
	int pos = 0;
	while (pos < Size)
	{
		pos += send(SS,(const char *)Buf+pos,Size-pos,0);
	}
	return pos;
}

int Socket::RecvInitInfo(int SS, void *Buf,int Size)
{
	int Result = SS<0? -1:recv(SS,(char *)Buf,Size,0);

	return Result;
}