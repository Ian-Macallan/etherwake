// etherwake.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include "etherwake.h"

#include <Windows.h>

#include <winsock2.h>
#include <ws2tcpip.h>
// #include <mstcpip.h>
#include <icmpapi.h>

#include "AutomaticVersionHeader.h"

#include "strstr.h"
#include "PrintRoutine.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define LEN_TEXT_256    256
#define LEN_TEXT_1024   1024
#define LEN_TEXT_8192   8192

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
#ifndef _wsizeof
#define _wsizeof(x) (sizeof(x)/sizeof(WCHAR))
#endif

#define LEN_PATHNAME        280
#define NAMEANDWSIZE(x)     x,sizeof(x)/sizeof(WCHAR)

//
//      Process Creation
#define PROCESS_CREATION_FAILED     0xff
#define PROCESS_NOT_INVOKED         0xfe

//
const   WCHAR   *READ_BIN_MODE  = L"rb";
const   WCHAR   *READ_MODE      = L"r, ccs=UNICODE";
const   WCHAR   *WRITE_MODE     = L"w";
const   WCHAR   *WRITE_BIN_MODE = L"wb";

const   WCHAR   *NULL_MAC_ADDR = L"00:00:00:00:00:00";
const   WCHAR   *BROADCAST_ADDR = L"FF:FF:FF:FF:FF:FF";

//
#define LEN_MAGIC_PACKET    102
static  BYTE    MagicWakePacket[LEN_MAGIC_PACKET];

#define LEN_MAC             6
static  BYTE    MacAddress [ LEN_MAC ];
static  WCHAR   MacAddressString [ LEN_MAC * 4 ];

static  WCHAR   IpV4StringW [ 64 ];
static  WCHAR   IpV6StringW [ 128 ];

static  char    IpV4StringA [ 64 ];
static  char    IpV6StringA [ 128 ];

static  WCHAR   ResolvedHostname [ 256 ];

static  WCHAR   NameServer [ LEN_TEXT_256 ] = L"";

//
//
PDNS_ADDR_ARRAY     DNSArrayPtr             = NULL;
DNS_ADDR_ARRAY      DNSArray;

PIP4_ARRAY          DNS4ArrayPtr            = NULL;
IP4_ARRAY           DNS4Array;

//
static WCHAR    szHostName [ LEN_TEXT_256 ];

#define MAX_LENGTH          4096
static  WCHAR   AddressSearched [ MAX_LENGTH ] = L"";
static  WCHAR   MacFound [ MAX_LENGTH ] = L"";
static  WCHAR   szErrorText [ MAX_LENGTH ] = L"";
static  WCHAR   QueryType [ MAX_LENGTH ] = L"";
static  WCHAR   Subnet [ MAX_LENGTH ] = L"";

//  Action
static  bool    DoAction            = false;
static  bool    DoMac               = false;
static  bool    DoArp               = false;
static  bool    DoArp6              = false;
static  bool    DoAdapter           = false;
static  bool    DoAdapter6          = false;
static  bool    DoList              = false;
static  bool    DoWake              = false;
static  bool    DoQuery             = false;

//  Flags
static  bool    IPv4Only            = false;
static  bool    IPv6Only            = false;
static  bool    NonZeroMac          = false;
static  bool    IPUp                = false;
static  bool    IPDown              = false;
static  bool    ResolveMode         = false;
static  bool    UseDns              = false;
static  bool    DnsQueryExMode      = false;
static  bool    PingMode            = false;
static  bool    PingSubnetMode      = false;
static  bool    PingListMode        = false;
static  bool    IPMatchMac          = false;

//
static  WCHAR   ModuleFileName [ MAX_LENGTH ] = L"";
static  WCHAR   InitFileName [ MAX_LENGTH ] = L"";
static  WCHAR   ArpFileName [ MAX_LENGTH ] = L"";
static  WCHAR   ExecuteCommand [ MAX_LENGTH ] = L"";
static  WCHAR   LocaleString [ MAX_LENGTH ] = L"";

static  WCHAR   PingFileName [ MAX_LENGTH ] = L"";

static  WCHAR   LineReadW [ MAX_LENGTH ] = L"";

static  int     FirstMacAddress = 1;
static  DWORD   PingTimeOut = 2;

//
struct IP_STRUCT
{
    int binaryLength;
    union
    {
        IN_ADDR inAddr;
        IN6_ADDR inAddr6;
    } binaryData;
};

//
//  UP Address, Mac Address, hostname
#define LEN_IP_ARP          64
struct ArpItem
{
    WCHAR IPAddress [ LEN_IP_ARP ];
    IP_STRUCT   IP;
    WCHAR MacAddress [ LEN_IP_ARP ];
    WCHAR HostName [ LEN_IP_ARP ];
    int IPVersion;
};

#define MAX_ARP_LIST        (8*1024)
int     ArpListCount        = 0;
bool    ArpListUpdated      = false;
ArpItem ArpList [ MAX_ARP_LIST ];

//
//  Subnet
struct SubnetItem
{
    WCHAR IPAddress [ LEN_IP_ARP ];
    WCHAR IPMask [ LEN_IP_ARP ];
    IN_ADDR IP;
    IN_ADDR Mask;
};
#define MAX_SUBNET_LIST     64
int     SubnetListCount     = 0;
SubnetItem SubnetList [ MAX_SUBNET_LIST ];


//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
#define USE_RTL_STRING_TO_IP4       0

#if USE_RTL_STRING_TO_IP4
typedef  LONG (NTAPI *RtlIpv4StringToAddressWType)( _In_ PCWSTR S, _In_ BOOLEAN Strict, _Out_ LPCWSTR *Terminator, _Out_ struct in_addr *Addr );
RtlIpv4StringToAddressWType RtlIpv4StringToAddressW = NULL;
#endif

//  DnsQueryEx
typedef DNS_STATUS ( WINAPI *DnsQueryExType )( _In_ PDNS_QUERY_REQUEST pQueryRequest, _Inout_ PDNS_QUERY_RESULT pQueryResults,
                                                _Inout_opt_ PDNS_QUERY_CANCEL pCancelHandle );
DnsQueryExType  RuntimeDnsQueryEx = NULL;

//  RtlIpv4AddressToStringW
typedef PWSTR ( NTAPI *RtlIpv4AddressToStringWType ) ( _In_ const IN_ADDR *Addr, _Out_ WCHAR *S ) ;
RtlIpv4AddressToStringWType RtlIpv4AddressToStringW = NULL;

//  RtlIpv6AddressToStringW
typedef PWSTR ( NTAPI *RtlIpv6AddressToStringWType ) ( _In_ const IN6_ADDR *Addr, _Out_ WCHAR *S ) ;
RtlIpv6AddressToStringWType RtlIpv6AddressToStringW = NULL;

//  RtlIpv4AddressToStringExW
typedef LONG ( NTAPI *RtlIpv4AddressToStringExWType)( _In_ const IN_ADDR *Address, _In_ USHORT Port,
                                                        _Out_ LPWSTR AddressString, _Inout_ PULONG AddressStringLength );
RtlIpv4AddressToStringExWType   RtlIpv4AddressToStringExW = NULL;

//  RtlIpv6AddressToStringExW
typedef LONG ( NTAPI *RtlIpv6AddressToStringExWType)( _In_ const IN6_ADDR *Address, _In_ ULONG ScopeId, _In_ USHORT Port,
                                                        _Out_ LPWSTR AddressString, _Inout_ PULONG AddressStringLength );
RtlIpv6AddressToStringExWType   RtlIpv6AddressToStringExW = NULL;

//  Not Used
typedef LONG ( NTAPI *RtlIpv4StringToAddressExWType )( _In_ PCWSTR AddressString, _In_ BOOLEAN Strict,
                                                        _Out_ IN_ADDR *Address, _Out_ PUSHORT Port );
RtlIpv4StringToAddressExWType RtlIpv4StringToAddressExW = NULL;

typedef LONG ( NTAPI *RtlIpv6StringToAddressExWType )( _In_ PCWSTR AddressString, _Out_ IN6_ADDR *Address,
                                                        _Out_ PULONG ScopeId, _Out_ PUSHORT Port );
RtlIpv6StringToAddressExWType RtlIpv6StringToAddressExW = NULL;

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void MacAddressToString ( BYTE macAddress [], ULONG length )
{
    ZeroMemory ( MacAddressString, sizeof(MacAddressString) );
    for ( ULONG i = 0; i < length; i++ )
    {
        swprintf(MacAddressString + wcslen(MacAddressString), _wsizeof(MacAddressString) - wcslen(MacAddressString), L"%02X", macAddress [ i ] );
        if( i != length - 1 )
        {
            swprintf(MacAddressString + wcslen(MacAddressString), _wsizeof(MacAddressString) - wcslen(MacAddressString), L":" );
        }
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL convertHexa1 ( WCHAR digit, BYTE *halfByte )
{
    if ( digit >= L'0' && digit <= L'9' )
    {
        *halfByte = digit - '0';
    }
    else if ( digit >= L'A' && digit <= L'F' )
    {
        *halfByte = digit - 'A' + 10;
    }
    else if ( digit >= L'a' && digit <= L'f' )
    {
        *halfByte = digit - 'a' + 10;
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL convertHexa2 ( WCHAR *pText, BYTE *oneByte )
{
    BYTE cHigh;
    BYTE cLow;
    BOOL bDone = convertHexa1  ( pText [ 0 ], &cHigh );
    if ( ! bDone )
    {
        return FALSE;
    }
    bDone = convertHexa1  ( pText [ 1 ], &cLow );
    if ( ! bDone )
    {
        return FALSE;
    }

    *oneByte = ( (WORD) cHigh ) << 4 | cLow;

    return TRUE;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL convertMAC ( WCHAR *pMacAddress )
{
    int macIndex = 0;
    for ( size_t i = 0; i < wcslen(pMacAddress); i++ )
    {
        BYTE oneByte;
        BOOL bDone = convertHexa2 ( pMacAddress + i, &oneByte );
        if ( ! bDone )
        {
            PrintStderrW ( L"Error : MAC Address error %s at '%c%c'\n", pMacAddress, pMacAddress [ i ], pMacAddress [ i + 1 ] );
            return FALSE;
        }

        if ( macIndex >= LEN_MAC )
        {
            PrintStderrW ( L"Error : MAC Address too long\n");
            return FALSE;
        }

        MacAddress [ macIndex ] = oneByte;
        macIndex++;
        i += 2;
        if ( pMacAddress [ i ] != L'-' && pMacAddress [ i ] != L':' && pMacAddress [ i ] != L'\0' )
        {
            return FALSE;
        }
    }

    if ( macIndex != 6 )
    {
        PrintStderrW ( L"Error : MAC Address too short %d\n", macIndex );
        return FALSE;
    }

    return true;
}

//
//====================================================================================
//      Get Numeric INetAddr
//====================================================================================
INT GetINetAddr4 ( WCHAR *pAddress, sockaddr_in *pSockaddr )
{
    memset ( pSockaddr, 0, sizeof(sockaddr_in));
    INT     iSockaddr = sizeof(sockaddr_in);
    INT iResult = WSAStringToAddress(
        pAddress,                       //  _In_      LPTSTR AddressString,
        AF_INET,                        //  _In_      INT AddressFamily,
        NULL,                           //  _In_opt_  LPWSAPROTOCOL_INFO lpProtocolInfo,
        (LPSOCKADDR ) pSockaddr,        //  _Out_     LPSOCKADDR lpAddress,
        &iSockaddr                      //  _Inout_   LPINT lpAddressLength
    );

    return iResult;
}

//
//====================================================================================
//      Get Numeric INetAddr
//====================================================================================
INT GetINetAddr6 ( WCHAR *pAddress, sockaddr_in6 *pSockaddr )
{
    memset ( pSockaddr, 0, sizeof(sockaddr_in6));
    INT     iSockaddr = sizeof(sockaddr_in6);
    INT iResult = WSAStringToAddress(
        pAddress,                       //  _In_      LPTSTR AddressString,
        AF_INET6,                       //  _In_      INT AddressFamily,
        NULL,                           //  _In_opt_  LPWSAPROTOCOL_INFO lpProtocolInfo,
        (LPSOCKADDR ) pSockaddr,        //  _Out_     LPSOCKADDR lpAddress,
        &iSockaddr                      //  _Inout_   LPINT lpAddressLength
    );

    return iResult;
}

//
//====================================================================================
//      Get Numeric INetAddr
//====================================================================================
INT GetINetAddr4 ( WCHAR *pAddress, IN_ADDR *pInAddr )
{
    sockaddr_in sockAddr;
    memset ( &sockAddr, 0, sizeof(sockAddr));
    INT     iSockaddr = sizeof(sockAddr);
    INT iResult = WSAStringToAddress(
        pAddress,                       //  _In_      LPTSTR AddressString,
        AF_INET,                        //  _In_      INT AddressFamily,
        NULL,                           //  _In_opt_  LPWSAPROTOCOL_INFO lpProtocolInfo,
        (LPSOCKADDR ) &sockAddr,        //  _Out_     LPSOCKADDR lpAddress,
        &iSockaddr                      //  _Inout_   LPINT lpAddressLength
    );

    *pInAddr = sockAddr.sin_addr;

    return iResult;
}

//
//====================================================================================
//      Get Numeric INetAddr
//====================================================================================
INT GetINetAddr6 ( WCHAR *pAddress, IN6_ADDR *pInAddr )
{
    sockaddr_in6 sockAddr;
    memset ( &sockAddr, 0, sizeof(sockAddr));
    INT     iSockaddr = sizeof(sockAddr);
    INT iResult = WSAStringToAddress(
        pAddress,                       //  _In_      LPTSTR AddressString,
        AF_INET6,                       //  _In_      INT AddressFamily,
        NULL,                           //  _In_opt_  LPWSAPROTOCOL_INFO lpProtocolInfo,
        (LPSOCKADDR ) &sockAddr,        //  _Out_     LPSOCKADDR lpAddress,
        &iSockaddr                      //  _Inout_   LPINT lpAddressLength
    );

    *pInAddr = sockAddr.sin6_addr;

    return iResult;
}

//
//====================================================================================
//  Return 0 if error
//====================================================================================
int PingAddress ( WCHAR *pIPAddress )
{
    //
    // Declare and initialize variables

    //  IPV4
    if ( wcschr ( pIPAddress, L':' ) == NULL && wcschr ( pIPAddress, L'.' ) != NULL )
    {
        HANDLE hIcmpFile            = NULL;
        DWORD dwRetVal              = 0;
        char SendData[32]           = "Data Buffer";
        const DWORD ReplySize       = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);;
        char ReplyBuffer [ ReplySize ];

        // Validate the parameters
        IN_ADDR inAddr;
        ZeroMemory ( &inAddr, sizeof(inAddr));
        int iRes = GetINetAddr4(pIPAddress, &inAddr);
        if ( iRes != 0 || inAddr.S_un.S_addr == INADDR_NONE )
        {
            PrintStderr( L"Error on %s\n", pIPAddress);
            return 0;
        }

        hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE)
        {
            PrintStderr( L"Unable to open handle. IcmpCreatefile returned error: %ld\n", GetLastError() );
            return 0;
        }

        //  Timeout 5 Milliseconds is enough for local
        dwRetVal = IcmpSendEcho(hIcmpFile, inAddr.S_un.S_addr, SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, PingTimeOut);
        if (dwRetVal != 0)
        {
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
            struct in_addr ReplyAddr;
            ReplyAddr.S_un.S_addr = pEchoReply->Address;
            PrintVerbose ( L"\n> Sent icmp message to %s\n", pIPAddress);
            if (dwRetVal > 1)
            {
                PrintVerbose ( L"< Received %ld icmp message responses - Information from the first response - ", dwRetVal);
            }
            else
            {
                PrintVerbose ( L"< Received %ld icmp message response - Information from this response - ", dwRetVal);
            }
#if _MSC_VER < 1 // 1800
            PrintVerboseA ( "Received from %s\n", inet_ntoa( ReplyAddr ) );
#else
            WCHAR szAddress [ 64 ];
            PCTSTR lpwStr = InetNtop(
                AF_INET,                // _In_   INT  Family,
                (PVOID) &ReplyAddr,     // _In_   PVOID pAddr,
                szAddress,              //   _Out_  PTSTR pStringBuf,
                _wsizeof(szAddress)     //  _In_   size_t StringBufSize
            );
            PrintVerboseW ( L"Received from %s\n", szAddress );
#endif
            PrintVerbose ( L"< Status = %ld - Roundtrip time = %ld milliseconds\n", pEchoReply->Status, pEchoReply->RoundTripTime);
        }
        else
        {
            PrintVerbose ( L"Call to IcmpSendEcho failed - IcmpSendEcho returned error: %ld\n", GetLastError() );
            return 0;
        }
    }
    //  IPV6
    else if ( wcschr ( pIPAddress, L':' ) != NULL )
    {
        HANDLE hIcmpFile            = NULL;
        DWORD dwRetVal              = 0;
        char SendData[32]           = "Data Buffer";
        const DWORD ReplySize       = sizeof(ICMPV6_ECHO_REPLY) + sizeof(SendData);;
        char ReplyBuffer [ ReplySize ];

        ICMP6_ECHO_REPLY;
        // Validate the parameters
        sockaddr_in6    inAddrSource;
        ZeroMemory ( &inAddrSource, sizeof(inAddrSource));
        int iRes = GetINetAddr6(L"::", &inAddrSource);
        if ( iRes != 0 )
        {
            PrintStderr( L"Error on %s\n", pIPAddress);
            return 0;
        }

        sockaddr_in6    inAddrTarget;
        ZeroMemory ( &inAddrTarget, sizeof(inAddrTarget));
        iRes = GetINetAddr6(pIPAddress, &inAddrTarget);
        if ( iRes != 0 )
        {
            PrintStderr( L"Error on %s\n", pIPAddress);
            return 0;
        }

        hIcmpFile = Icmp6CreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE)
        {
            PrintStderr( L"Unable to open handle. IcmpCreatefile returned error: %ld\n", GetLastError() );
            return 0;
        }

        //  Timeout 5 Milliseconds is enough for local*
        IP_OPTION_INFORMATION   RequestOptions;
        ZeroMemory ( &RequestOptions, sizeof(RequestOptions) );

        //
        dwRetVal =
            Icmp6SendEcho2(
              hIcmpFile,                //  _In_      HANDLE IcmpHandle,
              NULL,                     //  _In_opt_  HANDLE Event,
              NULL,                     //  _In_opt_  PIO_APC_ROUTINE ApcRoutine,
              NULL,                     //  _In_opt_  PVOID ApcContext,
              &inAddrSource,            //  _In_      struct sockaddr_in6 *SourceAddress,
              &inAddrTarget,            //  _In_      struct sockaddr_in6 *DestinationAddress,
              SendData,                 //  _In_      LPVOID RequestData,
              sizeof(SendData),         //  _In_      WORD RequestSize,
              NULL,                     //  _In_opt_  PIP_OPTION_INFORMATION RequestOptions,
              ReplyBuffer,              //  _Out_     LPVOID ReplyBuffer,
              ReplySize,                //  _In_      DWORD ReplySize,
              PingTimeOut               //  _In_      DWORD Timeout
            );

        if (dwRetVal != 0)
        {
            PICMPV6_ECHO_REPLY pEchoReply = (PICMPV6_ECHO_REPLY)ReplyBuffer;
            PrintVerbose ( L"\n> Sent icmp message to %s\n", pIPAddress);
            if (dwRetVal > 1)
            {
                PrintVerbose ( L"< Received %ld icmp message responses - Information from the first response - ", dwRetVal);
            }
            else
            {
                PrintVerbose ( L"< Received %ld icmp message response - Information from this response - ", dwRetVal);
            }

            SOCKADDR_IN6  sockAddrIn6;
            ZeroMemory ( &sockAddrIn6, sizeof(sockAddrIn6) );

            sockAddrIn6.sin6_family = AF_INET6;
            sockAddrIn6.sin6_flowinfo   = pEchoReply->Address.sin6_flowinfo;
            sockAddrIn6.sin6_port       = pEchoReply->Address.sin6_port;
            sockAddrIn6.sin6_scope_id   = pEchoReply->Address.sin6_scope_id;
            memcpy ( sockAddrIn6.sin6_addr.u.Byte, pEchoReply->Address.sin6_addr, sizeof(sockAddrIn6.sin6_addr.u.Byte) );

            //
            WCHAR szAddress [ 64 ];
            ZeroMemory ( szAddress, sizeof(szAddress) );
            DWORD   dwReturned = _wsizeof(szAddress);

            INT iRes =  WSAAddressToString(
                (LPSOCKADDR)&sockAddrIn6,                   //  LPSOCKADDR          lpsaAddress,
                sizeof(sockAddrIn6),                        //  DWORD               dwAddressLength,
                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                szAddress,                                  //  LPSTR               lpszAddressString,
                &dwReturned                                 //  LPDWORD             lpdwAddressStringLength
                );

            if ( iRes != 0 )
            {
                int wsaError = WSAGetLastError();
                PrintStderrW ( L"Error from 0x%x\n", wsaError );
            }
            PrintVerbose ( L"Received from %s\n", szAddress );
            PrintVerbose ( L"< Status = %ld - Roundtrip time = %ld milliseconds\n", pEchoReply->Status, pEchoReply->RoundTripTime);
        }
        else
        {
            PrintVerbose ( L"Call to IcmpSendEcho failed - IcmpSendEcho returned error: %ld\n", GetLastError() );
            return 0;
        }
    }
    return 1;
}

//
//====================================================================================
//
//====================================================================================
bool IsInsideSubnet ( WCHAR *pIPAddress )
{
    IN_ADDR inAddr;
    ZeroMemory ( &inAddr, sizeof(inAddr) );

    GetINetAddr4 ( pIPAddress, &inAddr );

    for ( int i = 0; i < SubnetListCount; i++ )
    {
        ULONG ul = ( inAddr.S_un.S_addr ^ SubnetList [ i ].IP.S_un.S_addr );
        ul = ul & SubnetList [ i ].Mask.S_un.S_addr;
        if ( ul == 0 )
        {
            return true;
        }
    }

    return false;
}

//
//====================================================================================
//      Format Message
//====================================================================================
void FormatErrorMessage ( DWORD dwMessageId )
{
    ZeroMemory ( szErrorText, sizeof(szErrorText) );

    //
    HRESULT hResult     = HRESULT_FROM_WIN32(dwMessageId);
    WCHAR   *lpBuffer   = NULL;

    DWORD   dwFlags =   FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD dwResult = FormatMessage (
        dwFlags,                //  DWORD dwFlags,
        NULL,                   //  LPCVOID lpSource,
        dwMessageId,            //  DWORD dwMessageId,
        NULL,                   //  DWORD dwLanguageId,
        (LPTSTR) &lpBuffer,     //  LPTSTR lpBuffer,
        NULL,                   //  DWORD nSize,
        NULL                    //  va_list* Arguments
    );

    if ( dwResult <= 0 )
    {
        DWORD dwOtherError = GetLastError ();
        hResult = HRESULT_FROM_WIN32(dwOtherError);
    }

    if ( lpBuffer != NULL )
    {
        wcscpy_s ( szErrorText, _wsizeof (szErrorText), lpBuffer );
        LocalFree ( lpBuffer );
    }
}

//
////////////////////////////////////////////////////////////////////////
//      Search Init File
////////////////////////////////////////////////////////////////////////
bool SearchInitFile ( WCHAR *pInitFileName, size_t iInitFileName )
{
    WCHAR   initName [ LEN_PATHNAME ];
    WCHAR   initPathName [ LEN_PATHNAME ];
    WCHAR   *pVariable      = NULL;
    size_t  requiredSize    = 0;

    wcscpy_s ( NAMEANDWSIZE(initName), FindFileName ( pInitFileName ) );

    //
    //      First If ini file is here.
    if ( CheckPathExistW ( pInitFileName ) )
    {
        return true;
    }

    //
    //      Then Search Environnement
    _wgetenv_s ( &requiredSize, NULL, 0, L"PATH" );
    if ( requiredSize == 0 )
    {
        return false;
    }

    //
    size_t  iVariable   = ( requiredSize + 1 ) * sizeof(WCHAR) + 1;
    pVariable   = ( WCHAR * ) malloc ( iVariable );

    _wgetenv_s ( &requiredSize, pVariable, requiredSize + 1, L"PATH" );

    //      Treat Token for PATH
    WCHAR   strDelimit[]   = L";";
    WCHAR   *strToken   = NULL;
    WCHAR   *context    = NULL;

    //
    //      Treat Tokens
    strToken = wcstok_s ( pVariable, strDelimit, &context);
    while( strToken != NULL )
    {
        //
        //      Test Filename
        wcscpy_s ( NAMEANDWSIZE(initPathName), strToken );
        if ( ! EndsWithI ( initPathName, L"\\" ) )
        {
            wcscat_s ( NAMEANDWSIZE(initPathName), L"\\" );
        }
        wcscat_s ( NAMEANDWSIZE(initPathName), initName );

        if ( CheckPathExistW ( initPathName ) )
        {
            wcscpy_s ( InitFileName, iInitFileName, initPathName );
            free ( pVariable );
            return true;
        }

        //      Get next token:
        strToken = wcstok_s( NULL, strDelimit, &context);
    }

    free ( pVariable );

    return false;
}

//
////////////////////////////////////////////////////////////////////////
//      Search Init File
////////////////////////////////////////////////////////////////////////
bool SearchArpFile ( WCHAR *pArpFileName, size_t iArpFileName )
{
    WCHAR   initName [ LEN_PATHNAME ];
    WCHAR   initPathName [ LEN_PATHNAME ];
    WCHAR   *pVariable      = NULL;
    size_t  requiredSize    = 0;

    wcscpy_s ( NAMEANDWSIZE(initName), FindFileName ( pArpFileName ) );

    //
    //      First If ini file is here.
    if ( CheckPathExistW ( pArpFileName ) )
    {
        return true;
    }

    //
    //      Then Search Environnement
    _wgetenv_s ( &requiredSize, NULL, 0, L"PATH" );
    if ( requiredSize == 0 )
    {
        return false;
    }

    //
    size_t  iVariable   = ( requiredSize + 1 ) * sizeof(WCHAR) + 1;
    pVariable   = ( WCHAR * ) malloc ( iVariable );

    _wgetenv_s ( &requiredSize, pVariable, requiredSize + 1, L"PATH" );

    //      Treat Token for PATH
    WCHAR   strDelimit[]   = L";";
    WCHAR   *strToken   = NULL;
    WCHAR   *context    = NULL;

    //
    //      Treat Tokens
    strToken = wcstok_s ( pVariable, strDelimit, &context);
    while( strToken != NULL )
    {
        //
        //      Test Filename
        wcscpy_s ( NAMEANDWSIZE(initPathName), strToken );
        if ( ! EndsWithI ( initPathName, L"\\" ) )
        {
            wcscat_s ( NAMEANDWSIZE(initPathName), L"\\" );
        }
        wcscat_s ( NAMEANDWSIZE(initPathName), initName );

        if ( CheckPathExistW ( initPathName ) )
        {
            wcscpy_s ( ArpFileName, iArpFileName, initPathName );
            free ( pVariable );
            return true;
        }

        //      Get next token:
        strToken = wcstok_s( NULL, strDelimit, &context);
    }

    free ( pVariable );

    return false;
}

//
////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////
void GetModule ()
{
    DWORD dwResult =
        GetModuleFileName ( NULL,                       //  __in_opt  HMODULE hModule,
                            ModuleFileName,             //  __out     LPTSTR lpFilename,
                            _wsizeof(ModuleFileName)    //  __in      DWORD nSize
                            );
    wcscpy_s ( NAMEANDWSIZE(InitFileName), ModuleFileName );
    RemoveFileType ( InitFileName );
    wcscat_s ( NAMEANDWSIZE(InitFileName), L".ini" );

    wcscpy_s ( NAMEANDWSIZE(ArpFileName), ModuleFileName );
    RemoveFileType ( ArpFileName );
    wcscat_s ( NAMEANDWSIZE(ArpFileName), L".arp" );

    //
    //      Search Init File and in Path
    SearchInitFile ( NAMEANDWSIZE(InitFileName) );
    SearchArpFile ( NAMEANDWSIZE(ArpFileName) );
    PrintStdoutW ( L"Module File Name : %s\n", ModuleFileName );
    PrintStdoutW ( L"Init   File Name : %s\n", InitFileName );
    PrintStdoutW ( L"Apr    File Name : %s\n", ArpFileName );

}

//
//====================================================================================
//
//====================================================================================
void ReadArpFile ( )
{
    memset ( ArpList, 0, sizeof(ArpList) );
    ArpListCount    = 0;

    FILE *hArpFile = NULL;
    OpenFileCcsW( &hArpFile, ArpFileName, L"r" );
    if ( hArpFile == NULL )
    {
        return;
    }

    while ( ! feof ( hArpFile ) && ! ferror ( hArpFile ) )
    {
        WCHAR *pLine = fgetws ( LineReadW, _wsizeof(LineReadW), hArpFile );
        if ( pLine )
        {
            RemoveCRLFW ( LineReadW );
            WCHAR *pComma = wcschr ( pLine, L',' );
            if ( pComma != NULL )
            {
                WCHAR   *pMac = pComma + 1;
                *pComma = '\0';
                if ( ArpListCount < MAX_ARP_LIST )
                {
                    WCHAR   *pHostname = wcschr ( pMac, L',' );
                    if ( pHostname != NULL )
                    {
                        *pHostname = '\0';
                        pHostname++;
                    }

                    {
                        wcscpy_s ( ArpList [ ArpListCount ].IPAddress, _wsizeof(ArpList [ ArpListCount ].IPAddress), pLine );
                        wcscpy_s ( ArpList [ ArpListCount ].MacAddress, _wsizeof(ArpList [ ArpListCount ].MacAddress), pMac );

                        if ( pHostname != NULL )
                        {
                            wcscpy_s ( ArpList [ ArpListCount ].HostName, _wsizeof(ArpList [ ArpListCount ].HostName), pHostname );
                        }

                        RemoveLeadingByte ( ArpList [ ArpListCount ].IPAddress, L' ' );
                        RemoveTrailingByte ( ArpList [ ArpListCount ].IPAddress, L' ' );

                        //  IP V4
                        if ( wcschr(ArpList [ ArpListCount ].IPAddress, L':') == 0 )
                        {
                            ArpList [ ArpListCount ].IP.binaryLength    = sizeof(ArpList [ ArpListCount ].IP.binaryData.inAddr);
                            GetINetAddr4 ( ArpList [ ArpListCount ].IPAddress, &ArpList [ ArpListCount ].IP.binaryData.inAddr );
                            ArpList [ ArpListCount ].IPVersion          = 4;
                        }
                        else
                        {
                            ArpList [ ArpListCount ].IP.binaryLength    = sizeof(ArpList [ ArpListCount ].IP.binaryData.inAddr6);
                            GetINetAddr6 ( ArpList [ ArpListCount ].IPAddress, &ArpList [ ArpListCount ].IP.binaryData.inAddr6 );
                            ArpList [ ArpListCount ].IPVersion          = 6;
                        }

                        RemoveLeadingByte ( ArpList [ ArpListCount ].MacAddress, L' ' );
                        RemoveTrailingByte ( ArpList [ ArpListCount ].MacAddress, L' ' );

                        RemoveLeadingByte ( ArpList [ ArpListCount ].HostName, L' ' );
                        RemoveTrailingByte ( ArpList [ ArpListCount ].HostName, L' ' );

                        ArpListCount++;
                    }
                }
            }
        }
    }

    fclose ( hArpFile );

    ArpListUpdated = false;
}

//
//====================================================================================
//
//====================================================================================
boolean convertIP ( WCHAR *pText, IP_STRUCT *pBinary )
{
    //
    if ( wcschr(pText, _TEXT(':') ) != NULL )
    {
        sockaddr_in6 in6Addr;
        GetINetAddr6 ( pText, &in6Addr );
        pBinary->binaryLength       = sizeof(in6Addr.sin6_addr);
        pBinary->binaryData.inAddr6 = in6Addr.sin6_addr;
        return true;
    }

    //
    //  IPV4
    else if ( wcschr(pText, _TEXT('.') ) != NULL )
    {
        sockaddr_in inAddr;
        GetINetAddr4 ( pText, &inAddr );
        pBinary->binaryLength       = sizeof(inAddr.sin_addr);
        pBinary->binaryData.inAddr  = inAddr.sin_addr;
        return true;
    }

    return false;
}

//
//====================================================================================
//
//====================================================================================
static int compareItem ( const void *pVoid1, const void *pVoid2 )
{
    ArpItem *pOIX   = (ArpItem *) pVoid1;
    ArpItem *pOIY   = (ArpItem *) pVoid2;

    //
    IP_STRUCT SIX;
    IP_STRUCT SIY;
    memset ( &SIX, 0, sizeof(SIX) );
    memset ( &SIY, 0, sizeof(SIY) );

    convertIP ( pOIX->IPAddress, &SIX );
    convertIP ( pOIY->IPAddress, &SIY );

    //
    int iCmp = 0;
    iCmp = memcmp ( &SIX, &SIY, sizeof(IP_STRUCT)  );

    // PrintDirectW ( L"%s versus %s = %d\n", pOIX->IPAddress, pOIY->IPAddress, iCmp );
    return iCmp;
}

//
//====================================================================================
//
//====================================================================================
void WriteArpFile ( )
{
    //
    //  Sort
    qsort ( ArpList, ArpListCount, sizeof ( ArpItem ), compareItem );

    //
    FILE *hArpFile = NULL;
    OpenFileCcsW( &hArpFile, ArpFileName, L"w" );
    if ( hArpFile == NULL )
    {
        return;
    }

    for (  int i = 0; i < ArpListCount; i++ )
    {
        fwprintf ( hArpFile, L"%s,%s,%s\n", ArpList [ i ].IPAddress, ArpList [ i ].MacAddress,  ArpList [ i ].HostName );
    }

    fclose ( hArpFile );

    ArpListUpdated = false;

    PrintDirect ( L"File %s has been updated\n", ArpFileName );
}

//
//====================================================================================
//
//====================================================================================
int SearchMacAddress ( WCHAR *pMac, int IPVersion )
{
    for (  int i = 0; i < ArpListCount; i++ )
    {
        if ( wcscmp ( ArpList [ i ].MacAddress, pMac ) == 0 && ArpList [ i ].IPVersion == IPVersion )
        {
            return i;
        }
    }

    return -1;
}

//
//====================================================================================
//
//====================================================================================
bool StoreArpAddress ( WCHAR *pIP, WCHAR *pMac, WCHAR *pHostName, int IPVersion )
{
    bool bModify = false;

    //
    if ( IPVersion == 4 && ! IsInsideSubnet(pIP ) )
    {
        return bModify;
    }
    else if ( IPVersion == 6 && ! IsInsideSubnet(pIP )  )
    {
        //
    }

    //
    int iFound = SearchMacAddress ( pMac, IPVersion );
    if ( iFound >= 0 )
    {
        //  If Current Record has already a hostname and hostname is not set return
        if ( wcslen(ArpList [ iFound ].HostName) > 0 && wcslen(pHostName) == 0 )
        {
            return bModify;
        }

        if ( wcscmp(ArpList [ iFound ].IPAddress, pIP) != 0 )
        {
            PrintVerbose ( L"Changing %s to %s\n", ArpList [ iFound ].IPAddress, pIP );
            wcscpy_s ( ArpList [ iFound ].IPAddress, _wsizeof(ArpList [ iFound ].IPAddress), pIP );
            ArpListUpdated = true;
            bModify = true;
        }

        if ( IPVersion == 4 )
        {
            ArpList [ iFound ].IP.binaryLength = sizeof(ArpList [ iFound ].IP.binaryData.inAddr);
            GetINetAddr4 ( ArpList [ iFound ].IPAddress, &ArpList [ iFound ].IP.binaryData.inAddr );
            ArpList [ iFound ].IPVersion    = IPVersion;
        }
        else if ( IPVersion == 6 )
        {
            ArpList [ iFound ].IP.binaryLength = sizeof(ArpList [ iFound ].IP.binaryData.inAddr6);
            GetINetAddr6 ( ArpList [ iFound ].IPAddress, &ArpList [ iFound ].IP.binaryData.inAddr6 );
            ArpList [ iFound ].IPVersion    = IPVersion;
        }

        if ( wcscmp(ArpList [ iFound ].MacAddress, pMac ) != 0 )
        {
            PrintVerbose ( L"Changing %s to %s\n", ArpList [ iFound ].MacAddress, pMac );
            wcscpy_s ( ArpList [ iFound ].MacAddress, _wsizeof(ArpList [ iFound ].MacAddress), pMac );
            ArpListUpdated = true;
            bModify = true;
        }

        if ( pHostName != NULL && wcslen(pHostName) > 0 && wcscmp(ArpList [ iFound ].HostName, pHostName ) != 0 )
        {
            PrintVerbose ( L"Changing %s to %s\n", ArpList [ iFound ].HostName, pHostName );
            wcscpy_s ( ArpList [ iFound ].HostName, _wsizeof(ArpList [ iFound ].HostName), pHostName );
            ArpListUpdated = true;
            bModify = true;
        }
    }
    else
    {
        if ( ArpListCount < MAX_ARP_LIST )
        {
            if ( pHostName != NULL )
            {
                PrintVerbose ( L"Adding %s / %s / %s\n", pIP, pMac, pHostName );
            }
            else
            {
                PrintVerbose ( L"Adding %s / %s\n", pIP, pMac );
            }

            wcscpy_s ( ArpList [ ArpListCount ].IPAddress, _wsizeof(ArpList [ ArpListCount ].IPAddress), pIP );

            if ( IPVersion == 4 )
            {
                ArpList [ ArpListCount ].IP.binaryLength = sizeof(ArpList [ ArpListCount ].IP.binaryData.inAddr);
                GetINetAddr4 ( ArpList [ ArpListCount ].IPAddress, &ArpList [ ArpListCount ].IP.binaryData.inAddr );
                ArpList [ ArpListCount ].IPVersion  = IPVersion;
            }
            else if ( IPVersion == 6 )
            {
                 ArpList [ ArpListCount ].IP.binaryLength = sizeof(ArpList [ ArpListCount ].IP.binaryData.inAddr6);
                 GetINetAddr6 ( ArpList [ ArpListCount ].IPAddress, &ArpList [ ArpListCount ].IP.binaryData.inAddr6 );
                 ArpList [ ArpListCount ].IPVersion = IPVersion;
            }

            wcscpy_s ( ArpList [ ArpListCount ].MacAddress, _wsizeof(ArpList [ ArpListCount ].MacAddress), pMac );
            if ( pHostName != NULL && wcslen(pHostName) > 0 )
            {
                wcscpy_s ( ArpList [ ArpListCount ].HostName, _wsizeof(ArpList [ ArpListCount ].HostName), pHostName );
            }
            ArpListCount++;
            ArpListUpdated = true;
            bModify = true;
        }
    }

    return bModify;
}

//
//====================================================================================
//
//====================================================================================
void LowercaseText ( WCHAR *pText )
{
    for ( size_t i = 0; i < wcslen (pText); i++ )
    {
        pText [ i ] = tolower ( pText [ i ] );
    }
}

//
////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////
BOOL WriteProfile ( WCHAR *keyName, WCHAR *pValue )
{
    BOOL bWritten =
        WritePrivateProfileString (
            PROGRAM_NAME,       //  __in  LPCTSTR lpAppName,
            keyName,            //  __in  LPCTSTR lpKeyName,
            pValue,             //  __in  LPCTSTR lpString,
            InitFileName        //  __in  LPCTSTR lpFileName
        );
    if ( bWritten <= 0 )
    {
        return FALSE;
    }

    return TRUE;
}

//
////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////
BOOL ReadProfile ( WCHAR *keyName, WCHAR *pValue, size_t iValue, WCHAR *pDefault )
{
    ZeroMemory ( pValue, iValue * sizeof(WCHAR) );

    DWORD dwResult =
        GetPrivateProfileString(
            PROGRAM_NAME,                   //  __in   LPCTSTR lpAppName,
            keyName,                        //  __in   LPCTSTR lpKeyName,
            pDefault,                       //  __in   LPCTSTR lpDefault,
            pValue,                         //  __out  LPTSTR lpReturnedString,
            iValue,                         //  __in   DWORD nSize,
            InitFileName                    //  __in   LPCTSTR lpFileName
        );
    if ( dwResult <= 0 )
    {
        return FALSE;
    }

    return TRUE;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
bool IsLocalAddress ( const WCHAR *pAddress )
{
    if ( wcsncmp ( pAddress, L"10.", wcslen(L"10.") ) == 0 )
    {
        return true;
    }

    if ( wcsncmp ( pAddress, L"127.", wcslen(L"127.") ) == 0 )
    {
        return true;
    }

    if ( wcsncmp ( pAddress, L"192.168.", wcslen(L"192.168.") ) == 0 )
    {
        return true;
    }

    if ( wcsncmp ( pAddress, L"172.16.", wcslen(L"172.16.") ) >= 0 && wcsncmp ( pAddress, L"172.31.", wcslen(L"172.31.") ) )
    {
        return true;
    }

    return false;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL GetAddressW ( const WCHAR *pAddress, IN_ADDR *pIPAddress )
{
    //
    BOOL bAddressDone = FALSE;

    //
    PADDRINFOW pAddrInfoW;
    INT iResult =  GetAddrInfoW (
            pAddress,       //  PCWSTR          pNodeName,
            NULL,           //  PCWSTR          pServiceName,
            NULL,           //  const ADDRINFOW *pHints,
            &pAddrInfoW     //  PADDRINFOW      *ppResult
        );
    if ( iResult != 0 )
    {
        WCHAR *pMsg = gai_strerror( iResult );
        PrintStderrW ( L"Error : %d - %s\n", iResult, pMsg );
        return FALSE;
    }

    //
    //  Browse to look an not null address
    addrinfoW *pCurrentAddrInfoW = pAddrInfoW;
    for ( pCurrentAddrInfoW = pAddrInfoW; pCurrentAddrInfoW != NULL; pCurrentAddrInfoW = pCurrentAddrInfoW->ai_next )
    {
        struct sockaddr_in *addrIn = (sockaddr_in *) pCurrentAddrInfoW->ai_addr;
        if ( addrIn->sin_addr.S_un.S_addr != NULL && ! bAddressDone )
        {
            *pIPAddress = addrIn->sin_addr;
            bAddressDone = TRUE;

            //
            PrintStdoutW ( L"IP: %s -> %d.%d.%d.%d\n", pAddress,
                addrIn->sin_addr.S_un.S_un_b.s_b1, addrIn->sin_addr.S_un.S_un_b.s_b2,
                addrIn->sin_addr.S_un.S_un_b.s_b3, addrIn->sin_addr.S_un.S_un_b.s_b4 );
        }
        else
        {
            //
            PrintStdoutW ( L"IP: %s :  %d.%d.%d.%d\n", pAddress,
                addrIn->sin_addr.S_un.S_un_b.s_b1, addrIn->sin_addr.S_un.S_un_b.s_b2,
                addrIn->sin_addr.S_un.S_un_b.s_b3, addrIn->sin_addr.S_un.S_un_b.s_b4 );
        }
    }

    //
    return bAddressDone;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL GetAddressA ( char *pAddress, IN_ADDR *pIPAddress )
{
    //
    BOOL bAddressDone = FALSE;

    //
    PADDRINFOA pAddrInfoA;
    INT iResult =  GetAddrInfoA (
            pAddress,       //  PCWSTR          pNodeName,
            NULL,           //  PCWSTR          pServiceName,
            NULL,           //  const ADDRINFOW *pHints,
            &pAddrInfoA //  PADDRINFOW      *ppResult
        );
    if ( iResult != 0 )
    {
        WCHAR *pMsg = gai_strerror( iResult );
        PrintStderrW ( L"Error : %d - %s\n", iResult, pMsg );
        return FALSE;
    }

    //
    //  Browse to look an not null address
    addrinfo *pCurrentAddrInfo = pAddrInfoA;
    for ( pCurrentAddrInfo = pAddrInfoA; pCurrentAddrInfo != NULL; pCurrentAddrInfo = pCurrentAddrInfo->ai_next )
    {
        struct sockaddr_in *addrIn = (sockaddr_in *) pCurrentAddrInfo->ai_addr;
        if ( addrIn->sin_addr.S_un.S_addr != NULL && ! bAddressDone )
        {
            *pIPAddress = addrIn->sin_addr;
            bAddressDone = TRUE;

            //
            PrintStdoutA ( "IP: %s -> %d.%d.%d.%d\n", pAddress,
                addrIn->sin_addr.S_un.S_un_b.s_b1, addrIn->sin_addr.S_un.S_un_b.s_b2,
                addrIn->sin_addr.S_un.S_un_b.s_b3, addrIn->sin_addr.S_un.S_un_b.s_b4 );
        }
        else
        {
            //
            PrintStdoutA ( "IP: %s :  %d.%d.%d.%d\n", pAddress,
                addrIn->sin_addr.S_un.S_un_b.s_b1, addrIn->sin_addr.S_un.S_un_b.s_b2,
                addrIn->sin_addr.S_un.S_un_b.s_b3, addrIn->sin_addr.S_un.S_un_b.s_b4 );
        }

    }

    return bAddressDone;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void GetNameServerParams ()
{
    ZeroMemory ( &DNSArray, sizeof(DNSArray) );

    ZeroMemory ( &DNS4Array, sizeof(DNS4Array) );

    //
    if ( DnsQueryExMode )
    {
        //  For DNS Query Ex
        //
        DNSArray.AddrCount  = 0;
        DNSArray.MaxCount   = 0;
    }
    //
    //  For DNS Query
    else
    {
        //
        DNS4Array.AddrCount = 0;
        DNS4Array.AddrArray [ 0 ] = 0;
    }

    //
    if ( wcslen(NameServer) > 0 )
    {
        ADDRINFOW   NSHints;
        ADDRINFOW   *NSInfoList = NULL;

        bool    bResult = false;

        ZeroMemory ( &NSHints, sizeof ( NSHints ) );
        NSHints.ai_family       = PF_UNSPEC;
        NSHints.ai_socktype     = SOCK_STREAM;
        NSHints.ai_protocol     = IPPROTO_TCP;

        //
        //      Get Address Infos
        int iNSGetAddrInfoW = GetAddrInfoW ( NameServer, NULL, &NSHints, &NSInfoList );
        if ( iNSGetAddrInfoW != 0 )
        {
            PrintStderr ( L"Error getting Name Server %s\n", NameServer );
        }

        ADDRINFOW   *currentDNS = NULL;
        for ( currentDNS = NSInfoList; currentDNS != NULL && ! bResult; currentDNS = currentDNS->ai_next )
        {
            //
            if ( ( currentDNS->ai_family == AF_INET ) && ( currentDNS->ai_addr != NULL ) )
            {
                //
                //  DNS Array List
                if ( DnsQueryExMode )
                {
                    //
                    // SOCKADDR_IN sockAddr;
                    SOCKADDR_IN sockAddr;
                    ZeroMemory ( &sockAddr, sizeof(sockAddr) );

                    //
                    if ( false )
                    {
                        INT addressLength = sizeof(sockAddr);
                        int iError = WSAStringToAddress(NameServer,
                                AF_INET,
                                NULL,
                                (LPSOCKADDR)&sockAddr,
                                &addressLength);
                        if ( iError != 0 )
                        {
                            memcpy ( &sockAddr, currentDNS->ai_addr, currentDNS->ai_addrlen );
                        }
                    }
                    else
                    {
                        memcpy ( &sockAddr, currentDNS->ai_addr, currentDNS->ai_addrlen );
                    }
                    DNSArray.AddrCount  = 1;
                    DNSArray.MaxCount   = 1;
                    memcpy ( &DNSArray.AddrArray [ 0 ].MaxSa, &sockAddr, sizeof(sockAddr) );
                    DNSArray.Family = currentDNS->ai_family;

                    //  Say We have a dns Array
                    DNSArrayPtr         = &DNSArray;
                }
                //
                //  IP4 Array List
                else
                {
                    //
                    IN_ADDR                 NSInAddr4;
                    ZeroMemory ( &NSInAddr4, sizeof(NSInAddr4) );

                    NSInAddr4 = ( ( sockaddr_in * )( currentDNS->ai_addr ) )->sin_addr;

                    IP4_ADDRESS     ipServer = NSInAddr4.S_un.S_addr;
                    DNS4Array.AddrCount = 1;
                    memcpy ( &DNS4Array.AddrArray [ 0 ], &NSInAddr4, sizeof(NSInAddr4) );

                    //  Say We have a dns Array
                    DNS4ArrayPtr    = &DNS4Array;
                }

                PrintDebug ( L"Using IPV4 Name Server : %s\n", NameServer );

                bResult = true;
            }

            //
            else if (   ( currentDNS->ai_family == AF_INET6 ) && ( currentDNS->ai_addr != NULL ) )
            {
                //
                if ( RuntimeDnsQueryEx != NULL )
                {
                    DnsQueryExMode = true;
                }

                //
                //  DNS Array List
                if ( DnsQueryExMode )
                {
                    //
                    SOCKADDR_IN6    sockAddr;
                    ZeroMemory ( &sockAddr, sizeof(sockAddr) );

                    //
                    if ( false )
                    {
                        INT addressLength = sizeof(sockAddr);
                        int iError = WSAStringToAddress(NameServer,
                                AF_INET6,
                                NULL,
                                (LPSOCKADDR)&sockAddr,
                                &addressLength);
                        if ( iError != 0 )
                        {
                            memcpy ( &sockAddr, currentDNS->ai_addr, currentDNS->ai_addrlen );
                        }
                    }
                    else
                    {
                        memcpy ( &sockAddr, currentDNS->ai_addr, currentDNS->ai_addrlen );
                    }

                    DNSArray.AddrCount  = 1;
                    DNSArray.MaxCount   = 1;
                    memcpy ( &DNSArray.AddrArray [ 0 ].MaxSa, &sockAddr, sizeof(sockAddr) );
                    DNSArray.Family = currentDNS->ai_family;

                    //  Say We have a dns Array
                    DNSArrayPtr         = &DNSArray;

                    bResult = true;

                    PrintDebug ( L"Using IPV6 Name Server : %s\n", NameServer );
                }
                else
                {
                    PrintVerbose ( L"Unable to Use : %s\n", NameServer );
                }
            }
        }

        //
        //      Free List
        if ( NSInfoList )
        {
            FreeAddrInfoW ( NSInfoList );
        }

    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetDNSStatus(DNS_STATUS statusDNS)
{
    static WCHAR szError [  64 ] = L"";
    switch ( statusDNS )
    {
    case ERROR_NETWORK_UNREACHABLE : return L"ERROR_NETWORK_UNREACHABLE";
    case DNS_ERROR_RCODE_NAME_ERROR : return L"DNS_ERROR_RCODE_NAME_ERROR";
    case DNS_ERROR_RCODE_REFUSED : return L"DNS_ERROR_RCODE_REFUSED";
    case ERROR_INVALID_PARAMETER : return L"ERROR_INVALID_PARAMETER";
    case DNS_INFO_NO_RECORDS : return L"DNS_INFO_NO_RECORDS";
    case DNS_REQUEST_PENDING : return L"DNS_REQUEST_PENDING";
    case ERROR_TIMEOUT : return L"ERROR_TIMEOUT";
    case WSAEAFNOSUPPORT : return L"WSAEAFNOSUPPORT";
    case WSAETIMEDOUT : return L"WSAETIMEDOUT";
    case ERROR_SUCCESS : return L"";
    }

    swprintf_s ( szError, _wsizeof(szError),  L"Error : DNS ERROR %ld", statusDNS );
    return szError;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
WORD GetQueryType()
{
    //
    if ( wcslen(QueryType) == 0 )
    {
        return DNS_TYPE_PTR;
    }

#define COMPARE_TYPES(t)    if ( _wcsicmp(QueryType,L#t ) == 0 ) return DNS_TYPE_##t;

    //  RFC 1034/1035
    COMPARE_TYPES(A)
    COMPARE_TYPES(NS)
    COMPARE_TYPES(MD)
    COMPARE_TYPES(MF)
    COMPARE_TYPES(CNAME)
    COMPARE_TYPES(SOA)
    COMPARE_TYPES(MB)
    COMPARE_TYPES(MG)
    COMPARE_TYPES(MR)
    COMPARE_TYPES(NULL)
    COMPARE_TYPES(WKS)
    COMPARE_TYPES(PTR)
    COMPARE_TYPES(HINFO)
    COMPARE_TYPES(MINFO)
    COMPARE_TYPES(MX)
    COMPARE_TYPES(TEXT)

    //  RFC 1886    (IPv6 Address)
    COMPARE_TYPES(AAAA)

    //
    //  Query only types (1035, 1995)
    COMPARE_TYPES(ALL)
    COMPARE_TYPES(ANY)


    //  Not A Recognized type
    PrintStderr ( L"DNS Type %s not treated\n", QueryType );
    exit(2);
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetDnsTypeName ( WORD wType )
{
#define RETURN_DNS_TYPE_NAME(t) case t: return L#t + 4;

    switch ( wType )
    {
    RETURN_DNS_TYPE_NAME(DNS_TYPE_ZERO)

    //  RFC 1034/1035
    RETURN_DNS_TYPE_NAME(DNS_TYPE_A)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NS)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MD)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MF)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_CNAME)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_SOA)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MB)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MG)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MR)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NULL)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_WKS)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_PTR)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_HINFO)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MINFO)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MX)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_TEXT)

    //  RFC 1183
    RETURN_DNS_TYPE_NAME(DNS_TYPE_RP)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_AFSDB)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_X25)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_ISDN)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_RT)

    //  RFC 1348
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NSAP)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NSAPPTR)

    //  RFC 2065    (DNS security)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_SIG)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_KEY)

    //  RFC 1664    (X.400 mail)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_PX)

    //  RFC 1712    (Geographic position)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_GPOS)

    //  RFC 1886    (IPv6 Address)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_AAAA)

    //  RFC 1876    (Geographic location)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_LOC)

    //  RFC 2065    (Secure negative response)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NXT)

    //  Patton      (Endpoint Identifier)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_EID)

    //  Patton      (Nimrod Locator)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NIMLOC)

    //  RFC 2052    (Service location)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_SRV)

    //  ATM Standard something-or-another (ATM Address)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_ATMA)

    //  RFC 2168    (Naming Authority Pointer)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NAPTR)

    //  RFC 2230    (Key Exchanger)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_KX)

    //  RFC 2538    (CERT)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_CERT)

    //  A6 Draft    (A6)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_A6)

    //  DNAME Draft (DNAME)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_DNAME)

    //  Eastlake    (Kitchen Sink)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_SINK)

    //  RFC 2671    (EDNS OPT)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_OPT)

    //  RFC 4034    (DNSSEC DS)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_DS)

    //  RFC 4034    (DNSSEC RRSIG)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_RRSIG)

    //  RFC 4034    (DNSSEC NSEC)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NSEC)

    //  RFC 4034    (DNSSEC DNSKEY)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_DNSKEY)

    //  RFC 4701    (DHCID)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_DHCID)

    //  RFC 5155    (DNSSEC NSEC3)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NSEC3)

    //  RFC 5155    (DNSSEC NSEC3PARAM)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_NSEC3PARAM)

    //
    //  IANA Reserved
    //

    RETURN_DNS_TYPE_NAME(DNS_TYPE_UINFO)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_UID)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_GID)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_UNSPEC)

    //
    //  Query only types (1035, 1995)
    //      - Crawford      (ADDRS)
    //      - TKEY draft    (TKEY)
    //      - TSIG draft    (TSIG)
    //      - RFC 1995      (IXFR)
    //      - RFC 1035      (AXFR up)
    //

    RETURN_DNS_TYPE_NAME(DNS_TYPE_ADDRS)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_TKEY)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_TSIG)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_IXFR)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_AXFR)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MAILB)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_MAILA)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_ALL)
    // RETURN_DNS_TYPE_NAME(DNS_TYPE_ANY)

    //
    //  Private use Microsoft types --  See www.iana.org/assignments/dns-parameters
    //

    RETURN_DNS_TYPE_NAME(DNS_TYPE_WINS)
    RETURN_DNS_TYPE_NAME(DNS_TYPE_WINSR)

    //
    //  DNS Record Types -- Net Byte Order
    //

    RETURN_DNS_TYPE_NAME(DNS_RTYPE_A)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NS)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MD)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MF)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_CNAME)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_SOA)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MB)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MG)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MR)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NULL)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_WKS)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_PTR)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_HINFO)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MINFO)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MX)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_TEXT)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_RP)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_AFSDB)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_X25)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_ISDN)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_RT)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NSAP)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NSAPPTR)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_SIG)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_KEY)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_PX)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_GPOS)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_AAAA)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_LOC)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NXT)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_EID)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NIMLOC)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_SRV)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_ATMA)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NAPTR)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_KX)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_CERT)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_A6)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_DNAME)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_SINK)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_OPT)

    RETURN_DNS_TYPE_NAME(DNS_RTYPE_DS)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_RRSIG)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NSEC)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_DNSKEY)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_DHCID)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NSEC3)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_NSEC3PARAM)

    //
    //  IANA Reserved
    //

    RETURN_DNS_TYPE_NAME(DNS_RTYPE_UINFO)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_UID)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_GID)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_UNSPEC)

    //
    //  Query only types
    //

    RETURN_DNS_TYPE_NAME(DNS_RTYPE_TKEY)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_TSIG)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_IXFR)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_AXFR)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MAILB)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_MAILA)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_ALL)
    // RETURN_DNS_TYPE_NAME(DNS_RTYPE_ANY)

    //
    //  Private use Microsoft types --  See www.iana.org/assignments/dns-parameters
    //

    RETURN_DNS_TYPE_NAME(DNS_RTYPE_WINS)
    RETURN_DNS_TYPE_NAME(DNS_RTYPE_WINSR)
    }


    return L"";
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *IPV4ToString ( const IP4_ADDRESS &ip4 )
{
    static WCHAR szIP4String [ MAX_PATH ];

    SOCKADDR_IN sockAddr;
    ZeroMemory ( &sockAddr, sizeof(sockAddr) );
    sockAddr.sin_family = AF_INET;
    memcpy ( &sockAddr.sin_addr.S_un, &ip4, sizeof(ip4) );

    DWORD dwSize = _wsizeof(szIP4String);

    INT iRes =  WSAAddressToString (
        (SOCKADDR *)&sockAddr,          //  LPSOCKADDR          lpsaAddress,
        sizeof(sockAddr),               //  DWORD               dwAddressLength,
        NULL,                           //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
        szIP4String,                    //  LPSTR               lpszAddressString,
        &dwSize                         //  LPDWORD             lpdwAddressStringLength
        );

    return szIP4String;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *IPV6ToString ( const IP6_ADDRESS &ip6 )
{
    static WCHAR szIP6String [ MAX_PATH ];

    SOCKADDR_IN6    sockAddr;
    ZeroMemory ( &sockAddr, sizeof(sockAddr) );
    sockAddr.sin6_family    = AF_INET;
    memcpy ( sockAddr.sin6_addr.u.Byte, &ip6, sizeof(ip6) );

    DWORD dwSize = _wsizeof(szIP6String);

    RtlIpv6AddressToStringW ( &sockAddr.sin6_addr, szIP6String );

    return szIP6String;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetQueryData(WORD dnsType, DNS_RECORD *ppCurrent)
{
    static WCHAR sztQueryData [ LEN_TEXT_8192 ];

    //
    switch ( dnsType )
    {
        case DNS_TYPE_NS: return ppCurrent->Data.NS.pNameHost;
        case DNS_TYPE_MD: return ppCurrent->Data.MD.pNameHost;
        case DNS_TYPE_MF: return ppCurrent->Data.MF.pNameHost;
        case DNS_TYPE_CNAME: return ppCurrent->Data.CNAME.pNameHost;
        case DNS_TYPE_MB : return ppCurrent->Data.MB.pNameHost;
        case DNS_TYPE_MG: return ppCurrent->Data.MG.pNameHost;
        case DNS_TYPE_MR: return ppCurrent->Data.MR.pNameHost;
        case DNS_TYPE_MX: return ppCurrent->Data.MX.pNameExchange;
        case DNS_TYPE_PTR: return ppCurrent->Data.PTR.pNameHost;
        case DNS_TYPE_MINFO: return ppCurrent->Data.MINFO.pNameMailbox;
    }

    //
    switch ( dnsType )
    {
        case DNS_TYPE_A:
        {
            return IPV4ToString ( ppCurrent->Data.A.IpAddress );
        }
        case DNS_TYPE_SOA:
        {
            swprintf_s ( sztQueryData, _wsizeof(sztQueryData), L"%s %s",
                ppCurrent->Data.SOA.pNamePrimaryServer,
                ppCurrent->Data.SOA.pNameAdministrator );
            return sztQueryData;
        }
        case DNS_TYPE_TEXT:
        {
            ZeroMemory ( sztQueryData, sizeof(sztQueryData) );
            for ( DWORD dw = 0; dw < ppCurrent->Data.TXT.dwStringCount; dw++ )
            {
                swprintf_s ( sztQueryData + wcslen(sztQueryData),
                    _wsizeof(sztQueryData) - wcslen(sztQueryData),
                    L"%s, ",
                    ppCurrent->Data.TXT.pStringArray [ dw ]);
            }
            return sztQueryData;
        }
        case DNS_TYPE_RRSIG:
        {
            swprintf_s ( sztQueryData, _wsizeof(sztQueryData), L"RRSIG %s",
                ppCurrent->Data.RRSIG.pNameSigner );
            return sztQueryData;
        }
        case DNS_TYPE_DNSKEY:
        {
            swprintf_s ( sztQueryData, _wsizeof(sztQueryData), L"DNSKEY Key Length %d",
                ppCurrent->Data.DNSKEY.wKeyLength );
            return sztQueryData;
        }
        case DNS_TYPE_NSEC3PARAM:
        {
            swprintf_s ( sztQueryData, _wsizeof(sztQueryData), L"NSEC Salt Length %d",
                ppCurrent->Data.NSEC3PARAM.bSaltLength  );
            return sztQueryData;
        }
        case DNS_TYPE_AAAA:
        {
            return IPV6ToString ( ppCurrent->Data.AAAA.Ip6Address );
        }
    }

    swprintf_s ( sztQueryData, _wsizeof(sztQueryData), L"Type : %d", dnsType );

    return sztQueryData;

}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//  DnsQuery would require an reversed address as 105.1.168.192.IN-ADDR.ARPA for a DNS_TYPE_PTR
//////////////////////////////////////////////////////////////////////////////////////////////////
void ResolveOneHost ( const WCHAR *pIPAddress, WCHAR *pResolved, size_t sizeInType, bool bQueryOnly = false )
{
    ZeroMemory ( pResolved, sizeInType * sizeof(WCHAR) );

    //
    WCHAR IpString [ LEN_IP_ARP ];

    //
    if ( RuntimeDnsQueryEx == NULL )
    {
        DnsQueryExMode  = false;
    }

    //
    if ( ResolveMode )
    {
        //
#if 0
        IN_ADDR inAddr;
        ZeroMemory ( &inAddr, sizeof(inAddr) );
        GetAddressW ( pIPAddress, &inAddr );
#endif

        //
        //      Query the DNS server for the Mail Server
        WORD wType      = DNS_TYPE_PTR;
        if ( bQueryOnly )
        {
            wType       = GetQueryType();
        }

        //
        bool HostNameFound = false;

        //  Using GetAddrInfoW
        ADDRINFOW   hostHints;
        ZeroMemory ( &hostHints, sizeof(hostHints) );

        hostHints.ai_socktype   = SOCK_STREAM;
        hostHints.ai_protocol   = IPPROTO_TCP;
        if ( wcschr(pIPAddress, L'.' ) != NULL )
        {
            hostHints.ai_family =   AF_INET;
        }
        else if ( wcschr(pIPAddress, L':' ) != NULL )
        {
            hostHints.ai_family =   AF_INET6;
        }
        else
        {
            hostHints.ai_family =   AF_UNSPEC;
        }

        //
        int iFamily = hostHints.ai_family;

        //
        WCHAR szInArpa [ LEN_TEXT_256 ];
        ZeroMemory ( szInArpa, sizeof(szInArpa) );

        //
        int         iHostGetAddrInfoW    = 0;
        PADDRINFOW  pHostAddrInfo1      = NULL;

        //
        //  For Pointer Revers IP
        if ( wType == DNS_TYPE_PTR )
        {
            //  This is used to retrieve IP Address
            //  To Make the in-addr.arpa string to use fore DNS
            //  Or for the last iHostGetNameInfoW
            iHostGetAddrInfoW = GetAddrInfoW (
              pIPAddress,               //  _In_opt_  PCWSTR pNodeName,
              NULL,                     //  _In_opt_  PCWSTR pServiceName,
              &hostHints,               //  _In_opt_  const ADDRINFOW *pHints,
              &pHostAddrInfo1           //  _Out_     PADDRINFOW *ppResult
            );

            //
            //  Using DNS Server
            if ( UseDns && iHostGetAddrInfoW == 0 && pHostAddrInfo1 != NULL )
            {

                //
                if ( pHostAddrInfo1->ai_family == AF_INET )
                {
                    IN_ADDR hostInAddr;
                    hostInAddr = ( ( sockaddr_in * )( pHostAddrInfo1->ai_addr ) )->sin_addr;

                    wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"%d." , hostInAddr.S_un.S_un_b.s_b4 );
                    wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"%d." , hostInAddr.S_un.S_un_b.s_b3 );
                    wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"%d." , hostInAddr.S_un.S_un_b.s_b2 );
                    wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"%d." , hostInAddr.S_un.S_un_b.s_b1 );
                    wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"in-addr.arpa" );
                }
                else if ( pHostAddrInfo1->ai_family == AF_INET6 )
                {
                    IN6_ADDR hostInAddr;
                    hostInAddr = ( ( sockaddr_in6 * )( pHostAddrInfo1->ai_addr ) )->sin6_addr;
                    for ( int i = 15; i >= 0; i-- )
                    {
                        UCHAR one = hostInAddr.u.Byte [ i ];
                        UCHAR low = one & 0xf;
                        UCHAR high = ( one & 0xf0) >> 4;
                        wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"%x.", low );
                        wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"%x.", high );
                    }
                    wnsprintf ( szInArpa + wcslen(szInArpa), _wsizeof(szInArpa) - wcslen(szInArpa), L"ip6.arpa" );
                }
            }
        }
        else
        {
            wcscpy_s ( szInArpa, _wsizeof(szInArpa), pIPAddress );
        }

        if ( UseDns || bQueryOnly )
        {
            //
            DNS_STATUS  statusDNS = 0;

            //
            DWORD wOptions  = DNS_QUERY_BYPASS_CACHE;
            if ( bQueryOnly )
            {
                 wOptions       |= DNS_QUERY_NO_LOCAL_NAME;
                 wOptions       |= DNS_QUERY_NO_HOSTS_FILE;
                 wOptions       |= DNS_QUERY_USE_TCP_ONLY;
            }
            DNS_RECORD  *ppQueryResultsSet = NULL;

            //
            if ( bQueryOnly )
            {
                PrintDirect ( L"Searching %s\n", szInArpa );
            }

            //
            //      Query the DNS server for the Mail Server
            if ( DnsQueryExMode )
            {
                DNS_QUERY_REQUEST   dnsRequest;
                DNS_QUERY_RESULT    dnsResult;
                ZeroMemory ( &dnsRequest, sizeof(dnsRequest) );
                ZeroMemory ( &dnsResult, sizeof(dnsResult) );

                //
                dnsRequest.Version          = DNS_QUERY_REQUEST_VERSION1;
                dnsRequest.QueryName        = szInArpa;
                dnsRequest.QueryType        = wType;
                dnsRequest.QueryOptions     = wOptions;
                dnsRequest.pDnsServerList   = DNSArrayPtr;
            
                //
                dnsResult.Version           = DNS_QUERY_REQUEST_VERSION1;
                dnsResult.QueryOptions      = wOptions;

                //
                if ( DebugMode )
                {
                    if ( DNSArrayPtr != NULL && DNSArrayPtr->AddrCount > 0 )
                    {
                        PrintDirect ( L"(Using DNSQueryEx) " );
                        if ( bQueryOnly )
                        {
                            PrintDirect ( L"\n" );
                        }
                    }
                    else
                    {
                        PrintDirect ( L"(Using DNSQueryEx with an empty List)\n" );
                    }
                }

                //  DnsQueryEx
                statusDNS = (*RuntimeDnsQueryEx)( &dnsRequest, &dnsResult, NULL );
                ppQueryResultsSet   = dnsResult.pQueryRecords;
            }
            else
            {
                //
                if ( DebugMode )
                {
                    if ( DNS4ArrayPtr != NULL && DNS4ArrayPtr->AddrCount > 0 )
                    {
                        PrintDirect ( L"(Using DNSQuery) " );
                        if ( bQueryOnly )
                        {
                            PrintDirect ( L"\n" );
                        }
                    }
                    else
                    {
                        PrintDirect ( L"(Using DNSQuery with an empty List)\n" );
                    }
                }

                //  DnsQuery
                statusDNS =
                    DnsQuery (  szInArpa, wType,
                                wOptions, DNS4ArrayPtr,
                                &ppQueryResultsSet, NULL );
            }

            //
            //      Initial Query Record
            DNS_RECORD  *ppCurrent = ppQueryResultsSet;

            if ( statusDNS == ERROR_SUCCESS && ppCurrent != NULL )
            {
                //
                //      While Result Set Is Not Null
                for (  ppCurrent = ppQueryResultsSet; ppCurrent != NULL; ppCurrent = ppCurrent->pNext )
                {

                    //
                    //      RFC 1034/1035
                    //      DNS_TYPE_A          0x0001      //  1
                    //      DNS_TYPE_NS         0x0002      //  2
                    //      DNS_TYPE_MD         0x0003      //  3
                    //      DNS_TYPE_MF         0x0004      //  4
                    //      DNS_TYPE_CNAME      0x0005      //  5
                    //      DNS_TYPE_SOA        0x0006      //  6
                    //      DNS_TYPE_MB         0x0007      //  7
                    //      DNS_TYPE_MG         0x0008      //  8
                    //      DNS_TYPE_MR         0x0009      //  9
                    //      DNS_TYPE_NULL       0x000a      //  10
                    //      DNS_TYPE_WKS        0x000b      //  11
                    //      DNS_TYPE_PTR        0x000c      //  12
                    //      DNS_TYPE_HINFO      0x000d      //  13
                    //      DNS_TYPE_MINFO      0x000e      //  14
                    //      DNS_TYPE_MX         0x000f      //  15
                    //      DNS_TYPE_TEXT       0x0010      //  16
                    //
                    
                    if ( ppCurrent->wType == wType || wType == DNS_TYPE_ALL )
                    {
                        const WCHAR *ptr = GetQueryData (ppCurrent->wType, ppCurrent );
                        if ( ptr != NULL )
                        {
                            //  Check Host
                            if ( bQueryOnly )
                            {
                                PrintDirectW ( L"%20s : %s\n", GetDnsTypeName ( ppCurrent->wType ), ptr );
                            }
                            else
                            {
                                wcscpy_s ( pResolved, sizeInType, ptr );
                                ZeroMemory ( IpString, sizeof(IpString) );

                                ZeroMemory ( &hostHints, sizeof(hostHints) );

                                hostHints.ai_socktype   = SOCK_STREAM;
                                hostHints.ai_protocol   = IPPROTO_TCP;
                                hostHints.ai_family     = iFamily;

                                PADDRINFOW  pHostAddrInfo2 = NULL;

                                iHostGetAddrInfoW = GetAddrInfoW (
                                  pResolved,                //  _In_opt_  PCWSTR pNodeName,
                                  NULL,                     //  _In_opt_  PCWSTR pServiceName,
                                  &hostHints,               //  _In_opt_  const ADDRINFOW *pHints,
                                  &pHostAddrInfo2           //  _Out_     PADDRINFOW *ppResult
                                );

                                //
                                PADDRINFOW  current;
                                for ( current = pHostAddrInfo2; current != NULL && ! HostNameFound; current = current->ai_next)
                                {
                                    ZeroMemory ( IpString, sizeof(IpString) );
                                    DWORD dwSize = _wsizeof(IpString);
                                    INT iRes =  WSAAddressToString (
                                            current->ai_addr,               //  LPSOCKADDR          lpsaAddress,
                                            current->ai_addrlen,            //  DWORD               dwAddressLength,
                                            NULL,                           //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                            IpString,                       //  LPSTR               lpszAddressString,
                                            &dwSize                         //  LPDWORD             lpdwAddressStringLength
                                            );
                                    if ( wcscmp(IpString, pIPAddress ) == 0 )
                                    {
                                        HostNameFound   = true;
                                        PrintDebug ( L"Found a good name for %s : %s\n", IpString, pResolved );
                                    }
                                    else
                                    {
                                        PrintDebug ( L"Not a good name for %s : %s\n", IpString, pResolved );
                                    }
                                }

                                //
                                //  Not A good Result
                                if ( ! HostNameFound )
                                {
                                    PrintVerbose ( L"Not a suitable name %s (%s)\n", pResolved, IpString );
                                    ZeroMemory ( pResolved, sizeInType * sizeof(WCHAR) );
                                }

                                if ( pHostAddrInfo2 )
                                {
                                    FreeAddrInfoW ( pHostAddrInfo2 );
                                    pHostAddrInfo2  = NULL;
                                }
                            }
                        }
                    }

                }
            }
            else if ( statusDNS != ERROR_SUCCESS )
            {
                if ( DebugMode || bQueryOnly )
                {
                    PrintStderr ( L"%s\n", GetDNSStatus( statusDNS ) );
                }
            }

            //
            //      Free Record
            if ( ppQueryResultsSet )
            {
                DnsRecordListFree ( ppQueryResultsSet, DnsFreeRecordList );
                ppQueryResultsSet = NULL;
            }
        }

        //  DNS Has be called or not : we call GetNameInfoW if pResolved is empty
        //  To Retrieve the host name
        if ( iHostGetAddrInfoW == 0 && pHostAddrInfo1 != NULL && wcslen ( pResolved ) == 0 )
        {
            int iHostGetNameInfoW =
                GetNameInfoW ( pHostAddrInfo1->ai_addr, pHostAddrInfo1->ai_addrlen, pResolved, sizeInType, NULL, 0, NI_NAMEREQD  );
        }

        //
        if ( pHostAddrInfo1 )
        {
            FreeAddrInfoW ( pHostAddrInfo1 );
            pHostAddrInfo1  = NULL;
        }

        //
        if ( bQueryOnly )
        {
            return;
        }

        //
        //  Test Result Host
        if ( ! HostNameFound )
        {
            ZeroMemory ( &hostHints, sizeof(hostHints) );

            hostHints.ai_socktype   = SOCK_STREAM;
            hostHints.ai_protocol   = IPPROTO_TCP;
            hostHints.ai_family     = iFamily;

            PADDRINFOW  pHostAddrInfo2 = NULL;

            iHostGetAddrInfoW = GetAddrInfoW (
              pResolved,                //  _In_opt_  PCWSTR pNodeName,
              NULL,                     //  _In_opt_  PCWSTR pServiceName,
              &hostHints,               //  _In_opt_  const ADDRINFOW *pHints,
              &pHostAddrInfo2           //  _Out_     PADDRINFOW *ppResult
            );

            //
            PADDRINFOW  current;
            ZeroMemory ( IpString, sizeof(IpString) );
            for ( current = pHostAddrInfo2; current != NULL && ! HostNameFound; current = current->ai_next )
            {
                ZeroMemory ( IpString, sizeof(IpString) );
                DWORD dwSize = _wsizeof(IpString);
                INT iRes =  WSAAddressToString (
                        current->ai_addr,               //  LPSOCKADDR          lpsaAddress,
                        current->ai_addrlen,            //  DWORD               dwAddressLength,
                        NULL,                           //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                        IpString,                       //  LPSTR               lpszAddressString,
                        &dwSize                         //  LPDWORD             lpdwAddressStringLength
                        );
                if ( wcscmp(IpString, pIPAddress ) == 0 )
                {
                    HostNameFound = true;
                }
            }

            //  Not A good Result
            if ( ! HostNameFound )
            {
                PrintVerbose ( L"Not a suitable name '%s' (%s)\n", pResolved, IpString );
                ZeroMemory ( pResolved, sizeInType * sizeof(WCHAR) );
            }

            if ( pHostAddrInfo2 )
            {
                FreeAddrInfoW ( pHostAddrInfo2 );
                pHostAddrInfo2  = NULL;
            }
        }
    }

    if ( _wcsicmp ( pIPAddress, pResolved ) == 0 )
    {
        ZeroMemory ( pResolved, sizeInType * sizeof(WCHAR) );
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL sendWake ( WCHAR *pSubnet )
{
    SOCKET socketWake = INVALID_SOCKET;

    //
    int iFamily     = AF_INET;
    int iType       = SOCK_DGRAM;
    int iProtocol   = IPPROTO_UDP;
    socketWake = socket ( iFamily, iType, iProtocol);
    if ( socketWake == INVALID_SOCKET )
    {
        int wsaLastError = WSAGetLastError();
        FormatErrorMessage ( wsaLastError );
        PrintStderrW ( L"Error : %d - %s\n", wsaLastError, szErrorText );
        return FALSE;
    }

    //
    int     iOptVal     = 0;
    int     iOptLen     = sizeof (iOptVal);

    BOOL    bOptVal     = FALSE;
    int     bOptLen     = sizeof (bOptVal);

    bOptVal = TRUE;
    int iResult = setsockopt ( socketWake, SOL_SOCKET, SO_BROADCAST, ( char *) &bOptVal, bOptLen );
    if (iResult == SOCKET_ERROR)
    {
        int wsaLastError = WSAGetLastError();
        FormatErrorMessage ( wsaLastError );
        PrintStderrW ( L"Error : %d - %s\n", wsaLastError, szErrorText );
        return FALSE;
    }

    //
    sockaddr_in targetAddrIn;
    targetAddrIn.sin_addr.s_addr    = INADDR_BROADCAST;
    targetAddrIn.sin_family         = iFamily;
    targetAddrIn.sin_port           = htons(40000);

    //  fill first 6 Bytes with 0xFF
    for ( int i = 0; i < 6; i++)
    {
        MagicWakePacket [ i ] = 0xff;
    }

    //  fill bytes 6-12 with mac address
    for ( int i = 0; i < 6; i++ )
    {
        //Get 2 charachters from mac address and convert it to int to fill
        //magic packet
        MagicWakePacket [ i + 6 ] = MacAddress [ i ];
    }

    //  Fill remaining 90 bytes (15 time repeat of the 6 mac address)
    for ( int i = 0; i < 15; i++ )
    {
        memcpy( &MagicWakePacket [ ( i + 2 ) * 6 ], &MagicWakePacket [ 6 ], 6 );
    }

    //
    sockaddr_in *pTarget = &targetAddrIn;
    int iTargetLen = sizeof(targetAddrIn);

    //
    if ( wcslen(pSubnet) > 0 )
    {
        IN_ADDR inAddr;
        ZeroMemory ( &inAddr, sizeof(inAddr) );
        GetINetAddr4 ( pSubnet, &inAddr );
        targetAddrIn.sin_addr.s_addr = inAddr.S_un.S_addr;
    }

    int iSendTo = sendto(socketWake, (const char *) MagicWakePacket, sizeof(MagicWakePacket), 0,  (sockaddr *) pTarget, iTargetLen );
    if (iSendTo == SOCKET_ERROR)
    {
        int wsaLastError = WSAGetLastError();
        FormatErrorMessage ( wsaLastError );
        PrintStderrW ( L"Error : %d - %s\n", wsaLastError, szErrorText );
        return FALSE;
    }
    else if ( VerboseMode )
    {
        PrintVerbose ( L"Sending Wake Through Address %u.%u.%u.%u\n",
            targetAddrIn.sin_addr.S_un.S_un_b.s_b1, targetAddrIn.sin_addr.S_un.S_un_b.s_b2,
            targetAddrIn.sin_addr.S_un.S_un_b.s_b3, targetAddrIn.sin_addr.S_un.S_un_b.s_b4 );
    }


    //  On All adapter separatly
    if ( wcslen(pSubnet) == 0 )
    {
        for ( int i = 0; i < SubnetListCount; i++ )
        {
            SubnetItem item = SubnetList [ i ];
            IN_ADDR inAddr  = item.IP;
            IN_ADDR inMask  = item.Mask;

            //  address and mask 192.168.1.101 & 192.168.1.0
            inAddr.S_un.S_addr = inAddr.S_un.S_addr & inMask.S_un.S_addr;
            //  mask xor 0xffffffff gives 0.0.0.255
            inMask.S_un.S_addr  = inMask.S_un.S_addr ^ 0xffffffff;
            if ( DebugMode )
            {
                PrintDebug ( L"Sending Wake with Mask %u.%u.%u.%u\n",
                    inMask.S_un.S_un_b.s_b1, inMask.S_un.S_un_b.s_b2,
                    inMask.S_un.S_un_b.s_b3, inMask.S_un.S_un_b.s_b4 );
            }
            inAddr.S_un.S_addr  = inAddr.S_un.S_addr |  inMask.S_un.S_addr;
            targetAddrIn.sin_addr.s_addr = inAddr.S_un.S_addr;

            int iSendTo = sendto(socketWake, (const char *) MagicWakePacket, sizeof(MagicWakePacket), 0,  (sockaddr *) pTarget, iTargetLen );
            if (iSendTo == SOCKET_ERROR)
            {
                int wsaLastError = WSAGetLastError();
                FormatErrorMessage ( wsaLastError );
                PrintStderrW ( L"Error : %d - %s\n", wsaLastError, szErrorText );
            }
            else if ( VerboseMode )
            {
                PrintVerbose ( L"Sending Wake Through Address %u.%u.%u.%u\n",
                    targetAddrIn.sin_addr.S_un.S_un_b.s_b1, targetAddrIn.sin_addr.S_un.S_un_b.s_b2,
                    targetAddrIn.sin_addr.S_un.S_un_b.s_b3, targetAddrIn.sin_addr.S_un.S_un_b.s_b4 );
            }
        }
    }

    return TRUE;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL MacIsNotNull ( BYTE macAddress [ 6 ] )
{
    //
    for ( int i = 0; i < 6; i++ )
    {
        if ( macAddress [ i ] != 0 )
        {
            return TRUE;
        }
    }

    return FALSE;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetAdapterOperStatus ( IF_OPER_STATUS status )
{
    switch ( status )
    {
    case IfOperStatusUp : return L"Up";
    case IfOperStatusDown  : return L"Down";
    case IfOperStatusTesting  : return L"Testing";
    case IfOperStatusUnknown  : return L"Unknown";
    case IfOperStatusDormant  : return L"Dormant";
    case IfOperStatusNotPresent  : return L"Not Present";
    case IfOperStatusLowerLayerDown  : return L"Lower Layer Down";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetDadState( IP_DAD_STATE state )
{
    switch ( state )
    {
    case IpDadStateInvalid : return L"Invalid";
    case IpDadStateTentative  : return L"Tentative";
    case IpDadStateDuplicate  : return L"Duplicate";
    case IpDadStateDeprecated  : return L"Deprecated";
    case IpDadStatePreferred  : return L"Preferred";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetPrefixOrigin ( IP_PREFIX_ORIGIN origin )
{
    switch ( origin )
    {
    case IpPrefixOriginOther : return L"Other";
    case IpPrefixOriginManual  : return L"Manual";
    case IpPrefixOriginWellKnown  : return L"WellKnown";
    case IpPrefixOriginDhcp  : return L"Dhcp";
    case IpPrefixOriginRouterAdvertisement  : return L"RouterAdvertisement";
    case IpPrefixOriginUnchanged  : return L"Unchanged";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetSuffixOrigin ( IP_SUFFIX_ORIGIN origin )
{
    switch ( origin )
    {
    case IpSuffixOriginOther : return L"Other";
    case IpSuffixOriginManual  : return L"Manual";
    case IpSuffixOriginWellKnown  : return L"WellKnown";
    case IpSuffixOriginDhcp  : return L"Dhcp";
    case IpSuffixOriginLinkLayerAddress  : return L"LinkLayerAddress";
    case IpSuffixOriginRandom  : return L"Random";
    case IpSuffixOriginUnchanged  : return L"Unchanged";
    default : return L"?";
    }
    
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetAdapterTypeValue ( IFTYPE type )
{
    switch ( type )
    {
    case IF_TYPE_OTHER : return L"OTHER";
    case IF_TYPE_ETHERNET_CSMACD : return L"ETHERNET_CSMACD";
    case IF_TYPE_ISO88025_TOKENRING : return L"ISO88025_TOKENRING";
    case IF_TYPE_PPP : return L"PPP";
    case IF_TYPE_SOFTWARE_LOOPBACK : return L"SOFTWARE_LOOPBACK";
    case IF_TYPE_ATM : return L"ATM";
    case IF_TYPE_IEEE80211 : return L"IEEE80211";
    case IF_TYPE_TUNNEL : return L"TUNNEL";
    case IF_TYPE_IEEE1394 : return L"IEEE1394";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetAdapterTunnelType ( TUNNEL_TYPE type )
{
    switch ( type )
    {
    case TUNNEL_TYPE_NONE : return L"NONE";
    case TUNNEL_TYPE_OTHER : return L"OTHER";
    case TUNNEL_TYPE_DIRECT : return L"DIRECT";
    case TUNNEL_TYPE_6TO4 : return L"6TO4";
    case TUNNEL_TYPE_ISATAP : return L"ISATAP";
    case TUNNEL_TYPE_TEREDO : return L"TEREDO";
    case TUNNEL_TYPE_IPHTTPS : return L"IPHTTPS";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void ShowAdapters64()
{
    //
    ULONG SizePointer   = 512 * 1024;
    PIP_ADAPTER_ADDRESSES AdapterAddresses = ( PIP_ADAPTER_ADDRESSES ) malloc ( SizePointer );
    ULONG Flags = NULL;
    Flags |= GAA_FLAG_INCLUDE_GATEWAYS;
    Flags |= GAA_FLAG_INCLUDE_WINS_INFO;
    Flags |= GAA_FLAG_INCLUDE_ALL_INTERFACES;
    Flags |= GAA_FLAG_INCLUDE_PREFIX;
    Flags |= GAA_FLAG_INCLUDE_ALL_COMPARTMENTS;
    Flags |= GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER;

    ULONG Family = AF_UNSPEC;
    if ( IPv4Only )
    {
        Family  = AF_INET;
    }
    else if ( IPv6Only )
    {
        Family  = AF_INET6;
    }

    //
    DWORD dwResult = GetAdaptersAddresses (
        Family,                 //  _In_     ULONG Family,
        Flags,                  //  _In_     ULONG Flags,
        NULL,                   //  _In_     PVOID Reserved,
        AdapterAddresses,       //  _Inout_  PIP_ADAPTER_ADDRESSES AdapterAddresses,
        &SizePointer            //  Inout_  PULONG SizePointer
    );

    ERROR_NOT_ENOUGH_MEMORY;
    //
    if ( ERROR_SUCCESS != dwResult )
    {
        PrintStderrW ( L"Error : GetAdaptersAddresses %d\n", dwResult );
        return;
    }

    PIP_ADAPTER_ADDRESSES pAdapterAddress = AdapterAddresses;
    for ( pAdapterAddress = AdapterAddresses; pAdapterAddress != NULL; pAdapterAddress = pAdapterAddress->Next )
    {
        if ( ! NonZeroMac || MacIsNotNull ( pAdapterAddress->PhysicalAddress ) )
        {
            BOOL bShow = TRUE;
            if ( IPUp && pAdapterAddress->OperStatus != IfOperStatusUp )
            {
                bShow = FALSE;
            }

            if ( IPDown && pAdapterAddress->OperStatus != IfOperStatusDown )
            {
                bShow = FALSE;
            }

            //
            if ( bShow )
            {
                PrintNormalA ( "#%2ld\tName : %s\n", pAdapterAddress->Ipv6IfIndex, pAdapterAddress->AdapterName );
                PrintNormalW ( L"\tDescription : %s\n", pAdapterAddress->Description );
                PrintNormalW ( L"\tFriendly Name : %s\n", pAdapterAddress->FriendlyName );
                MacAddressToString ( pAdapterAddress->PhysicalAddress, pAdapterAddress->PhysicalAddressLength );
                PrintNormalW ( L"\tMAC : %s\n", MacAddressString );

                if ( wcslen(pAdapterAddress->DnsSuffix) > 0 )
                {
                    PrintNormalW ( L"\tDNS Suffix : %s\n", pAdapterAddress->DnsSuffix );
                }
                PrintNormalW ( L"\tMTU : %ld\n", pAdapterAddress->Mtu );
                PrintNormalW ( L"\tOper Status : %s\n", GetAdapterOperStatus ( pAdapterAddress->OperStatus ) );
                PrintNormalW ( L"\tType : %s\n", GetAdapterTypeValue ( pAdapterAddress->IfType ) );
                if ( pAdapterAddress->TunnelType != TUNNEL_TYPE_NONE )
                {
                    PrintNormalW ( L"\tTunnel Type : %s\n", GetAdapterTunnelType ( pAdapterAddress->TunnelType ) );
                }
                PrintNormalW ( L"\tSpeed S:%lld R:%lld\n", pAdapterAddress->TransmitLinkSpeed, pAdapterAddress->ReceiveLinkSpeed );

                //
                {
                    PIP_ADAPTER_UNICAST_ADDRESS pCurrentAddress = pAdapterAddress->FirstUnicastAddress;
                    if ( pCurrentAddress != NULL )
                    {
                        PrintNormalW ( L"\tIP :\n" );
                        for (   pCurrentAddress = pAdapterAddress->FirstUnicastAddress;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                            DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                            INT iRes =  WSAAddressToString(
                                pCurrentAddress->Address.lpSockaddr,        //  LPSOCKADDR          lpsaAddress,
                                pCurrentAddress->Address.iSockaddrLength,   //  DWORD               dwAddressLength,
                                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                IpV6StringW,                                //  LPSTR               lpszAddressString,
                                &dwAddressStringLength                      //  LPDWORD             lpdwAddressStringLength
                            );

                            PrintNormalW ( L"\t- %s ", IpV6StringW );

                            //
                            //  Resolve for adapter only when a MAC Address is present
                            ZeroMemory ( ResolvedHostname, sizeof(ResolvedHostname) );
                            if (    ResolveMode &&
                                    MacIsNotNull(pAdapterAddress->PhysicalAddress) &&
                                    pCurrentAddress->SuffixOrigin != IpSuffixOriginRandom )
                            {
                                ResolveOneHost ( IpV6StringW, ResolvedHostname, _wsizeof(ResolvedHostname) );
                                PrintNormalW ( L"(%s)", ResolvedHostname );
                            }

                            //
                            PrintNormalW ( L" P:%s", GetPrefixOrigin ( pCurrentAddress->PrefixOrigin  ) );
                            PrintNormalW ( L" S:%s", GetSuffixOrigin ( pCurrentAddress->SuffixOrigin  ) );
                            PrintNormalW ( L" %s", GetDadState ( pCurrentAddress->DadState ) );

                            //
                            if ( MacIsNotNull ( pAdapterAddress->PhysicalAddress ) && pCurrentAddress->SuffixOrigin != IpSuffixOriginRandom )
                            {
                                if ( wcschr (IpV6StringW, L':') == NULL )
                                {
                                    bool bModified = StoreArpAddress (IpV6StringW, MacAddressString, ResolvedHostname, 4 );
                                    if ( bModified )
                                    {
                                        PrintNormalW ( L" +" );
                                    }
                                }
                                else
                                {
                                    bool bModified = StoreArpAddress (IpV6StringW, MacAddressString, ResolvedHostname, 6 );
                                    if ( bModified )
                                    {
                                        PrintNormalW ( L" +" );
                                    }
                                }
                            }

                            //
                            PrintNormalW ( L"\n" );

                        }
                    }
                }

                //
                {
                    PIP_ADAPTER_DNS_SERVER_ADDRESS pCurrentAddress = pAdapterAddress->FirstDnsServerAddress;
                    if ( pCurrentAddress != NULL )
                    {
                        int DNSCount = 0;
                        for (   pCurrentAddress = pAdapterAddress->FirstDnsServerAddress;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            if ( ( DNSCount % 4 ) == 0 )
                            {
                                if ( DNSCount > 0 )
                                {
                                    PrintNormalW ( L"\n" );
                                }
                                PrintNormalW ( L"\tDNS :" );
                            }
                            DNSCount++;
                            ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                            DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                            INT iRes =  WSAAddressToString(
                                pCurrentAddress->Address.lpSockaddr,        //  LPSOCKADDR          lpsaAddress,
                                pCurrentAddress->Address.iSockaddrLength,   //  DWORD               dwAddressLength,
                                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                IpV6StringW,                                //  LPSTR               lpszAddressString,
                                &dwAddressStringLength                      //  LPDWORD             lpdwAddressStringLength
                            );

                            PrintNormalW ( L" %s ", IpV6StringW );
                        }

                        PrintNormalW ( L"\n" );
                    }
                }

                //
                {
                    PIP_ADAPTER_GATEWAY_ADDRESS pCurrentAddress = pAdapterAddress->FirstGatewayAddress;
                    if ( pCurrentAddress != NULL )
                    {
                        PrintNormalW ( L"\tGW :" );
                        for (   pCurrentAddress = pAdapterAddress->FirstGatewayAddress;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                            DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                            INT iRes =  WSAAddressToString(
                                pCurrentAddress->Address.lpSockaddr,        //  LPSOCKADDR          lpsaAddress,
                                pCurrentAddress->Address.iSockaddrLength,   //  DWORD               dwAddressLength,
                                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                IpV6StringW,                                //  LPSTR               lpszAddressString,
                                &dwAddressStringLength                      //  LPDWORD             lpdwAddressStringLength
                            );

                            PrintNormalW ( L" %s ", IpV6StringW );
                        }

                        PrintNormalW ( L"\n" );
                    }
                }

                //
                {
                    PIP_ADAPTER_WINS_SERVER_ADDRESS pCurrentAddress = pAdapterAddress->FirstWinsServerAddress;
                    if ( pCurrentAddress != NULL )
                    {
                        PrintNormalW ( L"\tWIN :" );
                        for (   pCurrentAddress = pAdapterAddress->FirstWinsServerAddress;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                            DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                            INT iRes =  WSAAddressToString(
                                pCurrentAddress->Address.lpSockaddr,        //  LPSOCKADDR          lpsaAddress,
                                pCurrentAddress->Address.iSockaddrLength,   //  DWORD               dwAddressLength,
                                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                IpV6StringW,                                //  LPSTR               lpszAddressString,
                                &dwAddressStringLength                      //  LPDWORD             lpdwAddressStringLength
                            );

                            PrintNormalW ( L" %s ", IpV6StringW );
                        }
                        while ( pCurrentAddress );

                        PrintNormalW ( L"\n" );
                    }
                }

                //
                {
                    PIP_ADAPTER_ANYCAST_ADDRESS pCurrentAddress = pAdapterAddress->FirstAnycastAddress;
                    if ( pCurrentAddress != NULL )
                    {
                        PrintNormalW ( L"\tAC :" );
                        for (   pCurrentAddress = pAdapterAddress->FirstAnycastAddress;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                            DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                            INT iRes =  WSAAddressToString(
                                pCurrentAddress->Address.lpSockaddr,        //  LPSOCKADDR          lpsaAddress,
                                pCurrentAddress->Address.iSockaddrLength,   //  DWORD               dwAddressLength,
                                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                IpV6StringW,                                //  LPSTR               lpszAddressString,
                                &dwAddressStringLength                      //  LPDWORD             lpdwAddressStringLength
                            );

                            PrintNormalW ( L" %s ", IpV6StringW );
                        }

                        PrintNormalW ( L"\n" );
                    }
                }

                //
                {
                    PIP_ADAPTER_MULTICAST_ADDRESS pCurrentAddress = pAdapterAddress->FirstMulticastAddress;
                    if ( pCurrentAddress != NULL )
                    {
                        int MCCount = 0;
                        for (   pCurrentAddress = pAdapterAddress->FirstMulticastAddress;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            if ( ( MCCount % 4 ) == 0 )
                            {
                                if ( MCCount > 0 )
                                {
                                    PrintNormalW ( L"\n" );
                                }
                                PrintNormalW ( L"\tMC :" );
                            }
                            MCCount++;
                            ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                            DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                            INT iRes =  WSAAddressToString(
                                pCurrentAddress->Address.lpSockaddr,        //  LPSOCKADDR          lpsaAddress,
                                pCurrentAddress->Address.iSockaddrLength,   //  DWORD               dwAddressLength,
                                NULL,                                       //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                IpV6StringW,                                //  LPSTR               lpszAddressString,
                                &dwAddressStringLength                      //  LPDWORD             lpdwAddressStringLength
                            );

                            PrintNormalW ( L" %s ", IpV6StringW );
                        }

                        PrintNormalW ( L"\n" );
                    }
                }

                //
                {
                    PIP_ADAPTER_DNS_SUFFIX pCurrentAddress = pAdapterAddress->FirstDnsSuffix;
                    if ( pCurrentAddress != NULL )
                    {
                        PrintNormalW ( L"\tDNS :" );
                        for (   pCurrentAddress = pAdapterAddress->FirstDnsSuffix;
                                pCurrentAddress != NULL;
                                pCurrentAddress = pCurrentAddress->Next )
                        {
                            PrintNormalW ( L" %s ", pCurrentAddress->String );
                        }
                        while ( pCurrentAddress );

                        PrintNormalW ( L"\n" );
                    }
                }
            }
        }

    }

    //
    free ( AdapterAddresses );
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetAdaptatorType(UINT type)
{
    switch ( type )
    {
    case MIB_IF_TYPE_OTHER : return L"Other";
    case MIB_IF_TYPE_ETHERNET : return L"Ethernet";
    case MIB_IF_TYPE_TOKENRING: return L"TokenRing";
    case MIB_IF_TYPE_FDDI : return L"FDDI";
    case MIB_IF_TYPE_PPP: return L"PPP";
    case MIB_IF_TYPE_LOOPBACK: return L"LoopBack";
    case MIB_IF_TYPE_SLIP: return L"SLIP";
    case IF_TYPE_IEEE80211 : return L"IEEE80211";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetNodeType(UINT nodeType)
{
    switch ( nodeType )
    {
    case BROADCAST_NODETYPE  : return L"BROADCAST";
    case PEER_TO_PEER_NODETYPE  : return L"PEER_TO_PEER";
    case MIXED_NODETYPE : return L"MIXED";
    case HYBRID_NODETYPE : return L"HYBRID";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void ShowAdapters()
{
    //
    {
        ULONG dwFixedInfo = 20 * sizeof(FIXED_INFO);
        PFIXED_INFO pFixedInfo = (PFIXED_INFO) malloc ( dwFixedInfo );
        ZeroMemory ( pFixedInfo, dwFixedInfo );
        DWORD dwRes = GetNetworkParams ( pFixedInfo, &dwFixedInfo );
        if ( dwRes == ERROR_SUCCESS )
        {
            PrintNormalA ( "\tHost name      : %s", pFixedInfo->HostName );
            PrintNormalA ( " - Domain name : %s\n", pFixedInfo->DomainName );
            PIP_ADDR_STRING  dnsServerLIst = &pFixedInfo->DnsServerList;
            PrintNormalA ( "\tDNS Servers    : ", dnsServerLIst->IpAddress.String );
            for ( dnsServerLIst = &pFixedInfo->DnsServerList; dnsServerLIst != NULL; dnsServerLIst = dnsServerLIst->Next )
            {
                PrintNormalA ( "%s ", dnsServerLIst->IpAddress.String );
            }
            PrintNormalA ( "\n" );
            PrintNormalW ( L"\tNode Type      : %s\n", GetNodeType(pFixedInfo->NodeType) );
            PrintNormalA ( "\tDHCP Scope Id  : %s\n", pFixedInfo->ScopeId );
            PrintNormalA ( "\tEnable Routing : %d", pFixedInfo->EnableRouting );
            PrintNormalA ( " - Enable Arp Proxy : %d", pFixedInfo->EnableProxy );
            PrintNormalA ( " - Enable DNS : %d\n", pFixedInfo->EnableDns );
            PrintNormalA ( "\n" );
        }
        else
        {
            PrintStderr ( L"GetNetworkParams error %ld\n", dwRes );
        }

        if ( pFixedInfo )
        {
            free ( pFixedInfo );
        }
    }

    //
    {
        DWORD dwBufLen      = sizeof(IP_ADAPTER_INFO) * 16;
        PIP_ADAPTER_INFO AdapterInfo = ( PIP_ADAPTER_INFO ) malloc ( dwBufLen );

        //
        DWORD dwResult = GetAdaptersInfo (
            AdapterInfo,    //  _Out_    PIP_ADAPTER_INFO pAdapterInfo,
            &dwBufLen       // _Inout_  PULONG pOutBufLen
        );

        //
        if ( ERROR_SUCCESS != ERROR_BUFFER_OVERFLOW )
        {
            free ( AdapterInfo );
            AdapterInfo = ( PIP_ADAPTER_INFO ) malloc ( dwBufLen );
            DWORD dwResult = GetAdaptersInfo (
                AdapterInfo,    //  _Out_    PIP_ADAPTER_INFO pAdapterInfo,
                &dwBufLen       // _Inout_  PULONG pOutBufLen
            );
        }

        //
        if ( ERROR_SUCCESS != dwResult )
        {
            free ( AdapterInfo );
            PrintStderrW ( L"Error : GetAdaptersInfo %d\n", dwResult );
            return;
        }

        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        for (  pAdapterInfo = AdapterInfo; pAdapterInfo != NULL; pAdapterInfo = pAdapterInfo->Next )
        {
            if ( ! NonZeroMac || MacIsNotNull ( pAdapterInfo->Address ) )
            {
                PrintNormalA ( "#%2d\tName : %s\n", pAdapterInfo->Index, pAdapterInfo->AdapterName );
                PrintNormalA ( "\tDescription : %s\n", pAdapterInfo->Description );
                MacAddressToString ( pAdapterInfo->Address, pAdapterInfo->AddressLength );
                PrintNormalW ( L"\tMAC : %s\n", MacAddressString );
                PrintNormalW ( L"\tType: %s\n", GetAdaptatorType(pAdapterInfo->Type) );


                //
                PIP_ADDR_STRING pCurrentAddress = pAdapterInfo->CurrentIpAddress;
                for ( pCurrentAddress = pAdapterInfo->CurrentIpAddress; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next )
                {
                    PrintNormalA ( "\tCUR IP : %-16s", pCurrentAddress->IpAddress.String );
                    PrintNormalA ( "\n" );
                }

                //
                pCurrentAddress = &pAdapterInfo->IpAddressList;
                for ( pCurrentAddress = &pAdapterInfo->IpAddressList; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next )
                {
                    PrintNormalA ( "\tIP : %-16s ", pCurrentAddress->IpAddress.String );
                    ZeroMemory ( IpV4StringW, sizeof(IpV4StringW) );
                    BOOL bErrors = false;
                    ConvertMBCSToWC ( pCurrentAddress->IpAddress.String, strlen(pCurrentAddress->IpAddress.String), IpV4StringW, sizeof(IpV4StringW), CP_ACP, bErrors );

                    PrintNormalA ( " - Mask : %-16s ", pCurrentAddress->IpMask.String );
                    ZeroMemory ( ResolvedHostname, sizeof(ResolvedHostname) );

                    //  Resolved for adapter only when MAC address s not null
                    if ( ResolveMode && MacIsNotNull ( pAdapterInfo->Address ) )
                    {
                        ResolveOneHost ( IpV4StringW, ResolvedHostname, _wsizeof(ResolvedHostname) );
                        PrintNormalW ( L"(%s)", ResolvedHostname );
                    }

                    if ( MacIsNotNull ( pAdapterInfo->Address ) )
                    {
                        bool bModified = StoreArpAddress (IpV4StringW, MacAddressString, ResolvedHostname, 4 );
                        if ( bModified )
                        {
                            PrintNormalA ( " +" );
                        }
                    }
                    PrintNormalA ( "\n" );
                }

                //
                for ( pCurrentAddress = &pAdapterInfo->GatewayList; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next )
                {
                    PrintNormalA ( "\tGW : %-16s ", pCurrentAddress->IpAddress.String );
                    PrintNormalA ( " - Mask : %-16s ", pCurrentAddress->IpMask.String );
                    PrintNormalA ( "\n" );
                }

                //
                if ( pAdapterInfo->HaveWins )
                {
                    ;
                    for ( pCurrentAddress = &pAdapterInfo->PrimaryWinsServer; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next )
                    {
                        PrintNormalA ( "\tWINS : %-16s ", pCurrentAddress->IpAddress.String );
                        PrintNormalA ( " - Mask : %-16s ", pCurrentAddress->IpMask.String );
                        PrintNormalA ( "\n" );
                    }


                    for ( pCurrentAddress = &pAdapterInfo->SecondaryWinsServer; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next )
                    {
                        PrintNormalA ( "\tWINS : %-16s ", pCurrentAddress->IpAddress.String );
                        PrintNormalA ( " - Mask : %-16s ", pCurrentAddress->IpMask.String );
                        PrintNormalA ( "\n" );
                    }
                }
            }
        }

        free ( AdapterInfo );
    }

    //
    {
        PrintNormalW ( L"\n" );
        DWORD dwBufLen      = sizeof(IP_INTERFACE_INFO) * 16;
        PIP_INTERFACE_INFO InterfaceInfo = ( PIP_INTERFACE_INFO ) malloc ( dwBufLen );

        //
        DWORD dwResult = GetInterfaceInfo (
            InterfaceInfo,      //  _Out_    PIP_ADAPTER_INFO pAdapterInfo,
            &dwBufLen           // _Inout_  PULONG pOutBufLen
        );

        //
        if ( ERROR_SUCCESS != ERROR_BUFFER_OVERFLOW )
        {
            free ( InterfaceInfo );
            InterfaceInfo = ( PIP_INTERFACE_INFO ) malloc ( dwBufLen );
            DWORD dwResult = GetInterfaceInfo (
                InterfaceInfo,  //  _Out_    PIP_INTERFACE_INFO pAdapterInfo,
                &dwBufLen       // _Inout_  PULONG pOutBufLen
            );
        }

        //
        if ( ERROR_SUCCESS != dwResult )
        {
            free ( InterfaceInfo );
            PrintStderrW ( L"Error : GetInterfaceInfo %d\n", dwResult );
            return;
        }

        PIP_INTERFACE_INFO pInterfaceInfo = InterfaceInfo;
        for ( int i = 0; i < pInterfaceInfo->NumAdapters; i++ )
        {
            PrintNormalW ( L"#%2d\tName : %s\n", pInterfaceInfo->Adapter [ i ].Index, pInterfaceInfo->Adapter [ i ].Name );
        }
        
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void GetSubnets()
{
    //
    {
        DWORD dwBufLen      = sizeof(IP_ADAPTER_INFO) * 16;
        PIP_ADAPTER_INFO AdapterInfo = ( PIP_ADAPTER_INFO ) malloc ( dwBufLen );

        //
        DWORD dwResult = GetAdaptersInfo (
            AdapterInfo,    //  _Out_    PIP_ADAPTER_INFO pAdapterInfo,
            &dwBufLen       // _Inout_  PULONG pOutBufLen
        );

        //
        if ( ERROR_SUCCESS != ERROR_BUFFER_OVERFLOW )
        {
            free ( AdapterInfo );
            AdapterInfo = ( PIP_ADAPTER_INFO ) malloc ( dwBufLen );
            DWORD dwResult = GetAdaptersInfo (
                AdapterInfo,    //  _Out_    PIP_ADAPTER_INFO pAdapterInfo,
                &dwBufLen       // _Inout_  PULONG pOutBufLen
            );
        }

        //
        if ( ERROR_SUCCESS != dwResult )
        {
            free ( AdapterInfo );
            PrintStderrW ( L"Error : GetAdaptersInfo %d\n", dwResult );
            return;
        }

        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        for ( pAdapterInfo = AdapterInfo; pAdapterInfo != NULL; pAdapterInfo = pAdapterInfo->Next )
        {
            if ( MacIsNotNull ( pAdapterInfo->Address ) )
            {
                MacAddressToString ( pAdapterInfo->Address, pAdapterInfo->AddressLength );

                //
                PIP_ADDR_STRING pCurrentAddress = &pAdapterInfo->IpAddressList;
                for ( pCurrentAddress = &pAdapterInfo->IpAddressList; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next )
                {
                    BOOL bErrors = false;
                    ZeroMemory ( IpV4StringW, sizeof(IpV4StringW) );
                    if ( SubnetListCount < MAX_SUBNET_LIST )
                    {
                        ConvertMBCSToWC ( pCurrentAddress->IpAddress.String, strlen(pCurrentAddress->IpAddress.String), IpV4StringW, sizeof(IpV4StringW), CP_ACP, bErrors );
                        wcscpy_s ( SubnetList [ SubnetListCount ].IPAddress, _wsizeof(SubnetList [ SubnetListCount ].IPAddress), IpV4StringW );
                        GetINetAddr4 ( IpV4StringW, &SubnetList [ SubnetListCount ].IP );
                        ConvertMBCSToWC ( pCurrentAddress->IpMask.String, strlen(pCurrentAddress->IpMask.String), IpV4StringW, sizeof(IpV4StringW), CP_ACP, bErrors );
                        wcscpy_s ( SubnetList [ SubnetListCount ].IPMask, _wsizeof(SubnetList [ SubnetListCount ].IPMask), IpV4StringW );
                        GetINetAddr4 ( IpV4StringW, &SubnetList [ SubnetListCount ].Mask );

                        SubnetListCount++;
                    }
                }
            }
        }

        //
        free ( AdapterInfo );
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
const WCHAR *GetStateValue ( NL_NEIGHBOR_STATE state )
{
    switch ( state )
    {
    case NlnsUnreachable : return L"Unreachable";
    case NlnsIncomplete : return L"Incomplete";
    case NlnsProbe : return L"Probe";
    case NlnsDelay : return L"Delay";
    case NlnsStale : return L"Stale";
    case NlnsReachable : return L"Reachable";
    case NlnsPermanent : return L"Permanent";
    case NlnsMaximum : return L"Maximum";
    default : return L"?";
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
bool IsIPV6Special ( IN6_ADDR *pAddr )
{
    if ( pAddr )
    {
        if ( pAddr->u.Byte [ 0 ] == 0xff || pAddr->u.Byte [ 0 ] == 0xfe )
        {
            return true;
        }
    }

    return false;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
bool MatchIPWithMAC ( SOCKADDR_INET *ipAddress, UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH] )
{
    int iMac = LEN_MAC - 3;
    for ( int i = 13; i < 16 && iMac < LEN_MAC; i++, iMac++ )
    {
        UCHAR uChar1 = ipAddress->Ipv6.sin6_addr.u.Byte [ i ];
        UCHAR uChar2 = PhysicalAddress [ iMac ];
        if ( uChar1 != uChar2 )
        {
            return false;
        }
    }

    return true;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
int CountMACAddress ( PMIB_IPNET_TABLE2 pIpNetTable, ADDRESS_FAMILY family, UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH] )
{
    int iCount = 0;
    for ( UINT i = 0; i < pIpNetTable->NumEntries; i++ )
    {
        if (    pIpNetTable->Table [ i ].PhysicalAddressLength != 0 &&
                pIpNetTable->Table [ i ].Address.si_family == family &&
                memcmp ( pIpNetTable->Table [ i ].PhysicalAddress, PhysicalAddress, pIpNetTable->Table [ i ].PhysicalAddressLength ) == 0 )
        {
            iCount++;
        }
    }

    return iCount;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void ShowArp64()
{
    PMIB_IPNET_TABLE2   pIpNetTable;

    //
    ADDRESS_FAMILY  Family = AF_UNSPEC;
    if ( IPv4Only )
    {
        Family  = AF_INET;
    }
    else if ( IPv6Only )
    {
        Family  = AF_INET6;
    }

    DWORD dwIpTable = GetIpNetTable2 (
        Family,         //  _In_   ADDRESS_FAMILY  Family,
        &pIpNetTable    //  _Out_  PMIB_IPNET_TABLE2 *Table
    );

    //
    if ( dwIpTable != NO_ERROR )
    {
        free ( pIpNetTable );

        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return;
    }

    //
    for ( UINT i = 0; i < pIpNetTable->NumEntries; i++ )
    {
        bool bModified = false;

        //
        MIB_IPNET_ROW2 row = pIpNetTable->Table [ i ];
        SOCKADDR_INET inetAddress   = row.Address;
        NET_IFINDEX index           = row.InterfaceIndex;
        UCHAR *macAddress           = row.PhysicalAddress;

        //  Same as IsRouter and IsUnreachable
        UCHAR flag                  = row.Flags;
        if ( ! NonZeroMac || MacIsNotNull ( macAddress ) )
        {
            MacAddressToString ( row.PhysicalAddress, row.PhysicalAddressLength );
            ZeroMemory ( szHostName, sizeof ( szHostName ) );

            if ( inetAddress.si_family  == AF_INET )
            {
                RtlIpv4AddressToStringW ( &inetAddress.Ipv4.sin_addr, IpV4StringW  );
                PrintNormalW ( L"#%2ld IPv4 : %-40s", index, IpV4StringW );

                //  Resolve for IPV4
                if (    IsInsideSubnet(IpV4StringW) &&
                        wcscmp ( MacAddressString, BROADCAST_ADDR ) != 0 &&
                        ( wcscmp ( MacAddressString, NULL_MAC_ADDR ) != 0 || ! row.IsUnreachable ) )
                {
                    ResolveOneHost ( IpV4StringW, szHostName, _wsizeof ( szHostName ) );
                }

                // char *ip = inet_ntoa ( * ( in_addr * ) & inetAddress.Ipv4.sin_addr );
                //PrintNormalA ( "#%2ld IPv4 : %-40s", index, ip );
            }
            else if ( inetAddress.si_family  == AF_INET6 )
            {
                ZeroMemory ( IpV6StringW, sizeof(IpV6StringW) );
                DWORD dwAddressStringLength = _wsizeof(IpV6StringW);
                INT iRes =  WSAAddressToString(
                    (LPSOCKADDR) &inetAddress.Ipv6,     //  LPSOCKADDR          lpsaAddress,
                    sizeof(inetAddress.Ipv6),           //  DWORD               dwAddressLength,
                    NULL,                               //  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                    IpV6StringW,                        //  LPSTR               lpszAddressString,
                    &dwAddressStringLength              //  LPDWORD             lpdwAddressStringLength
                );
                if ( iRes != 0 )
                {
                    int wsaLastError = WSAGetLastError();
                    FormatErrorMessage ( wsaLastError );
                    PrintStderrW ( L"Error : %d - %s\n", wsaLastError, szErrorText );
                }
                else
                {
                    PrintNormalW ( L"#%2ld IPv6 : %-40s", index, IpV6StringW );

                    //  Resolve for IPV6
                    if (    ! IsIPV6Special(&inetAddress.Ipv6.sin6_addr) &&
                            wcscmp(MacAddressString, BROADCAST_ADDR) != 0 &&
                            ( wcscmp ( MacAddressString, NULL_MAC_ADDR ) != 0 || ! row.IsUnreachable ) )
                    {
                        ResolveOneHost ( IpV6StringW, szHostName, _wsizeof ( szHostName ) );
                    }
                }
            }

            PrintNormalW ( L" MAC : %-20s", MacAddressString );

            //
            if ( PingMode )
            {
                if ( inetAddress.si_family  == AF_INET && wcslen(IpV4StringW) > 0 && IsInsideSubnet ( IpV4StringW ) )
                {
                    PingAddress ( IpV4StringW );
                }
                else if ( inetAddress.si_family  == AF_INET6 && wcslen(IpV6StringW) > 0 && ! IsIPV6Special(&inetAddress.Ipv6.sin6_addr) )
                {
                    PingAddress ( IpV6StringW );
                }
            }

            //
            if ( MacIsNotNull ( macAddress ) )
            {
                //  Only ForIPV4
                if ( inetAddress.si_family  == AF_INET )
                {
                    bModified = StoreArpAddress ( IpV4StringW, MacAddressString, szHostName, 4 );
                }
                else if ( inetAddress.si_family  == AF_INET6 && ! IsIPV6Special(&inetAddress.Ipv6.sin6_addr) )
                {
                    int macCount = CountMACAddress ( pIpNetTable, inetAddress.si_family, row.PhysicalAddress );
                    if ( MatchIPWithMAC ( &inetAddress, row.PhysicalAddress ) || ! IPMatchMac )
                    {
                        bModified = StoreArpAddress ( IpV6StringW, MacAddressString, szHostName, 6 );
                    }
                }
            }

            if ( row.IsRouter )
            {
                PrintNormalW ( L" %-10s", L"Router" );
            }
            else
            {
                PrintNormalW ( L" %-10s", L"-" );
            }

            //
            if ( row.IsUnreachable )
            {
                PrintNormalW ( L" %-12s", L"Unreachable" );
            }
            else
            {
                PrintNormalW ( L" %-12s", L"Reachable" );
            }

            PrintNormalW ( L" %-12s", GetStateValue ( row.State ) );

            PrintNormalW ( L" %10ld", row.ReachabilityTime.LastReachable );

            if ( ResolveMode )
            {
                PrintNormalW ( L" : %s", szHostName );
            }

            if( bModified )
            {
                PrintNormalW ( L" +" );
            }

            //
            PrintNormalW ( L"\n" );
        }
    }

    //
    FreeMibTable(pIpNetTable);
}


//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
void ShowArp()
{
    PMIB_IPNETTABLE pIpNetTable     = (PMIB_IPNETTABLE) malloc ( sizeof(MIB_IPNETTABLE) );
    DWORD           dwSize          = sizeof(MIB_IPNETTABLE);
    BOOL            order           = TRUE;

    //
    DWORD dwIpTable = GetIpNetTable (
        pIpNetTable,    //  _Out_    PMIB_IPNETTABLE pIpNetTable,
        &dwSize,        //  _Inout_  PULONG pdwSize,
        order           //  _In_     BOOL bOrder
    );

    if ( dwIpTable == ERROR_INSUFFICIENT_BUFFER )
    {
        free ( pIpNetTable );
        pIpNetTable     = (PMIB_IPNETTABLE) malloc ( dwSize );
    }

    //
    dwIpTable = GetIpNetTable (
        pIpNetTable,            //  _Out_    PMIB_IPNETTABLE pIpNetTable,
        &dwSize,        //  _Inout_  PULONG pdwSize,
        order           //  _In_     BOOL bOrder
    );

    if ( dwIpTable != NO_ERROR )
    {
        free ( pIpNetTable );

        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return ;
    }

    //
    for ( UINT i = 0; i < pIpNetTable->dwNumEntries; i++ )
    {
        MIB_IPNETROW row = pIpNetTable->table [ i ];
        if ( ! NonZeroMac || MacIsNotNull ( row.bPhysAddr ) )
        {
            MacAddressToString ( row.bPhysAddr, row.dwPhysAddrLen );
            ZeroMemory ( szHostName, sizeof ( szHostName ) );
            RtlIpv4AddressToStringW ( ( in_addr * ) & row.dwAddr, IpV4StringW  );
            PrintNormalW ( L"#%2ld IPv4 : %-40s", row.dwIndex, IpV4StringW );

            //  Resolved for IPV4
            if (    IsInsideSubnet(IpV4StringW) &&
                    wcscmp ( MacAddressString, BROADCAST_ADDR ) != 0 &&
                    wcscmp ( MacAddressString, NULL_MAC_ADDR ) != 0 )
            {
                ResolveOneHost ( IpV4StringW, szHostName, _wsizeof ( szHostName ) );
            }

            // char *ip = inet_ntoa ( * ( in_addr * ) & row.dwAddr );
            // PrintNormalA ( "#%2d IP : %-40s", row.dwIndex, ip );
            PrintNormalW ( L" MAC : %-20s", MacAddressString );
            if ( ResolveMode )
            {
                PrintNormalW ( L" : %s", szHostName );
            }

            //
            if ( PingMode && IsInsideSubnet ( IpV4StringW ) )
            {
                PingAddress ( IpV4StringW );
            }

            //
            if ( MacIsNotNull ( row.bPhysAddr )  )
            {
                //
                bool bModified = StoreArpAddress ( IpV4StringW, MacAddressString, szHostName, 4 );
                if ( bModified )
                {
                    PrintNormalW ( L" +" );
                }
            }

            PrintNormalW ( L"\n" );

        }
    }

    //
    free ( pIpNetTable );

}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL GetLocalMacAddress ( WCHAR *pAddress )
{
    //
    PrintStdoutW ( L"GetLocalMacAddress\n" );

    //
    ZeroMemory ( MacFound, sizeof(MacFound) );

    //
    IN_ADDR InAddr;
    ZeroMemory ( &InAddr, sizeof(InAddr) );

    BOOL bFound = GetAddressW ( pAddress, &InAddr );
    if ( ! bFound )
    {
        return FALSE;
    }

    //
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);

    DWORD dwResult = GetAdaptersInfo (
        AdapterInfo,    //  _Out_    PIP_ADAPTER_INFO pAdapterInfo,
        &dwBufLen       // _Inout_  PULONG pOutBufLen
    );

    //
    if ( ERROR_SUCCESS != dwResult )
    {
        PrintStderrW ( L"Error : GetAdaptersInfo %d\n", dwResult );
        return FALSE;
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    do
    {
        if ( pAdapterInfo->Address != NULL )        // Address not null
        {
            //
            IN_ADDR InAddrCurrent;
            BOOL bFound = GetAddressA ( pAdapterInfo->IpAddressList.IpAddress.String, &InAddrCurrent );

            //  Found
            if ( bFound )
            {
                //
                //  Same Address
                if ( InAddrCurrent.S_un.S_addr == InAddr.S_un.S_addr )
                {
                    BYTE *macAdress = pAdapterInfo->Address;
                    BOOL bMacValid = MacIsNotNull ( macAdress );
                    if ( bMacValid )
                    {
                        MacAddressToString ( macAdress, pAdapterInfo->AddressLength );
                        PrintStdoutW ( L"MAC found for %-40s : %-20s\n", pAddress, MacAddressString );

                        //
                        if ( wcslen ( MacFound ) == 0 )
                        {
                            for ( int j = 0; j < 6; j++ )
                            {
                                swprintf_s ( MacFound + wcslen(MacFound), _wsizeof(MacFound) -  wcslen(MacFound), L"%02X", macAdress [ j ] );
                                if ( j < 5 )
                                {
                                    wcscat_s ( MacFound, _wsizeof(MacFound), L":" );
                                }
                            }
                        }
                    }

                }   //  Same Address

            }   // Result OK

        }   // Address not null

        //  Next Adapter
        pAdapterInfo = pAdapterInfo->Next;
    }
    while ( pAdapterInfo );

    //
    if ( wcslen ( MacFound ) > 0 )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
BOOL GetMacAddress ( WCHAR *pAddress )
{
    //
    PrintStdoutW ( L"GetMacAddress\n" );

    //
    ZeroMemory ( MacFound, sizeof(MacFound) );

    //
    IN_ADDR InAddr;
    ZeroMemory ( &InAddr, sizeof(InAddr) );

    BOOL bFound = GetAddressW ( pAddress, &InAddr );
    if ( ! bFound )
    {
        return FALSE;
    }

    //
#if USE_RTL_STRING_TO_IP4
    const WCHAR *terminator;
    LONG lResult = (*RtlIpv4StringToAddressW)(
        pAddress,           //  _In_   PCTSTR S,
        FALSE,              //  _In_   BOOLEAN Strict,
        &terminator,        // _Out_  LPCTSTR *Terminator,
        &InAddr             // _Out_  IN_ADDR *Addr
    );
#endif

    PMIB_IPNETTABLE pIpNetTable     = (PMIB_IPNETTABLE) malloc ( sizeof(MIB_IPNETTABLE) );
    DWORD           dwSize          = sizeof(MIB_IPNETTABLE);
    BOOL            order           = TRUE;

    //
    DWORD dwIpTable = GetIpNetTable (
        pIpNetTable,    //  _Out_    PMIB_IPNETTABLE pIpNetTable,
        &dwSize,        //  _Inout_  PULONG pdwSize,
        order           //  _In_     BOOL bOrder
    );

    if ( dwIpTable == ERROR_INSUFFICIENT_BUFFER )
    {
        free ( pIpNetTable );
        pIpNetTable     = (PMIB_IPNETTABLE) malloc ( dwSize );
    }

    //
    dwIpTable = GetIpNetTable (
        pIpNetTable,            //  _Out_    PMIB_IPNETTABLE pIpNetTable,
        &dwSize,        //  _Inout_  PULONG pdwSize,
        order           //  _In_     BOOL bOrder
    );

    if ( dwIpTable != NO_ERROR )
    {
        free ( pIpNetTable );

        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return FALSE;
    }

    //
    for ( UINT i = 0; i < pIpNetTable->dwNumEntries; i++ )
    {
        //
        if ( ( pIpNetTable->table[i].dwAddr ) == InAddr.S_un.S_addr )
        {
            BYTE *macAdress = (BYTE*) & pIpNetTable->table [ i ].bPhysAddr;
            BOOL bMacValid = MacIsNotNull ( macAdress );
            if ( bMacValid )
            {
                MacAddressToString ( macAdress, pIpNetTable->table [ i ].dwPhysAddrLen );
                PrintStdoutW ( L"MAC found : %-20s\n", MacAddressString );

                //
                if ( wcslen ( MacFound ) == 0 )
                {
                    for ( int j = 0; j < 6; j++ )
                    {
                        swprintf_s ( MacFound + wcslen(MacFound), _wsizeof(MacFound) -  wcslen(MacFound), L"%02X", macAdress [ j ] );
                        if ( j < 5 )
                        {
                            wcscat_s ( MacFound, _wsizeof(MacFound), L":" );
                        }
                    }
                }
            }
        }
    }

    //
    free ( pIpNetTable );

    if ( wcslen ( MacFound ) > 0 )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

//
////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////
DWORD Execute ( WCHAR *pCommandLine, LPCTSTR lpCurrentDirectory, WCHAR *output )
{
    //
    //      Set A False Return code
    DWORD ExitCode = PROCESS_CREATION_FAILED;

    //
    PrintStdoutW ( L"Executing : '%s'\n", pCommandLine );
    DWORD dwCreationFlags   = NULL;

    SECURITY_ATTRIBUTES SecurityAttributes;
    memset ( &SecurityAttributes, 0, sizeof ( SecurityAttributes ) );
    SecurityAttributes.nLength          = sizeof(SecurityAttributes);
    SecurityAttributes.bInheritHandle   = TRUE;

    STARTUPINFO StartupInfo;
    memset ( &StartupInfo, 0, sizeof ( StartupInfo ) );
    StartupInfo.cb = sizeof ( StartupInfo );
    HANDLE hOutputFile = NULL;
    if ( output != NULL )
    {
        DWORD dwDesiredAccess       = NULL;
        dwDesiredAccess             |= GENERIC_READ;
        dwDesiredAccess             |= GENERIC_WRITE;

        DWORD dwShareMode           = NULL;
        dwShareMode                 |= FILE_SHARE_READ;
        dwShareMode                 |= FILE_SHARE_WRITE;
        dwShareMode                 |= FILE_SHARE_DELETE;

        DWORD dwCreationDisposition = NULL;
        dwCreationDisposition       |= CREATE_ALWAYS;

        WORD dwFlagsAndAttributes   = NULL;
        dwFlagsAndAttributes        |= FILE_ATTRIBUTE_NORMAL;

        hOutputFile =
            CreateFile(
                output,                     //  __in   LPCTSTR lpFileName,
                dwDesiredAccess,            //  __in   DWORD dwDesiredAccess,
                dwShareMode,                // __in   DWORD dwShareMode,
                &SecurityAttributes,        //  __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                dwCreationDisposition,      // __in   DWORD dwCreationDisposition,
                dwFlagsAndAttributes,       // __in   DWORD dwFlagsAndAttributes,
                NULL                        // __in_opt HANDLE hTemplateFile
            );

        if ( hOutputFile == NULL )
        {
            PrintStderrW (L"Error - CreateFile - Unable to open %s\n", output);
        }

        StartupInfo.hStdInput   = NULL;
        StartupInfo.hStdOutput  = hOutputFile;
        StartupInfo.hStdError   = hOutputFile;
        StartupInfo.dwFlags     |= STARTF_USESTDHANDLES;
    }

    PROCESS_INFORMATION ProcessInformation;
    memset ( &ProcessInformation, 0, sizeof ( ProcessInformation ) );

    PrintStdoutW ( L"Process : Starting Process...\n" );
    PrintStdoutW ( L"Command Line :\n%s\n", pCommandLine );

    BOOL bCreated =
        CreateProcess(
            NULL,                   //  __in_opt   LPCTSTR lpApplicationName,
            pCommandLine,           //  __inout_opt LPTSTR lpCommandLine,
            &SecurityAttributes,    //  __in_opt   LPSECURITY_ATTRIBUTES lpProcessAttributes,
            NULL,                   //  __in_opt   LPSECURITY_ATTRIBUTES lpThreadAttributes,
            TRUE,                   //  __in     BOOL bInheritHandles,
            dwCreationFlags,        //  __in     DWORD dwCreationFlags,
            NULL,                   //  __in_opt   LPVOID lpEnvironment,
            lpCurrentDirectory,     //  __in_opt   LPCTSTR lpCurrentDirectory,
            &StartupInfo,           //  __in     LPSTARTUPINFO lpStartupInfo,
            &ProcessInformation     //  __out LPPROCESS_INFORMATION lpProcessInformation
    );

    if ( bCreated )
    {
        PrintStdoutW (  L"Process : Started...\n" );

        //
        WaitForSingleObject ( ProcessInformation.hProcess, INFINITE );
        BOOL bExitCode =
            GetExitCodeProcess(
                ProcessInformation.hProcess,    // __in  HANDLE hProcess,
                &ExitCode                       // __out LPDWORD lpExitCode
            );
        if ( ExitCode == 0 )
        {
            PrintStdoutW ( L"Process : Exit Code : %ld (0x%lx)\n", ExitCode, ExitCode );
        }
        else
        {
            PrintStdoutW ( L"Process : Exit Code : %ld (0x%lx)\n", ExitCode, ExitCode );
        }
        CloseHandle( ProcessInformation.hProcess );
        CloseHandle( ProcessInformation.hThread );
        PrintStdoutW ( L"Process : Ended...\n" );
    }
    else
    {
        PrintStderrW ( L"Process : Error Creating Process\n" );
    }

    if ( hOutputFile != NULL )
    {
        CloseHandle ( hOutputFile );
    }

    return ExitCode;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
int PrintHelp(int iArgCount, WCHAR* pArgValues[], bool bLong )
{
    int iWidth = 30;

    PrintHelpLine ( iWidth, PROGRAM_NAME_P, PROGRAM_DATE_F, PROGRAM_VERSION );
    PrintHelpLine ( );
    PrintHelpLine ( iWidth, L"Usage", PROGRAM_NAME, L"[Options] MACAddress [MACAddress...]" );
    PrintHelpLine ( iWidth, L"Usage", PROGRAM_NAME, L"[Options] hostname [hostname...]" );
    PrintHelpLine ( );
    PrintHelpLine ( iWidth, L"-h, -?, -help", L"print help" );
    PrintHelpLine ( iWidth, L"-hl, -lh, -helplong", L"print long help" );
    PrintHelpLine ( );

    //  Actions
    PrintHelpLine ( iWidth, L"-a4, -arp", L"show arp table for IPv4" );
    PrintHelpLine ( iWidth, L"-a6, -arp6", L"show arp table for IPv4 and IPv6" );
    PrintHelpLine ( iWidth, L"-d4, -adapter", L"show local adapter for IPv4" );
    PrintHelpLine ( iWidth, L"-d6, -adapter6", L"show local adapter for IPv4 and IPv6" );
    PrintHelpLine ( iWidth, L"-dnsqueryex", L"Use DnsQueryEx (Windows 8 and Above)" );
    if ( bLong )
    {
        PrintHelpLine ( iWidth, L"", L"This Enable to use IPV6 DNS Server" );
    }
    PrintHelpLine ( iWidth, L"-l, -list", L"show ip and mac addresses known in .ini file" );
    PrintHelpLine ( iWidth, L"-mac ipaddr", L"search mac for an ip address and store it in .ini file" );
    PrintHelpLine ( iWidth, L"-pingsub", L"Ping All Hosts in Subnet" );
    PrintHelpLine ( iWidth, L"-pinglist file", L"Ping A List Of Host from a file" );
    if ( bLong )
    {
        PrintHelpLine ( iWidth, L"", L"First Argument is An IP Address" );
    }
    if ( bLong )
    {
        PrintHelpLine ( iWidth, L"-query a", L"query a dns server (with -s) for an address" );
        PrintHelpLine ( iWidth, L"-querytype t", L"query type (PTR...)" );
    }
    PrintHelpLine ( iWidth, L"-subnet", L"Send wake to a specific subnet" );
    PrintHelpLine ( iWidth, L"-wake", L"wake MAC Address (optional)" );
    PrintHelpLine ( );

    //  Flags
    PrintHelpLine ( iWidth, L"-4, -ipv4", L"before -adapter6 and -arp6 filters output" );
    PrintHelpLine ( iWidth, L"-6, -ipv6", L"before -adapter6 and -arp6 filters output" );
    PrintHelpLine ( iWidth, L"-debug", L"debug mode" );
    PrintHelpLine ( iWidth, L"-down", L"show only items in DOWN State" );
    PrintHelpLine ( iWidth, L"-imm", L"IP Match MAC for IPV6 (Generally for NAS and Windows)" );
    PrintHelpLine ( iWidth, L"-locale locale", L"set locale fr-fr or .1252" );
    PrintHelpLine ( iWidth, L"-noimm", L"IP Does not Match MAC for IPV6" );
    PrintHelpLine ( iWidth, L"-nz", L"show only items with non zero MAC" );
    PrintHelpLine ( iWidth, L"-ping", L"Ping Hosts During -arp" );
    PrintHelpLine ( iWidth, L"-q, -quiet", L"quiet mode" );
    PrintHelpLine ( iWidth, L"-r, -resolve", L"Resolve Hostname for -arp or -adapter" );
    PrintHelpLine ( iWidth, L"-s, -server dns", L"DNS Server" );
    PrintHelpLine ( iWidth, L"-timeout t", L"Time Out for Ping" );
    PrintHelpLine ( iWidth, L"-up", L"show only items in UP State" );
    PrintHelpLine ( iWidth, L"-v, -verbose", L"verbose mode" );

    //
    PrintHelpLine ( );
    PrintHelpLine ( iWidth, L"Example", PROGRAM_NAME, L"AA-AA-AA-AA-AA-AA BB:BB:BB:BB:BB:BB" );
    PrintHelpLine ( iWidth, L"", PROGRAM_NAME, L"-wake AA-AA-AA-AA-AA-AA BB:BB:BB:BB:BB:BB" );
    if ( bLong )
    {
        PrintHelpLine ( iWidth, L"", PROGRAM_NAME, L"registers MAC Addresses in a etherwake.arp file." );
        PrintHelpLine ( iWidth, L"", PROGRAM_NAME, L"for wake purpose stores hostnames and MAC Addresses in etherwake.ini file." );
    }

    //
    PrintHelpReadMe ( iWidth, PROGRAM_NAME, iArgCount, pArgValues, bLong );

    //
    return 0;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
int TreatOptions(int iArgCount, WCHAR* pArgValues[], WCHAR* pEnvironment[] )
{
    //
    //  Argument Count
    if ( iArgCount < 2 )
    {
        PrintStderrW ( L"Error : Not Enough Arguments\n" );
        PrintStderrW ( L"Usage : See %s -help\n", pArgValues [ 0 ] );
        exit(1);
    }

    //
    //  Treat Options
    FirstMacAddress = 1;
    for ( int i = 1; i < iArgCount; i++ )
    {
        WCHAR *pArgument = pArgValues [ i ];
        if ( *pArgument == L'-' || *pArgument == L'/' )
        {
            FirstMacAddress = i + 1;

            WCHAR *pOption = pArgument + 1;
            if ( __wcsicmpL ( pOption, L"h", L"?", L"help", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }

                //
                PrintHelp( iArgCount, pArgValues, false );

                //
                exit (0);
            }
            else if ( __wcsicmpL ( pOption, L"hl", L"lh", L"helplong", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }

                //
                PrintHelp( iArgCount, pArgValues, true );

                //
                exit (0);
            }
            else if ( __wcsicmpL ( pOption, L"v", L"verbose", NULL ) == 0 )
            {
                VerboseMode = true;
            }
            else if ( __wcsicmpL ( pOption, L"debug", NULL ) == 0 )
            {
                DebugMode = true;
            }
            else if ( __wcsicmpL ( pOption, L"q", L"quiet", NULL ) == 0 )
            {
                QuietMode = true;
            }
            else if ( __wcsicmpL ( pOption, L"l", L"list", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }
                DoAction    = true;
                DoList      = true;
            }
            else if ( __wcsicmpL ( pOption, L"r", L"resolve", NULL ) == 0 )
            {
                ResolveMode = true;
            }
            else if ( __wcsicmpL ( pOption, L"s", L"server", NULL ) == 0 || __wcsnicmpL ( pOption, L"s=", L"server=", NULL ) == 0 )
            {
                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );

                wcscpy_s ( NameServer, _wsizeof ( NameServer ), pCode );
                UseDns = true;
            }
            else if ( __wcsicmpL ( pOption, L"timeout", NULL ) == 0 || __wcsnicmpL ( pOption, L"timeout=", NULL ) == 0 )
            {
                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );

                PingTimeOut =_wtol ( pCode );
                if ( PingTimeOut <= 0 )
                {
                    PingTimeOut = 1;
                }
                if ( PingTimeOut > 100 )
                {
                    PingTimeOut = 100;
                }
            }
            else if ( __wcsicmpL ( pOption, L"dnsqueryex", NULL ) == 0 )
            {
                DnsQueryExMode = true;
            }
            else if ( _wcsicmp ( pOption, L"up" ) == 0 )
            {
                IPUp = true;
            }
            else if ( _wcsicmp ( pOption, L"down" ) == 0 )
            {
                IPDown = true;
            }
            else if ( _wcsicmp ( pOption, L"imm" ) == 0 )
            {
                IPMatchMac = true;
            }
            else if ( _wcsicmp ( pOption, L"noimm" ) == 0 )
            {
                IPMatchMac = false;
            }
            else if ( _wcsicmp ( pOption, L"ping" ) == 0 )
            {
                PingMode = true;
            }
            else if ( _wcsicmp ( pOption, L"pingsub" ) == 0 )
            {
                PingSubnetMode  = true;
                DoAction        = true;
            }
            else if ( __wcsicmpL ( pOption, L"pinglist", NULL ) == 0 || __wcsnicmpL ( pOption, L"pinglist=", NULL ) == 0 )
            {
                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );

                wcscpy_s ( PingFileName, _wsizeof ( PingFileName ), pCode );

                PingListMode    = true;
                DoAction        = true;
            }
            else if ( __wcsicmpL ( pOption, L"4", L"ipv4", NULL ) == 0 )
            {
                IPv4Only = true;
            }
            else if ( __wcsicmpL ( pOption, L"6", L"ipv6", NULL ) == 0 )
            {
                IPv6Only = true;
            }
            else if ( _wcsicmp ( pOption, L"nz" ) == 0 )
            {
                NonZeroMac = true;
            }
            else if ( __wcsicmpL ( pOption, L"d4", L"adapter", L"adapters", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }
                DoAction    = true;
                DoAdapter   = true;
            }
            else if (  __wcsicmpL ( pOption, L"d6", L"adapter6", L"adapters6", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    return 1;
                }
                DoAction    = true;
                DoAdapter6  = true;
            }
            else if (  __wcsicmpL ( pOption, L"a4", L"arp", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    return 1;
                }
                DoAction    = true;
                DoArp       = true;
            }
            else if ( __wcsicmpL ( pOption, L"a6", L"arp6", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }
                DoAction    = true;
                DoArp6      = true;
            }
            //  Search MAC Address for an host
            else if ( _wcsicmp ( pOption, L"mac" ) == 0 || __wcsnicmpL (pOption, L"mac=", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }

                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );

                wcscpy_s ( AddressSearched, _wsizeof ( AddressSearched ), pCode );
                DoAction    = true;
                DoMac       = true;
            }
            //
            //  Query
            else if ( _wcsicmp ( pOption, L"query" ) == 0 || __wcsnicmpL (pOption, L"query=", NULL ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }

                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );

                wcscpy_s ( AddressSearched, _wsizeof ( AddressSearched ), pCode );
                DoAction        = true;
                DoQuery         = true;
                ResolveMode     = true;
            }
            //
            //
            //  Query
            else if ( _wcsicmp ( pOption, L"querytype" ) == 0 || __wcsnicmpL (pOption, L"querytype=", NULL ) == 0 )
            {
                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );

                wcscpy_s ( QueryType, _wsizeof ( QueryType ), pCode );
            }
            //  Locale
            else if ( _wcsicmp ( pOption, L"locale" ) == 0 || __wcsnicmpL (pOption, L"locale=", NULL ) == 0 )
            {
                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );
                wcscpy_s ( LocaleString, _wsizeof(LocaleString), pCode );
                LocaleMode  = true;
            }
            //
            else if ( _wcsicmp ( pOption, L"subnet" ) == 0 || __wcsnicmpL (pOption, L"subnet=", NULL ) == 0 )
            {
                WCHAR *pCode = GetArgumentW ( iArgCount, pArgValues, &i );
                wcscpy_s ( Subnet, _wsizeof(Subnet), pCode );
            }
            //
            //  Wake
            else if ( _wcsicmp ( pOption, L"wake" ) == 0 )
            {
                if ( DoAction )
                {
                    PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                    exit(1);
                }
                DoAction    = true;
                DoWake      = true;
                FirstMacAddress = i + 1;
                break;
            }
            else if ( TreatReadMeOption ( iArgCount, pArgValues, pOption, i ) )
            {
                PrintRealVersionW();

                char *pText = GetReadMeResouce(IDR_RC_README);
                if ( pText )
                {
                    puts ( pText );
                    free ( pText );
                }
                exit(0);
                return 0;
            }
            else
            {
                PrintStderrW ( L"Error : Invalid Option %s\n", pArgument );
                exit(1);
            }
        }
        //
        //  No Action : Simply wake
        else
        {
            if ( DoAction )
            {
                PrintStderrW ( L"Error : An Action Is Already Defined\n" );
                exit(1);
            }
            DoAction    = true;
            DoWake      = true;
            FirstMacAddress = i;
            break;
        }
    }

    return 0;
}

//
//////////////////////////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////////////////////////
int _tmain(int iArgCount, WCHAR* pArgValues[], WCHAR* pEnvironment[] )
{
    //
    InitStdHandlers();

    // Initialize Winsock
    WSADATA wsaData = {0};
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        PrintStderrW ( L"Error : WSAStartup failed: %d\n", iResult );
        return 1;
    }

    //
    int exitCode = 0;

    //  Ntdll.dll
    HMODULE hNtTDLL = GetModuleHandle ( L"Ntdll.dll" );
    if ( hNtTDLL == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

    //  RtlIpv4AddressToStringW
    RtlIpv4AddressToStringW = (RtlIpv4AddressToStringWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv4AddressToStringW"       //  LPCSTR  lpProcName
    );
    if ( RtlIpv4AddressToStringW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

    //  RtlIpv6AddressToStringW
    RtlIpv6AddressToStringW = (RtlIpv6AddressToStringWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv6AddressToStringW"       //  LPCSTR  lpProcName
    );
    if ( RtlIpv6AddressToStringW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

    //  RtlIpv4AddressToStringExW
    RtlIpv4AddressToStringExW = (RtlIpv4AddressToStringExWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv4AddressToStringExW"     //  LPCSTR  lpProcName
    );
    if ( RtlIpv4AddressToStringExW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

    //  RtlIpv6AddressToStringExW
    RtlIpv6AddressToStringExW = (RtlIpv6AddressToStringExWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv6AddressToStringExW"     //  LPCSTR  lpProcName
    );
    if ( RtlIpv6AddressToStringExW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

    //  RtlIpv4StringToAddressExW
    RtlIpv4StringToAddressExW = (RtlIpv4StringToAddressExWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv4StringToAddressExW"     //  LPCSTR  lpProcName
    );
    if ( RtlIpv4StringToAddressExW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

    //  RtlIpv6StringToAddressExW
    RtlIpv6StringToAddressExW = (RtlIpv6StringToAddressExWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv6StringToAddressExW"     //  LPCSTR  lpProcName
    );
    if ( RtlIpv6StringToAddressExW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }

#if USE_RTL_STRING_TO_IP4

    RtlIpv4StringToAddressW = (RtlIpv4StringToAddressWType) GetProcAddress (
        hNtTDLL,                        //  HMODULE hModule,
        "RtlIpv4StringToAddressW"       //  LPCSTR  lpProcName
    );
    if ( RtlIpv4StringToAddressW == NULL )
    {
        int lastError = GetLastError();
        FormatErrorMessage ( lastError );
        PrintStderrW ( L"Error : %d - %s\n", lastError, szErrorText );
        return 1;
    }
#endif

    //
    ZeroMemory ( LocaleString, sizeof(LocaleString) );

    //
    TreatOptions( iArgCount, pArgValues, pEnvironment );

    //
    //  Init File
    GetModule();


    //  DnsQueryEx
    HMODULE hDnsapiDLL = GetModuleHandle ( L"Dnsapi.dll" );
    RuntimeDnsQueryEx = (DnsQueryExType) GetProcAddress (
        hDnsapiDLL,                     //  HMODULE hModule,
        "DnsQueryEx"                    //  LPCSTR  lpProcName
    );
    if ( RuntimeDnsQueryEx != NULL )
    {
        PrintDebug ( L"Found DnsQueryEx Entry Point : %llx\n", RuntimeDnsQueryEx );
    }
    else
    {
        PrintDebug ( L"DnsQueryEx Entry Point Not Found\n" );
        if ( DnsQueryExMode )
        {
            PrintDirect ( L"-dnsqueryex is disabled because entry point is not found\n" );
            DnsQueryExMode = false;
        }
    }

    //
    //  For IPV>6 Name Server
    if ( wcslen(NameServer) > 0 && wcschr(NameServer, L':' ) != NULL && RuntimeDnsQueryEx != NULL )
    {
        DnsQueryExMode = true;
    }

    //
    GetNameServerParams();

    //
    //
    memset ( SubnetList, 0, sizeof(SubnetList) );
    GetSubnets ();

    if ( VerboseMode )
    {
        PrintVerbose ( L"Subnets\n" );
        for ( int i = 0; i < SubnetListCount; i++ )
        {
            PrintVerbose ( L"- IP : %s - Mask %s\n", SubnetList [ i ].IPAddress, SubnetList [ i ].IPMask );
        }
        PrintVerbose ( L"\n" );
    }

    //
    //  Read Arp File
    ReadArpFile ( );

    //
    CreateLocalePointer ( LocaleString );

    //
    //  Show List
    if ( DoList )
    {
        PrintDirect ( L"File Used is : %s\n", InitFileName );
        ZeroMemory ( ExecuteCommand, sizeof(ExecuteCommand) );
        wcscpy_s ( ExecuteCommand, _wsizeof(ExecuteCommand), L"cmd.exe /c type " );
        wcscat_s ( ExecuteCommand, _wsizeof(ExecuteCommand), L"\"" );
        wcscat_s ( ExecuteCommand, _wsizeof(ExecuteCommand), InitFileName );
        wcscat_s ( ExecuteCommand, _wsizeof(ExecuteCommand), L"\"" );

        Execute ( ExecuteCommand, NULL, NULL  );
    }

    //
    //  Ping All Subnet
    else if ( PingSubnetMode && SubnetListCount >= 1 )
    {
        //  Avoid x.x.x.0 and x.x.x.255
        for ( int i = 1; i <= 254; i++ )
        {
            WCHAR szAddress [ LEN_IP_ARP ];
            ZeroMemory ( szAddress, sizeof(szAddress) );

            swprintf_s ( szAddress, _wsizeof(szAddress), L"%d.%d.%d.%d",
                SubnetList [ 0 ].IP.S_un.S_un_b.s_b1, SubnetList [ 0 ].IP.S_un.S_un_b.s_b2,
                SubnetList [ 0 ].IP.S_un.S_un_b.s_b3, i );

            int iRes = PingAddress ( szAddress );
            PrintDirect ( L"Pinging %s - %d\n", szAddress, iRes );
        }
    }
    else if ( PingListMode )
    {
        FILE *hFile;
        OpenFileCcs ( &hFile, PingFileName, L"r" );
        if ( hFile != NULL )
        {
            while ( ! feof(hFile) && ! ferror(hFile) )
            {
                WCHAR *pLine = fgetws ( LineReadW, _wsizeof(LineReadW), hFile );
                if ( pLine != NULL )
                {
                    RemoveCRLF ( LineReadW );
                    WCHAR *pFirst = NextNotSpaces ( LineReadW );
                    if ( pFirst != NULL && *pFirst != L'#' )
                    {
                        WCHAR *pNext = NextSpaces ( pFirst );
                        if ( pNext )
                        {
                            *pNext = L'\0';
                        }

                        if ( wcslen(pFirst) > 0 )
                        {
                            int iRes = PingAddress ( pFirst );
                            PrintDirect ( L"Pinging %s - %d\n", pFirst, iRes );
                        }
                    }

                }
            }
            fclose ( hFile );
        }
        else
        {
            PrintStderr ( L"Error opening file %s\n", PingFileName );
        }
    }
    //
    //  Show Arp
    else if ( DoArp )
    {
        if ( IPv4Only )
        {
            ShowArp64();
        }
        else if ( IPv6Only )
        {
            ShowArp64();
        }
        else
        {
            ShowArp();
        }
    }

    //
    //  Show Arp6
    else if ( DoArp6 )
    {
        if ( IPv4Only )
        {
            ShowArp64();
        }
        else if ( IPv6Only )
        {
            ShowArp64();
        }
        else
        {
            ShowArp64();
        }
    }

    //
    //  Adapter
    else if ( DoAdapter )
    {
        if ( IPv4Only )
        {
            ShowAdapters64();
        }
        else if ( IPv6Only )
        {
            ShowAdapters64();
        }
        else
        {
            ShowAdapters();
        }
    }

    //
    //  Adapter6
    else if ( DoAdapter6 )
    {
        if ( IPv4Only )
        {
            ShowAdapters64();
        }
        else if ( IPv6Only )
        {
            ShowAdapters64();
        }
        else
        {
            ShowAdapters64();
        }
    }

    //  Mac Search
    else if ( DoMac )
    {
        BOOL bFound = GetMacAddress ( AddressSearched );
        if ( ! bFound )
        {
            bFound = GetLocalMacAddress ( AddressSearched );
        }

        if ( bFound )
        {
            PrintNormalW ( L"Found MAC for Address %s : %s\n", AddressSearched, MacFound );
            LowercaseText ( AddressSearched );
            WriteProfile ( AddressSearched, MacFound );
        }
        else
        {
            PrintStderrW ( L"Error : MAC for Address %s Not Found\n", AddressSearched );
        }
    }

    //
    //  Query
    else if ( DoQuery )
    {
        ZeroMemory ( ResolvedHostname, sizeof(ResolvedHostname) );
        ResolveOneHost ( AddressSearched, ResolvedHostname, _wsizeof(ResolvedHostname), true );
    }
    //
    //  Normal Wake
    else
    {
        //
        for ( int i = FirstMacAddress; i < iArgCount; i++ )
        {
            BOOL bDone = FALSE;

            //  First Read from Ini File
            bDone = ReadProfile ( pArgValues [ i ], MacAddressString, _wsizeof(MacAddressString), L"" );
            if ( ! bDone )
            {
                //  Use Directly argument
                wcscpy_s ( MacAddressString, _wsizeof(MacAddressString), pArgValues [ i ] );
            }
            else
            {
                PrintStdoutW ( L"Using Mac Address %-20s for %s\n", MacAddressString, pArgValues [ i ] );
            }

            //
            bDone = convertMAC ( MacAddressString );

            //
            if ( ! bDone )
            {
                PrintStderrW ( L"Error : Invalid Mac Address %-20s\n", MacAddressString );
            }
            else
            {
                //  Convert Back
                MacAddressToString ( MacAddress, LEN_MAC );
                PrintStdoutW ( L"Sending Wake to %-20s\n", MacAddressString );
                BOOL bSend = sendWake(Subnet);
                if ( bSend && ! QuietMode )
                {
                    PrintNormalW ( L"Success : Wake to %-20s has been sent\n", MacAddressString );
                }
            }
        }
    }

    //
    if ( ArpListUpdated )
    {
        WriteArpFile ( );
    }

    //
    WSACleanup();

    return exitCode;
}
