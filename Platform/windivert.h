

#ifndef __WINDIVERT_H
#define __WINDIVERT_H

#ifndef WINDIVERT_KERNEL
#include <windows.h>
#endif

#ifndef WINDIVERTEXPORT
#define WINDIVERTEXPORT extern __declspec(dllimport)
#endif

#ifdef __MINGW32__
#define __in
#define __in_opt
#define __out
#define __out_opt
#define __inout
#define __inout_opt
#include <stdint.h>
#define INT8 int8_t
#define UINT8 uint8_t
#define INT16 int16_t
#define UINT16 uint16_t
#define INT32 int32_t
#define UINT32 uint32_t
#define INT64 int64_t
#define UINT64 uint64_t
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  WINDIVERT_LAYER_NETWORK = 0,
  WINDIVERT_LAYER_NETWORK_FORWARD = 1,
  WINDIVERT_LAYER_FLOW = 2,
  WINDIVERT_LAYER_SOCKET = 3,
  WINDIVERT_LAYER_REFLECT = 4,
} WINDIVERT_LAYER,
    *PWINDIVERT_LAYER;

typedef struct {
  UINT32 IfIdx;
  UINT32 SubIfIdx;
} WINDIVERT_DATA_NETWORK, *PWINDIVERT_DATA_NETWORK;

typedef struct {
  UINT64 EndpointId;
  UINT64 ParentEndpointId;
  UINT32 ProcessId;
  UINT32 LocalAddr[4];
  UINT32 RemoteAddr[4];
  UINT16 LocalPort;
  UINT16 RemotePort;
  UINT8 Protocol;
} WINDIVERT_DATA_FLOW, *PWINDIVERT_DATA_FLOW;

typedef struct {
  UINT64 EndpointId;
  UINT64 ParentEndpointId;
  UINT32 ProcessId;
  UINT32 LocalAddr[4];
  UINT32 RemoteAddr[4];
  UINT16 LocalPort;
  UINT16 RemotePort;
  UINT8 Protocol;
} WINDIVERT_DATA_SOCKET, *PWINDIVERT_DATA_SOCKET;

typedef struct {
  INT64 Timestamp;
  UINT32 ProcessId;
  WINDIVERT_LAYER Layer;
  UINT64 Flags;
  INT16 Priority;
} WINDIVERT_DATA_REFLECT, *PWINDIVERT_DATA_REFLECT;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
typedef struct {
  INT64 Timestamp;
  UINT32 Layer : 8;
  UINT32 Event : 8;
  UINT32 Sniffed : 1;
  UINT32 Outbound : 1;
  UINT32 Loopback : 1;
  UINT32 Impostor : 1;
  UINT32 IPv6 : 1;
  UINT32 IPChecksum : 1;
  UINT32 TCPChecksum : 1;
  UINT32 UDPChecksum : 1;
  UINT32 Reserved1 : 8;
  UINT32 Reserved2;
  union {
    WINDIVERT_DATA_NETWORK Network;
    WINDIVERT_DATA_FLOW Flow;
    WINDIVERT_DATA_SOCKET Socket;
    WINDIVERT_DATA_REFLECT Reflect;
    UINT8 Reserved3[64];
  };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;
#ifdef _MSC_VER
#pragma warning(pop)
#endif

typedef enum {
  WINDIVERT_EVENT_NETWORK_PACKET = 0,
  WINDIVERT_EVENT_FLOW_ESTABLISHED = 1,

  WINDIVERT_EVENT_FLOW_DELETED = 2,
  WINDIVERT_EVENT_SOCKET_BIND = 3,
  WINDIVERT_EVENT_SOCKET_CONNECT = 4,
  WINDIVERT_EVENT_SOCKET_LISTEN = 5,
  WINDIVERT_EVENT_SOCKET_ACCEPT = 6,
  WINDIVERT_EVENT_SOCKET_CLOSE = 7,
  WINDIVERT_EVENT_REFLECT_OPEN = 8,
  WINDIVERT_EVENT_REFLECT_CLOSE = 9,
} WINDIVERT_EVENT,
    *PWINDIVERT_EVENT;

#define WINDIVERT_FLAG_SNIFF 0x0001
#define WINDIVERT_FLAG_DROP 0x0002
#define WINDIVERT_FLAG_RECV_ONLY 0x0004
#define WINDIVERT_FLAG_READ_ONLY WINDIVERT_FLAG_RECV_ONLY
#define WINDIVERT_FLAG_SEND_ONLY 0x0008
#define WINDIVERT_FLAG_WRITE_ONLY WINDIVERT_FLAG_SEND_ONLY
#define WINDIVERT_FLAG_NO_INSTALL 0x0010
#define WINDIVERT_FLAG_FRAGMENTS 0x0020

typedef enum {
  WINDIVERT_PARAM_QUEUE_LENGTH = 0,
  WINDIVERT_PARAM_QUEUE_TIME = 1,
  WINDIVERT_PARAM_QUEUE_SIZE = 2,
  WINDIVERT_PARAM_VERSION_MAJOR = 3,
  WINDIVERT_PARAM_VERSION_MINOR = 4,
} WINDIVERT_PARAM,
    *PWINDIVERT_PARAM;
#define WINDIVERT_PARAM_MAX WINDIVERT_PARAM_VERSION_MINOR

typedef enum {
  WINDIVERT_SHUTDOWN_RECV = 0x1,
  WINDIVERT_SHUTDOWN_SEND = 0x2,
  WINDIVERT_SHUTDOWN_BOTH = 0x3,
} WINDIVERT_SHUTDOWN,
    *PWINDIVERT_SHUTDOWN;
#define WINDIVERT_SHUTDOWN_MAX WINDIVERT_SHUTDOWN_BOTH

#ifndef WINDIVERT_KERNEL

WINDIVERTEXPORT HANDLE WinDivertOpen(__in const char *filter,
                                     __in WINDIVERT_LAYER layer,
                                     __in INT16 priority, __in UINT64 flags);

WINDIVERTEXPORT BOOL WinDivertRecv(__in HANDLE handle, __out_opt VOID *pPacket,
                                   __in UINT packetLen,
                                   __out_opt UINT *pRecvLen,
                                   __out_opt WINDIVERT_ADDRESS *pAddr);

WINDIVERTEXPORT BOOL WinDivertRecvEx(
    __in HANDLE handle, __out_opt VOID *pPacket, __in UINT packetLen,
    __out_opt UINT *pRecvLen, __in UINT64 flags, __out WINDIVERT_ADDRESS *pAddr,
    __inout_opt UINT *pAddrLen, __inout_opt LPOVERLAPPED lpOverlapped);

WINDIVERTEXPORT BOOL WinDivertSend(__in HANDLE handle, __in const VOID *pPacket,
                                   __in UINT packetLen,
                                   __out_opt UINT *pSendLen,
                                   __in const WINDIVERT_ADDRESS *pAddr);

WINDIVERTEXPORT BOOL
WinDivertSendEx(__in HANDLE handle, __in const VOID *pPacket,
                __in UINT packetLen, __out_opt UINT *pSendLen,
                __in UINT64 flags, __in const WINDIVERT_ADDRESS *pAddr,
                __in UINT addrLen, __inout_opt LPOVERLAPPED lpOverlapped);

WINDIVERTEXPORT BOOL WinDivertShutdown(__in HANDLE handle,
                                       __in WINDIVERT_SHUTDOWN how);

WINDIVERTEXPORT BOOL WinDivertClose(__in HANDLE handle);

WINDIVERTEXPORT BOOL WinDivertSetParam(__in HANDLE handle,
                                       __in WINDIVERT_PARAM param,
                                       __in UINT64 value);

WINDIVERTEXPORT BOOL WinDivertGetParam(__in HANDLE handle,
                                       __in WINDIVERT_PARAM param,
                                       __out UINT64 *pValue);

#endif

#define WINDIVERT_PRIORITY_HIGHEST 30000
#define WINDIVERT_PRIORITY_LOWEST (-WINDIVERT_PRIORITY_HIGHEST)
#define WINDIVERT_PARAM_QUEUE_LENGTH_DEFAULT 4096
#define WINDIVERT_PARAM_QUEUE_LENGTH_MIN 32
#define WINDIVERT_PARAM_QUEUE_LENGTH_MAX 16384
#define WINDIVERT_PARAM_QUEUE_TIME_DEFAULT 2000
#define WINDIVERT_PARAM_QUEUE_TIME_MIN 100
#define WINDIVERT_PARAM_QUEUE_TIME_MAX 16000
#define WINDIVERT_PARAM_QUEUE_SIZE_DEFAULT 4194304
#define WINDIVERT_PARAM_QUEUE_SIZE_MIN 65535
#define WINDIVERT_PARAM_QUEUE_SIZE_MAX 33554432
#define WINDIVERT_BATCH_MAX 0xFF
#define WINDIVERT_MTU_MAX (40 + 0xFFFF)

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4214)
#endif

typedef struct {
  UINT8 HdrLength : 4;
  UINT8 Version : 4;
  UINT8 TOS;
  UINT16 Length;
  UINT16 Id;
  UINT16 FragOff0;
  UINT8 TTL;
  UINT8 Protocol;
  UINT16 Checksum;
  UINT32 SrcAddr;
  UINT32 DstAddr;
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;

#define WINDIVERT_IPHDR_GET_FRAGOFF(hdr) (((hdr)->FragOff0) & 0xFF1F)
#define WINDIVERT_IPHDR_GET_MF(hdr) ((((hdr)->FragOff0) & 0x0020) != 0)
#define WINDIVERT_IPHDR_GET_DF(hdr) ((((hdr)->FragOff0) & 0x0040) != 0)
#define WINDIVERT_IPHDR_GET_RESERVED(hdr) ((((hdr)->FragOff0) & 0x0080) != 0)

#define WINDIVERT_IPHDR_SET_FRAGOFF(hdr, val)                                  \
  do {                                                                         \
    (hdr)->FragOff0 = (((hdr)->FragOff0) & 0x00E0) | ((val) & 0xFF1F);         \
  } while (FALSE)
#define WINDIVERT_IPHDR_SET_MF(hdr, val)                                       \
  do {                                                                         \
    (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFFDF) | (((val) & 0x0001) << 5);  \
  } while (FALSE)
#define WINDIVERT_IPHDR_SET_DF(hdr, val)                                       \
  do {                                                                         \
    (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFFBF) | (((val) & 0x0001) << 6);  \
  } while (FALSE)
#define WINDIVERT_IPHDR_SET_RESERVED(hdr, val)                                 \
  do {                                                                         \
    (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFF7F) | (((val) & 0x0001) << 7);  \
  } while (FALSE)

typedef struct {
  UINT8 TrafficClass0 : 4;
  UINT8 Version : 4;
  UINT8 FlowLabel0 : 4;
  UINT8 TrafficClass1 : 4;
  UINT16 FlowLabel1;
  UINT16 Length;
  UINT8 NextHdr;
  UINT8 HopLimit;
  UINT32 SrcAddr[4];
  UINT32 DstAddr[4];
} WINDIVERT_IPV6HDR, *PWINDIVERT_IPV6HDR;

#define WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(hdr)                                \
  ((((hdr)->TrafficClass0) << 4) | ((hdr)->TrafficClass1))
#define WINDIVERT_IPV6HDR_GET_FLOWLABEL(hdr)                                   \
  ((((UINT32)(hdr)->FlowLabel0) << 16) | ((UINT32)(hdr)->FlowLabel1))

#define WINDIVERT_IPV6HDR_SET_TRAFFICCLASS(hdr, val)                           \
  do {                                                                         \
    (hdr)->TrafficClass0 = ((UINT8)(val) >> 4);                                \
    (hdr)->TrafficClass1 = (UINT8)(val);                                       \
  } while (FALSE)
#define WINDIVERT_IPV6HDR_SET_FLOWLABEL(hdr, val)                              \
  do {                                                                         \
    (hdr)->FlowLabel0 = (UINT8)((val) >> 16);                                  \
    (hdr)->FlowLabel1 = (UINT16)(val);                                         \
  } while (FALSE)

typedef struct {
  UINT8 Type;
  UINT8 Code;
  UINT16 Checksum;
  UINT32 Body;
} WINDIVERT_ICMPHDR, *PWINDIVERT_ICMPHDR;

typedef struct {
  UINT8 Type;
  UINT8 Code;
  UINT16 Checksum;
  UINT32 Body;
} WINDIVERT_ICMPV6HDR, *PWINDIVERT_ICMPV6HDR;

typedef struct {
  UINT16 SrcPort;
  UINT16 DstPort;
  UINT32 SeqNum;
  UINT32 AckNum;
  UINT16 Reserved1 : 4;
  UINT16 HdrLength : 4;
  UINT16 Fin : 1;
  UINT16 Syn : 1;
  UINT16 Rst : 1;
  UINT16 Psh : 1;
  UINT16 Ack : 1;
  UINT16 Urg : 1;
  UINT16 Reserved2 : 2;
  UINT16 Window;
  UINT16 Checksum;
  UINT16 UrgPtr;
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;

typedef struct {
  UINT16 SrcPort;
  UINT16 DstPort;
  UINT16 Length;
  UINT16 Checksum;
} WINDIVERT_UDPHDR, *PWINDIVERT_UDPHDR;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#define WINDIVERT_HELPER_NO_IP_CHECKSUM 1
#define WINDIVERT_HELPER_NO_ICMP_CHECKSUM 2
#define WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM 4
#define WINDIVERT_HELPER_NO_TCP_CHECKSUM 8
#define WINDIVERT_HELPER_NO_UDP_CHECKSUM 16

#ifndef WINDIVERT_KERNEL

WINDIVERTEXPORT UINT64 WinDivertHelperHashPacket(__in const VOID *pPacket,
                                                 __in UINT packetLen,
                                                 __in UINT64 seed
#ifdef __cplusplus
                                                 = 0
#endif
);

WINDIVERTEXPORT BOOL WinDivertHelperParsePacket(
    __in const VOID *pPacket, __in UINT packetLen,
    __out_opt PWINDIVERT_IPHDR *ppIpHdr,
    __out_opt PWINDIVERT_IPV6HDR *ppIpv6Hdr, __out_opt UINT8 *pProtocol,
    __out_opt PWINDIVERT_ICMPHDR *ppIcmpHdr,
    __out_opt PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    __out_opt PWINDIVERT_TCPHDR *ppTcpHdr,
    __out_opt PWINDIVERT_UDPHDR *ppUdpHdr, __out_opt PVOID *ppData,
    __out_opt UINT *pDataLen, __out_opt PVOID *ppNext,
    __out_opt UINT *pNextLen);

WINDIVERTEXPORT BOOL WinDivertHelperParseIPv4Address(__in const char *addrStr,
                                                     __out_opt UINT32 *pAddr);

WINDIVERTEXPORT BOOL WinDivertHelperParseIPv6Address(__in const char *addrStr,
                                                     __out_opt UINT32 *pAddr);

WINDIVERTEXPORT BOOL WinDivertHelperFormatIPv4Address(__in UINT32 addr,
                                                      __out char *buffer,
                                                      __in UINT bufLen);

WINDIVERTEXPORT BOOL WinDivertHelperFormatIPv6Address(__in const UINT32 *pAddr,
                                                      __out char *buffer,
                                                      __in UINT bufLen);

WINDIVERTEXPORT BOOL WinDivertHelperCalcChecksums(
    __inout VOID *pPacket, __in UINT packetLen,
    __out_opt WINDIVERT_ADDRESS *pAddr, __in UINT64 flags);

WINDIVERTEXPORT BOOL WinDivertHelperDecrementTTL(__inout VOID *pPacket,
                                                 __in UINT packetLen);

WINDIVERTEXPORT BOOL WinDivertHelperCompileFilter(
    __in const char *filter, __in WINDIVERT_LAYER layer, __out_opt char *object,
    __in UINT objLen, __out_opt const char **errorStr,
    __out_opt UINT *errorPos);

WINDIVERTEXPORT BOOL WinDivertHelperEvalFilter(
    __in const char *filter, __in const VOID *pPacket, __in UINT packetLen,
    __in const WINDIVERT_ADDRESS *pAddr);

WINDIVERTEXPORT BOOL WinDivertHelperFormatFilter(__in const char *filter,
                                                 __in WINDIVERT_LAYER layer,
                                                 __out char *buffer,
                                                 __in UINT bufLen);

WINDIVERTEXPORT UINT16 WinDivertHelperNtohs(__in UINT16 x);
WINDIVERTEXPORT UINT16 WinDivertHelperHtons(__in UINT16 x);
WINDIVERTEXPORT UINT32 WinDivertHelperNtohl(__in UINT32 x);
WINDIVERTEXPORT UINT32 WinDivertHelperHtonl(__in UINT32 x);
WINDIVERTEXPORT UINT64 WinDivertHelperNtohll(__in UINT64 x);
WINDIVERTEXPORT UINT64 WinDivertHelperHtonll(__in UINT64 x);
WINDIVERTEXPORT void WinDivertHelperNtohIPv6Address(__in const UINT *inAddr,
                                                    __out UINT *outAddr);
WINDIVERTEXPORT void WinDivertHelperHtonIPv6Address(__in const UINT *inAddr,
                                                    __out UINT *outAddr);

WINDIVERTEXPORT void WinDivertHelperNtohIpv6Address(__in const UINT *inAddr,
                                                    __out UINT *outAddr);
WINDIVERTEXPORT void WinDivertHelperHtonIpv6Address(__in const UINT *inAddr,
                                                    __out UINT *outAddr);

#endif

#ifdef __cplusplus
}
#endif

#endif
