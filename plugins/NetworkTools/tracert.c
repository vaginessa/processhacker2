/*
 * Process Hacker Network Tools -
 *   Tracert dialog
 *
 * Copyright (C) 2015 dmex
 *
 * This file is part of Process Hacker.
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "nettools.h"
#include <commonutil.h>

#define TRACERT_HEADER1 L"Tracing route to %s [%s] over a maximum of %u hops:\r\n\r\n" 
#define TRACERT_HEADER2 L"Tracing route to %s over a maximum of %u hops\r\n\r\n" 

#define DEFAULT_MAXIMUM_HOPS        30 
#define DEFAULT_SEND_SIZE           64 
#define DEFAULT_RECEIVE_SIZE      ((sizeof(ICMP_ECHO_REPLY) + DEFAULT_SEND_SIZE + MAX_OPT_SIZE)) 

#define DEFAULT_TIMEOUT 4000
#define MIN_INTERVAL    1000

#define MAX_PINGS  3
#define IP_ADDRESS_COLUMN (MAX_PINGS + 1)
#define HOSTNAME_COLUMN (MAX_PINGS + 2)

typedef struct _TRACERT_RESOLVE_WORKITEM
{
    HWND LvHandle;
    INT LvItemIndex;

    ULONG Type;
    SOCKADDR_STORAGE SocketAddress;
} TRACERT_RESOLVE_WORKITEM, *PTRACERT_RESOLVE_WORKITEM;




PPH_STRING TracertGetErrorMessage(
    _In_ ULONG Result
    )
{
    PPH_STRING message;
    ULONG messageLength = 0;

    if (GetIpErrorString(Result, NULL, &messageLength) == ERROR_INSUFFICIENT_BUFFER)
    {
        message = PhCreateStringEx(NULL, messageLength * sizeof(WCHAR));

        if (GetIpErrorString(Result, message->Buffer, &messageLength) != NO_ERROR)
        {
            PhDereferenceObject(message);
            message = PhGetWin32Message(Result);
        }
    }
    else
    {
        message = PhGetWin32Message(Result);
    }

    return message;
}


VOID TracertUpdateTime(
    _In_ PNETWORK_OUTPUT_CONTEXT Context,
    _In_ INT Index,
    _In_ INT SubIndex,
    _In_ ULONG RoundTripTime
    ) 
{ 
    if (RoundTripTime)
    { 
        PhSetListViewSubItem(Context->OutputHandle, Index, SubIndex, PhFormatString(L"%lu ms", RoundTripTime)->Buffer);
    } 
    else 
    { 
        PhSetListViewSubItem(Context->OutputHandle, Index, SubIndex, PhFormatString(L"<1 ms", RoundTripTime)->Buffer);
    } 
} 



static NTSTATUS TracertHostnameLookupCallback(
    _In_ PVOID Parameter
    )
{
    PTRACERT_RESOLVE_WORKITEM workItem = Parameter;
    BOOLEAN success = FALSE;
    WSADATA winsockStartup;
    WCHAR ipAddrHostname[NI_MAXHOST] = L"";

    if (WSAStartup(WINSOCK_VERSION, &winsockStartup) != ERROR_SUCCESS)
        return STATUS_UNEXPECTED_NETWORK_ERROR;

    if (workItem->Type == PH_IPV4_NETWORK_TYPE)
    {
        if (!GetNameInfo(
            (PSOCKADDR)&workItem->SocketAddress,
            sizeof(SOCKADDR_IN),
            ipAddrHostname,
            ARRAYSIZE(ipAddrHostname),
            NULL,
            0,
            NI_NAMEREQD
            ))
        {
            success = TRUE;
        }
    }
    else if (workItem->Type == PH_IPV6_NETWORK_TYPE)
    {
        if (!GetNameInfo(
            (PSOCKADDR)&workItem->SocketAddress,
            sizeof(SOCKADDR_IN6),
            ipAddrHostname,
            ARRAYSIZE(ipAddrHostname),
            NULL,
            0,
            NI_NAMEREQD
            ))
        {
            success = TRUE;
        }
    }

    if (success)
    {
        PhSetListViewSubItem(workItem->LvHandle, workItem->LvItemIndex, HOSTNAME_COLUMN, ipAddrHostname);
    }
    else
    {
        ULONG errorCode = WSAGetLastError();

        if (errorCode != WSAHOST_NOT_FOUND && errorCode != WSATRY_AGAIN)
        {
            PPH_STRING errorMessage = PhGetWin32Message(errorCode);
            PhSetListViewSubItem(workItem->LvHandle, workItem->LvItemIndex, HOSTNAME_COLUMN, errorMessage->Buffer);
            PhDereferenceObject(errorMessage);
        }
        else
        {
            PhSetListViewSubItem(workItem->LvHandle, workItem->LvItemIndex, HOSTNAME_COLUMN, L"");
        }
    }

    WSACleanup();

    PhFree(workItem);

    return STATUS_SUCCESS;
}

VOID TracertQueueIpv4HostnameLookup(
    _In_ PNETWORK_OUTPUT_CONTEXT Context,
    _In_ INT LvItemIndex,
    _In_ IN_ADDR ipv4Addr
    )
{
    PTRACERT_RESOLVE_WORKITEM workItem;
    
    workItem = PhAllocate(sizeof(TRACERT_RESOLVE_WORKITEM));
    memset(workItem, 0, sizeof(TRACERT_RESOLVE_WORKITEM));

    workItem->LvHandle = Context->OutputHandle;
    workItem->LvItemIndex = LvItemIndex;
    workItem->Type = PH_IPV4_NETWORK_TYPE;

    ((PSOCKADDR_IN)&workItem->SocketAddress)->sin_family = AF_INET;
    ((PSOCKADDR_IN)&workItem->SocketAddress)->sin_addr = ipv4Addr;

    PhQueueItemWorkQueue(PhGetGlobalWorkQueue(), TracertHostnameLookupCallback, workItem);
}

VOID TracertQueueIpv6HostnameLookup(
    _In_ PNETWORK_OUTPUT_CONTEXT Context,
    _In_ INT LvItemIndex,
    _In_ IN6_ADDR ipv6Addr
    )
{
    PTRACERT_RESOLVE_WORKITEM workItem;

    workItem = PhAllocate(sizeof(TRACERT_RESOLVE_WORKITEM));
    memset(workItem, 0, sizeof(TRACERT_RESOLVE_WORKITEM));

    workItem->LvHandle = Context->OutputHandle;
    workItem->LvItemIndex = LvItemIndex;
    workItem->Type = PH_IPV6_NETWORK_TYPE;

    ((PSOCKADDR_IN6)&workItem->SocketAddress)->sin6_family = AF_INET6;
    ((PSOCKADDR_IN6)&workItem->SocketAddress)->sin6_addr = ipv6Addr;

    PhQueueItemWorkQueue(PhGetGlobalWorkQueue(), TracertHostnameLookupCallback, workItem);
}

VOID TracertShowIpAddress(
    _In_ PNETWORK_OUTPUT_CONTEXT Context,
    _In_ INT LvItemIndex,
    _In_ PVOID IpAddr
    ) 
{
    if (Context->RemoteEndpoint.Address.Type == PH_IPV4_NETWORK_TYPE)
    {
        IN_ADDR sockAddrIn;
        WCHAR addressString[INET6_ADDRSTRLEN + 1];

        memset(&sockAddrIn, 0, sizeof(IN_ADDR));
        memcpy(&sockAddrIn.s_addr, IpAddr, sizeof(IPAddr));

        RtlIpv4AddressToString(&sockAddrIn, addressString);

        PhSetListViewSubItem(Context->OutputHandle, LvItemIndex, IP_ADDRESS_COLUMN, addressString);
        PhSetListViewSubItem(Context->OutputHandle, LvItemIndex, HOSTNAME_COLUMN, L"Resolving address...");

        TracertQueueIpv4HostnameLookup(Context, LvItemIndex, sockAddrIn);
    }
    else if (Context->RemoteEndpoint.Address.Type == PH_IPV6_NETWORK_TYPE)
    {
        IN6_ADDR sockAddrIn6;
        WCHAR addressString[INET6_ADDRSTRLEN + 1];

        memset(&sockAddrIn6, 0, sizeof(IN6_ADDR));
        memcpy(&sockAddrIn6, IpAddr, sizeof(IN6_ADDR));

        RtlIpv6AddressToString(&sockAddrIn6, addressString);

        PhSetListViewSubItem(Context->OutputHandle, LvItemIndex, IP_ADDRESS_COLUMN, addressString);
        PhSetListViewSubItem(Context->OutputHandle, LvItemIndex, HOSTNAME_COLUMN, L"Resolving address...");

        TracertQueueIpv6HostnameLookup(Context, LvItemIndex, sockAddrIn6);
    }
}

VOID TracertConvertEndpointToStorage(
    _In_ PNETWORK_OUTPUT_CONTEXT Context,
    _Out_ PSOCKADDR_STORAGE SockAddrStorage
    )
{
    if (Context->RemoteEndpoint.Address.Type == PH_IPV4_NETWORK_TYPE)
    {
        ((PSOCKADDR_IN)SockAddrStorage)->sin_family = AF_INET;
        ((PSOCKADDR_IN)SockAddrStorage)->sin_addr = Context->RemoteEndpoint.Address.InAddr;
        ((PSOCKADDR_IN)SockAddrStorage)->sin_port = (USHORT)Context->RemoteEndpoint.Port;//_byteswap_ushort((USHORT)Context->RemoteEndpoint.Port);
    }
    else if (Context->RemoteEndpoint.Address.Type == PH_IPV6_NETWORK_TYPE)
    {
        ((PSOCKADDR_IN6)SockAddrStorage)->sin6_family = AF_INET6;
        ((PSOCKADDR_IN6)SockAddrStorage)->sin6_addr = Context->RemoteEndpoint.Address.In6Addr;
        ((PSOCKADDR_IN6)SockAddrStorage)->sin6_port = (USHORT)Context->RemoteEndpoint.Port;//_byteswap_ushort((USHORT)Context->RemoteEndpoint.Port);
    }
}



static BOOLEAN RunTraceRoute(
    _In_ PNETWORK_OUTPUT_CONTEXT Context
    )
{
    HANDLE IcmpHandle = INVALID_HANDLE_VALUE;
    SOCKADDR_STORAGE sourceAddress = { 0 };
    SOCKADDR_STORAGE destinationAddress = { 0 };

    ULONG icmpReplyLength = 0;
    PVOID icmpReplyBuffer = NULL;
    PPH_BYTES icmpEchoBuffer = NULL;
    IP_OPTION_INFORMATION pingOptions =
    {
        1,           // Time To Live
        0,           // Type Of Service
        IP_FLAG_DF,  // IP header flags
        0            // Size of options data
    };


    // A source address was not specified but this means each and every request selects its own source interface.
    // We can also requrire a specific source address for this destination. 
    //SOCKET socketHandle = INVALID_SOCKET;
    //socketHandle = socket(destinationAddress.ss_family, 0, IPPROTO_HOPOPTS);
    //if (socketHandle != INVALID_SOCKET)
    //{
    //    ULONG returnLength = 0;
    //    WSAIoctl(
    //        socketHandle,
    //        SIO_ROUTING_INTERFACE_QUERY,
    //        &destinationAddress,
    //        sizeof(destinationAddress),
    //        &sourceAddress,
    //        sizeof(sourceAddress),
    //        &returnLength,
    //        NULL,
    //        NULL
    //        );
    //    if (Context->RemoteEndpoint.Address.Type == PH_IPV4_NETWORK_TYPE)
    //    {
    //        if (returnLength != sizeof(SOCKADDR_IN))
    //        {
    //        }
    //    }
    //    else if (Context->RemoteEndpoint.Address.Type == PH_IPV6_NETWORK_TYPE)
    //    {
    //        if (returnLength != sizeof(SOCKADDR_IN6))
    //        {
    //        }
    //    }
    //    closesocket(socketHandle);
    //}

    TracertConvertEndpointToStorage(Context, &destinationAddress);
    
    switch (Context->RemoteEndpoint.Address.Type)
    {
    case PH_IPV4_NETWORK_TYPE:
        IcmpHandle = IcmpCreateFile();
        break;
    case PH_IPV6_NETWORK_TYPE:
        IcmpHandle = Icmp6CreateFile();
        break;
    }

    if (IcmpHandle == INVALID_HANDLE_VALUE)
    {

    }

    if (Context->PingSize > 0 && Context->PingSize != 32)
    {
        PPH_STRING randString;

        randString = PhCreateStringEx(NULL, Context->PingSize * 2 + 2);

        // Create a random string to fill the buffer.
        PhGenerateRandomAlphaString(randString->Buffer, (ULONG)randString->Length / sizeof(WCHAR));

        icmpEchoBuffer = PhConvertUtf16ToMultiByte(randString->Buffer);
        PhDereferenceObject(randString);
    }
    else
    {
        PPH_STRING version;

        // We're using a default length, query the PH version and use the previous buffer format.
        version = PhGetPhVersion();

        if (version)
        {
            icmpEchoBuffer = FormatAnsiString("processhacker_%S_0x0D06F00D_x1", version->Buffer);
            PhDereferenceObject(version);
        }
    }



    for (UINT i = 0; i < DEFAULT_MAXIMUM_HOPS; i++)
    {
        BOOLEAN haveReply = FALSE;
        IPAddr reply4Address = in4addr_any.s_addr;
        IN6_ADDR reply6Address = in6addr_any;
        INT lvItemIndex;
        
        if (!Context->OutputHandle)
            break;
        
        lvItemIndex = PhAddListViewItem(
            Context->OutputHandle, 
            MAXINT, 
            PhaFormatString(L"%u", (UINT)pingOptions.Ttl)->Buffer,
            NULL
            );

        for (UINT i = 0; i < MAX_PINGS; i++)
        {
            if (!Context->OutputHandle)
                break;

            if (Context->RemoteEndpoint.Address.Type == PH_IPV4_NETWORK_TYPE)
            {
                // Allocate ICMPv6 message.
                icmpReplyLength = ICMP_BUFFER_SIZE(sizeof(ICMP_ECHO_REPLY), icmpEchoBuffer);
                icmpReplyBuffer = PhAllocate(icmpReplyLength);
                memset(icmpReplyBuffer, 0, icmpReplyLength);

                if (!IcmpSendEcho2Ex(
                    IcmpHandle,
                    0,
                    NULL,
                    NULL,
                    ((PSOCKADDR_IN)&sourceAddress)->sin_addr.s_addr,
                    ((PSOCKADDR_IN)&destinationAddress)->sin_addr.s_addr,
                    icmpEchoBuffer->Buffer,
                    (USHORT)icmpEchoBuffer->Length,
                    &pingOptions,
                    icmpReplyBuffer,
                    icmpReplyLength,
                    DEFAULT_TIMEOUT
                    ))
                { 
                    // We did not get any replies due to a timeout or error. 
                    if (GetLastError() == IP_REQ_TIMED_OUT)
                    { 
                        PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, i + 1, L"*");

                        if (i == (MAX_PINGS - 1))
                        {
                            if (haveReply)
                            {
                                TracertShowIpAddress(Context, lvItemIndex, &reply4Address);
                            }
                            else
                            {
                                PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, IP_ADDRESS_COLUMN, TracertGetErrorMessage(GetLastError())->Buffer);
                            }
                        }
                    }
                    else
                    {
                        PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, IP_ADDRESS_COLUMN, TracertGetErrorMessage(GetLastError())->Buffer);
                    }
                }
                else
                {
                    // We got a reply. It's either the final destination address, the TTL expired or an unexpected error response.
                    PICMP_ECHO_REPLY reply4 = (PICMP_ECHO_REPLY)icmpReplyBuffer;

                    if (reply4->Status == IP_SUCCESS) 
                    { 
                        TracertUpdateTime(Context, lvItemIndex, i + 1, reply4->RoundTripTime);
         
                        if (i == (MAX_PINGS - 1))
                        {
                            TracertShowIpAddress(Context, lvItemIndex, &reply4->Address);
                            goto loop_end;
                        }
                        else
                        {
                            haveReply = TRUE;
                            reply4Address = reply4->Address;
                        }
                    }
                    else if (reply4->Status == IP_TTL_EXPIRED_TRANSIT)
                    {
                        TracertUpdateTime(Context, lvItemIndex, i + 1, reply4->RoundTripTime);
     
                        if (i == (MAX_PINGS - 1))
                        {
                            TracertShowIpAddress(Context, lvItemIndex, &reply4->Address);

                            if (reply4->RoundTripTime < MIN_INTERVAL)
                            {
                                Sleep(MIN_INTERVAL - reply4->RoundTripTime);
                            }
                        }
                        else
                        {
                            haveReply = TRUE;
                            reply4Address = reply4->Address;
                        }
                    }
                    else
                    {
                        PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, IP_ADDRESS_COLUMN, TracertGetErrorMessage(GetLastError())->Buffer);
                    }
                }
            }
            else 
            {
                icmpReplyLength = ICMP_BUFFER_SIZE(sizeof(ICMPV6_ECHO_REPLY), icmpEchoBuffer);
                icmpReplyBuffer = PhAllocate(icmpReplyLength);
                memset(icmpReplyBuffer, 0, icmpReplyLength);

                if (!Icmp6SendEcho2( 
                    IcmpHandle,
                    0,
                    NULL,
                    NULL,
                    ((PSOCKADDR_IN6)&sourceAddress),
                    ((PSOCKADDR_IN6)&destinationAddress),
                    icmpEchoBuffer->Buffer,
                    (USHORT)icmpEchoBuffer->Length,
                    &pingOptions,
                    icmpReplyBuffer,
                    icmpReplyLength,
                    DEFAULT_TIMEOUT
                    ))
                {
                    if (GetLastError() == IP_REQ_TIMED_OUT)
                    {
                        PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, i + 1, L"*");

                        if (i == (MAX_PINGS - 1))
                        {
                            if (haveReply)
                            {
                                TracertShowIpAddress(Context, lvItemIndex, &reply6Address);
                            }
                            else
                            {
                                PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, IP_ADDRESS_COLUMN, TracertGetErrorMessage(GetLastError())->Buffer);
                            }
                        }
                    }
                    else
                    {
                        PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, IP_ADDRESS_COLUMN, TracertGetErrorMessage(GetLastError())->Buffer);
                    }
                }
                else
                { 
                    PICMPV6_ECHO_REPLY reply6 = (PICMPV6_ECHO_REPLY)icmpReplyBuffer;

                    if (reply6->Status == IP_SUCCESS) 
                    {
                        TracertUpdateTime(Context, lvItemIndex, i + 1, reply6->RoundTripTime);

                        if (i == (MAX_PINGS - 1))
                        { 
                            TracertShowIpAddress(Context, lvItemIndex, (PIN6_ADDR)&reply6->Address.sin6_addr);
                            goto loop_end; 
                        } 
                        else 
                        { 
                            haveReply = TRUE;
                            memcpy(&reply6Address, &reply6->Address.sin6_addr, sizeof(IN6_ADDR)); 
                        } 
                    } 
                    else if (reply6->Status == IP_HOP_LIMIT_EXCEEDED) 
                    {
                        TracertUpdateTime(Context, lvItemIndex, i + 1, reply6->RoundTripTime);

                        if (i == (MAX_PINGS - 1))
                        { 
                            TracertShowIpAddress(Context, lvItemIndex, (PIN6_ADDR)&reply6->Address.sin6_addr);
     
                            if (reply6->RoundTripTime < MIN_INTERVAL)
                            { 
                                Sleep(MIN_INTERVAL - reply6->RoundTripTime); 
                            }
                        } 
                        else 
                        { 
                            haveReply = TRUE; 
                            memcpy(&reply6Address, &reply6->Address.sin6_addr, sizeof(IN6_ADDR)); 
                        } 
                    } 
                    else 
                    { 
                        PhSetListViewSubItem(Context->OutputHandle, lvItemIndex, IP_ADDRESS_COLUMN, TracertGetErrorMessage(GetLastError())->Buffer);
                    } 
                }
            }
        }
 
        pingOptions.Ttl++;
    } 
 

loop_end:
    //SendOutputStringFormat(Context, PhFormatString(L"\r\nTrace complete.\r\n")); 
    IcmpCloseHandle(IcmpHandle); 

    PostMessage(Context->WindowHandle, NTM_RECEIVEDFINISH, 0, 0);

    return TRUE; 
}




NTSTATUS NetworkTracertThreadStart(
    _In_ PVOID Parameter
    )
{
    PNETWORK_OUTPUT_CONTEXT context;
    PH_AUTO_POOL autoPool;

    context = (PNETWORK_OUTPUT_CONTEXT)Parameter;

    PhInitializeAutoPool(&autoPool);


    RunTraceRoute(context);

    

    PhDrainAutoPool(&autoPool);
    PhDeleteAutoPool(&autoPool);

    return STATUS_SUCCESS;
}




INT_PTR CALLBACK TracertDlgProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    )
{
    PNETWORK_OUTPUT_CONTEXT context;

    if (uMsg == WM_INITDIALOG)
    {
        context = (PNETWORK_OUTPUT_CONTEXT)lParam;
        SetProp(hwndDlg, L"Context", (HANDLE)context);
    }
    else
    {
        context = (PNETWORK_OUTPUT_CONTEXT)GetProp(hwndDlg, L"Context");

        if (uMsg == WM_DESTROY)
        {
            PhSaveListViewColumnsToSetting(SETTING_NAME_TRACERT_COLUMNS, context->OutputHandle);
            PhSaveWindowPlacementToSetting(SETTING_NAME_TRACERT_WINDOW_POSITION, SETTING_NAME_TRACERT_WINDOW_SIZE, hwndDlg);

            PhSaveWindowPlacementToSetting(
                SETTING_NAME_PING_WINDOW_POSITION,
                SETTING_NAME_PING_WINDOW_SIZE,
                hwndDlg
                );

            if (context->IconHandle)
                DestroyIcon(context->IconHandle);

            if (context->FontHandle)
                DeleteObject(context->FontHandle);

            PhDeleteLayoutManager(&context->LayoutManager);
            context->OutputHandle = NULL;

            RemoveProp(hwndDlg, L"Context");
            PhFree(context);

            PostQuitMessage(0);
        }
    }

    if (!context)
        return FALSE;

    switch (uMsg)
    {
    case WM_INITDIALOG:
        {
            PH_RECTANGLE windowRectangle;

            context->WindowHandle = hwndDlg;
            context->OutputHandle = GetDlgItem(hwndDlg, IDC_NETOUTPUTEDIT);
            context->MaxPingTimeout = PhGetIntegerSetting(SETTING_NAME_PING_MINIMUM_SCALING);
            context->PingSize = PhGetIntegerSetting(SETTING_NAME_PING_SIZE);

            windowRectangle.Position = PhGetIntegerPairSetting(SETTING_NAME_TRACERT_WINDOW_POSITION);
            windowRectangle.Size = PhGetScalableIntegerPairSetting(SETTING_NAME_TRACERT_WINDOW_SIZE, TRUE).Pair;

            // Create the font handle.
            context->FontHandle = CommonCreateFont(-15, GetDlgItem(hwndDlg, IDC_STATUS));

            // Load the Process Hacker icon.
            context->IconHandle = (HICON)LoadImage(
                NtCurrentPeb()->ImageBaseAddress,
                MAKEINTRESOURCE(PHAPP_IDI_PROCESSHACKER),
                IMAGE_ICON,
                GetSystemMetrics(SM_CXICON),
                GetSystemMetrics(SM_CYICON),
                LR_SHARED
                );

            // Set window icon.
            if (context->IconHandle)
                SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)context->IconHandle);

            //PhInitializeWorkQueue(&context->PingWorkQueue, 0, 20, 5000);

            PhSetListViewStyle(context->OutputHandle, FALSE, TRUE);
            PhSetControlTheme(context->OutputHandle, L"explorer");
            PhAddListViewColumn(context->OutputHandle, 0, 0, 0, LVCFMT_RIGHT, 30, L"TTL");
            for (UINT i = 0; i < MAX_PINGS; i++)
                PhAddListViewColumn(context->OutputHandle, i + 1, i + 1, i + 1, LVCFMT_RIGHT, 50, L"Time");
            PhAddListViewColumn(context->OutputHandle, IP_ADDRESS_COLUMN, IP_ADDRESS_COLUMN, IP_ADDRESS_COLUMN, LVCFMT_LEFT, 120, L"Ip Address");
            PhAddListViewColumn(context->OutputHandle, HOSTNAME_COLUMN, HOSTNAME_COLUMN, HOSTNAME_COLUMN, LVCFMT_LEFT, 240, L"Hostname");
            PhSetExtendedListView(context->OutputHandle);
            PhLoadListViewColumnsFromSetting(SETTING_NAME_TRACERT_COLUMNS, context->OutputHandle);

            PhInitializeLayoutManager(&context->LayoutManager, hwndDlg);
            PhAddLayoutItem(&context->LayoutManager, context->OutputHandle, NULL, PH_ANCHOR_ALL);
            PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_STATUS), NULL, PH_ANCHOR_TOP | PH_ANCHOR_LEFT | PH_ANCHOR_RIGHT);
            PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_ICMP_PANEL), NULL, PH_ANCHOR_BOTTOM | PH_ANCHOR_LEFT);
            PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_PINGS_SENT), NULL, PH_ANCHOR_BOTTOM | PH_ANCHOR_LEFT);
            PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_PINGS_LOST), NULL, PH_ANCHOR_BOTTOM | PH_ANCHOR_LEFT);
            PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_BAD_HASH), NULL, PH_ANCHOR_BOTTOM | PH_ANCHOR_LEFT);
            PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDCANCEL), NULL, PH_ANCHOR_BOTTOM | PH_ANCHOR_RIGHT);            

            // Load window settings.
            if (windowRectangle.Position.X == 0 || windowRectangle.Position.Y == 0)
                PhCenterWindow(hwndDlg, GetParent(hwndDlg));
            else
            {
                PhLoadWindowPlacementFromSetting(SETTING_NAME_PING_WINDOW_POSITION, SETTING_NAME_PING_WINDOW_SIZE, hwndDlg);
            }

            HANDLE dialogThread = INVALID_HANDLE_VALUE;

            Static_SetText(context->WindowHandle,
                PhaFormatString(L"Tracing route to %s...", context->IpAddressString)->Buffer
                );
            Static_SetText(GetDlgItem(hwndDlg, IDC_STATUS),
                PhaFormatString(L"Tracing route to %s...", context->IpAddressString)->Buffer
                );

            if (dialogThread = PhCreateThread(0, NetworkTracertThreadStart, (PVOID)context))
            {
                NtClose(dialogThread);
            }
        }
        break;
    case WM_COMMAND:
        {
            switch (GET_WM_COMMAND_ID(wParam, lParam))
            {
            case IDCANCEL:
            case IDOK:
                DestroyWindow(hwndDlg);
                break;
            }
        }
        break;
    case WM_SIZE:
        PhLayoutManagerLayout(&context->LayoutManager);
        break;
    case NTM_RECEIVEDFINISH:
        {
            PPH_STRING windowText = PhGetWindowText(context->WindowHandle);

            if (windowText)
            {
                Static_SetText(
                    context->WindowHandle,
                    PhaFormatString(L"%s complete.", windowText->Buffer)->Buffer
                    );
                PhDereferenceObject(windowText);
            }

            windowText = PhGetWindowText(GetDlgItem(hwndDlg, IDC_STATUS));

            if (windowText)
            {
                Static_SetText(
                    GetDlgItem(hwndDlg, IDC_STATUS),
                    PhaFormatString(L"%s complete.", windowText->Buffer)->Buffer
                    );
                PhDereferenceObject(windowText);
            }
        }
        break;
    }

    return FALSE;
}

NTSTATUS TracertDialogThreadStart(
    _In_ PVOID Parameter
    )
{
    BOOL result;
    MSG message;
    HWND windowHandle;
    PH_AUTO_POOL autoPool;
    PNETWORK_OUTPUT_CONTEXT context = (PNETWORK_OUTPUT_CONTEXT)Parameter;

    PhInitializeAutoPool(&autoPool);

    windowHandle = CreateDialogParam(
        (HINSTANCE)PluginInstance->DllBase,
        MAKEINTRESOURCE(IDD_TRACERT),
        PhMainWndHandle,
        TracertDlgProc,
        (LPARAM)Parameter
        );

    ShowWindow(windowHandle, SW_SHOW);
    SetForegroundWindow(windowHandle);

    while (result = GetMessage(&message, NULL, 0, 0))
    {
        if (result == -1)
            break;

        if (!IsDialogMessage(context->WindowHandle, &message))
        {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

        PhDrainAutoPool(&autoPool);
    }

    PhDeleteAutoPool(&autoPool);

    return STATUS_SUCCESS;
}

VOID ShowTracertWindow(
    _In_ PPH_NETWORK_ITEM NetworkItem
    )
{
    HANDLE dialogThread = INVALID_HANDLE_VALUE;
    PNETWORK_OUTPUT_CONTEXT context;

    context = (PNETWORK_OUTPUT_CONTEXT)PhAllocate(sizeof(NETWORK_OUTPUT_CONTEXT));
    memset(context, 0, sizeof(NETWORK_OUTPUT_CONTEXT));

    context->RemoteEndpoint = NetworkItem->RemoteEndpoint;

    if (NetworkItem->RemoteEndpoint.Address.Type == PH_IPV4_NETWORK_TYPE)
    {
        RtlIpv4AddressToString(&NetworkItem->RemoteEndpoint.Address.InAddr, context->IpAddressString);
    }
    else if (NetworkItem->RemoteEndpoint.Address.Type == PH_IPV6_NETWORK_TYPE)
    {
        RtlIpv6AddressToString(&NetworkItem->RemoteEndpoint.Address.In6Addr, context->IpAddressString);
    }

    if (dialogThread = PhCreateThread(0, TracertDialogThreadStart, (PVOID)context))
    {
        NtClose(dialogThread);
    }
}

VOID ShowTracertWindowFromAddress(
    _In_ PH_IP_ENDPOINT RemoteEndpoint
    )
{
    HANDLE dialogThread = INVALID_HANDLE_VALUE;
    PNETWORK_OUTPUT_CONTEXT context;

    context = (PNETWORK_OUTPUT_CONTEXT)PhAllocate(sizeof(NETWORK_OUTPUT_CONTEXT));
    memset(context, 0, sizeof(NETWORK_OUTPUT_CONTEXT));

    context->RemoteEndpoint = RemoteEndpoint;

    if (RemoteEndpoint.Address.Type == PH_IPV4_NETWORK_TYPE)
    {
        RtlIpv4AddressToString(&RemoteEndpoint.Address.InAddr, context->IpAddressString);
    }
    else if (RemoteEndpoint.Address.Type == PH_IPV6_NETWORK_TYPE)
    {
        RtlIpv6AddressToString(&RemoteEndpoint.Address.In6Addr, context->IpAddressString);
    }

    if (dialogThread = PhCreateThread(0, TracertDialogThreadStart, (PVOID)context))
    {
        NtClose(dialogThread);
    }
}