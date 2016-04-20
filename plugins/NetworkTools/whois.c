/*
 * Process Hacker Network Tools -
 *   Whois dialog
 *
 * Copyright (C) 2013 dmex
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

static PPH_STRING WhoisExtractServerUrl(
    _In_ PPH_STRING WhoisResponce
    )
{
    ULONG_PTR whoisServerHostnameIndex;
    ULONG_PTR whoisServerHostnameLength;

    whoisServerHostnameIndex = PhFindStringInString(WhoisResponce, 0, L"whois:");
    if (whoisServerHostnameIndex == -1)
        return NULL;

    whoisServerHostnameLength = PhFindStringInString(WhoisResponce, whoisServerHostnameIndex, L"\n") - whoisServerHostnameIndex;
    if (whoisServerHostnameLength == -1)
        return NULL;

    PPH_STRING whoisServerName = PhSubstring(
        WhoisResponce,
        whoisServerHostnameIndex + 14,
        (ULONG)whoisServerHostnameLength - 14
        );

    return whoisServerName;
}

static PPH_STRING WhoisExtractReferralServer(
    _In_ PPH_STRING WhoisResponce
    )
{
    ULONG_PTR whoisServerHostnameIndex;
    ULONG_PTR whoisServerHostnameLength;

    whoisServerHostnameIndex = PhFindStringInString(WhoisResponce, 0, L"ReferralServer:");
    if (whoisServerHostnameIndex == -1)
        return NULL;

    whoisServerHostnameLength = PhFindStringInString(WhoisResponce, whoisServerHostnameIndex, L"\n") - whoisServerHostnameIndex;
    if (whoisServerHostnameLength == -1)
        return NULL;

    PPH_STRING whoisServerName = PhSubstring(
        WhoisResponce,
        whoisServerHostnameIndex + 17,
        (ULONG)whoisServerHostnameLength - 17
        );

    int port = 80;
    WCHAR protocal[100];
    WCHAR address[100];
    WCHAR page[100];

    swscanf(whoisServerName->Buffer, L"%5s://%99[^:]:%99d/%99[^\n]", protocal, address, &port, page);

    PPH_STRING whoisServerAddress = PhCreateString(address);
    PhDereferenceObject(whoisServerName);

    return whoisServerAddress;
}


BOOLEAN ReadSocketString(
    _In_ SOCKET Handle,
    _Out_ _Deref_post_z_cap_(*DataLength) PSTR *Data,
    _Out_ ULONG *DataLength
    )
{
    PSTR data;
    ULONG allocatedLength;
    ULONG dataLength;
    ULONG returnLength;
    BYTE buffer[PAGE_SIZE];

    allocatedLength = sizeof(buffer);
    data = (PSTR)PhAllocate(allocatedLength);
    dataLength = 0;

    // Zero the buffer
    memset(buffer, 0, PAGE_SIZE);

    while ((returnLength = recv(Handle, buffer, PAGE_SIZE, 0)) != SOCKET_ERROR)
    {
        if (returnLength == 0)
            break;

        if (allocatedLength < dataLength + returnLength)
        {
            allocatedLength *= 2;
            data = (PSTR)PhReAllocate(data, allocatedLength);
        }

        // Copy the returned buffer into our pointer
        memcpy(data + dataLength, buffer, returnLength);
        // Zero the returned buffer for the next loop
        //memset(buffer, 0, returnLength);

        dataLength += returnLength;
    }

    if (allocatedLength < dataLength + 1)
    {
        allocatedLength++;
        data = (PSTR)PhReAllocate(data, allocatedLength);
    }

    // Ensure that the buffer is null-terminated.
    data[dataLength] = 0;

    *DataLength = dataLength;
    *Data = data;

    return TRUE;
}

BOOLEAN whois_query(PWSTR WhoisServerAddress, PWSTR query, PPH_STRING* response)
{
    WSADATA winsockStartup;
    PADDRINFOW result = NULL;
    PADDRINFOW ptr = NULL;
    ADDRINFOW hints;
    ULONG whoisResponceLength = 0;
    PSTR whoisResponce = NULL;
    CHAR whoisQuery[0x100] = "";

    if (PhEqualStringZ(WhoisServerAddress, L"whois.arin.net", TRUE))
    {
        _snprintf_s(whoisQuery, sizeof(whoisQuery), _TRUNCATE, "n %S\r\n", query);
    }
    else
    {
        _snprintf_s(whoisQuery, sizeof(whoisQuery), _TRUNCATE, "%S\r\n", query);
    }

    if (WSAStartup(WINSOCK_VERSION, &winsockStartup) != ERROR_SUCCESS)
        return FALSE;

    memset(&hints, 0, sizeof(ADDRINFOW));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (GetAddrInfo(WhoisServerAddress, L"43", &hints, &result))
    {
        WSACleanup();
        return FALSE;
    }

    for (ptr = result; ptr; ptr = ptr->ai_next)
    {
        SOCKET socketHandle = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

        if (socketHandle == INVALID_SOCKET)
            continue;

        if (connect(socketHandle, ptr->ai_addr, (int)ptr->ai_addrlen) != SOCKET_ERROR)
        {
            if (send(socketHandle, whoisQuery, (INT)strlen(whoisQuery), 0) == SOCKET_ERROR)
            {
                closesocket(socketHandle);
                continue;
            }

            ReadSocketString(socketHandle, &whoisResponce, &whoisResponceLength);

            closesocket(socketHandle);
            break;
        }

        closesocket(socketHandle);
    }

    FreeAddrInfo(result);
    WSACleanup();

    if (whoisResponce)
    {
        *response = PhConvertUtf8ToUtf16(whoisResponce);
        return TRUE;
    }

    return FALSE;
}

BOOLEAN get_whois(PWSTR ip, PPH_STRING* data)
{
    PPH_STRING whoisResponse = NULL;
    PPH_STRING whoisServerName = NULL;
    PPH_STRING whoisReferralServer = NULL;

    if (!whois_query(L"whois.iana.org", ip, &whoisResponse))
    {
        // Whois query failed
        return FALSE;
    }

    if (whoisServerName = WhoisExtractServerUrl(whoisResponse))
    {
        // whois.iana.org found the following authoritative answer from: %s

        if (whois_query(whoisServerName->Buffer, ip, &whoisResponse))
        {
            // Check if the response contains a referral server.
            if (whoisReferralServer = WhoisExtractReferralServer(whoisResponse))
            {
                PPH_STRING oldData = whoisResponse;
              
                if (whois_query(whoisReferralServer->Buffer, ip, &whoisResponse))
                {
                    *data = whoisResponse;

                    PhDereferenceObject(oldData);
                    PhDereferenceObject(whoisServerName);
                    return TRUE;
                }

                *data = oldData;
            }
            else
            {
                *data = whoisResponse;

                PhDereferenceObject(whoisServerName);
                return TRUE;
            }
        }

        PhDereferenceObject(whoisServerName);
    }

    return FALSE;
}





NTSTATUS NetworkWhoisThreadStart(
    _In_ PVOID Parameter
)
{
    PPH_STRING whoisReply = NULL;
    PNETWORK_OUTPUT_CONTEXT context = NULL;

    context = (PNETWORK_OUTPUT_CONTEXT)Parameter;

    if (get_whois(context->IpAddressString, &whoisReply))
    {
        PostMessage(context->WindowHandle, NTM_RECEIVEDWHOIS, 0, (LPARAM)whoisReply);
        PostMessage(context->WindowHandle, NTM_RECEIVEDFINISH, 0, 0);
    }

    return STATUS_SUCCESS;
}