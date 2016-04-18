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

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "nettools.h"
#include <commonutil.h>
#include <mxml.h>
#include <Shlwapi.h>
#include <winhttp.h>

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

    return whoisServerName;
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
            CHAR whoisQuery[0x100] = "";

            sprintf(whoisQuery, "%S\r\n", query);

            if (send(socketHandle, whoisQuery, (INT)strlen(whoisQuery), 0) == SOCKET_ERROR)
            {
                perror("send failed");
                break;
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
        // <server> found the following authoritative answer from: %s

        if (PhEqualString2(whoisServerName, L"whois.arin.net", TRUE))
        {
            WCHAR buffer[100] = L"";

            wcscat(buffer, L"n ");
            wcscat(buffer, ip);

            if (whois_query(whoisServerName->Buffer, buffer, data))
            {

            }

            if (whoisReferralServer = WhoisExtractReferralServer(*data))
            {
                //if (whois_query(whoisReferralServer->Buffer, buffer, data))
                //{
                //    return FALSE;
                //}
            }
        }
        else
        {
            if (!whois_query(whoisServerName->Buffer, ip, data))
            {

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
    BOOLEAN isSuccess = FALSE;
    ULONG xmlLength = 0;
    PSTR xmlBuffer = NULL;
    PPH_STRING phVersion = NULL;
    PPH_STRING userAgent = NULL;
    PPH_STRING whoisHttpGetString = NULL;
    HINTERNET connectionHandle = NULL;
    HINTERNET requestHandle = NULL;
    HINTERNET sessionHandle = NULL;
    PNETWORK_OUTPUT_CONTEXT context = NULL;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig = { 0 };

    //4.4.3. IP Addresses and Networks
    // https://www.arin.net/resources/whoisrws/whois_api.html
    //TODO: use REF string from /rest/ip/ lookup for querying the IP network: "/rest/net/NET-74-125-0-0-1?showDetails=true"
    // or use CIDR string from /rest/ip/ lookup for querying the IP network: "/rest/cidr/216.34.181.0/24?showDetails=true
    //WinHttpAddRequestHeaders(requestHandle, L"application/arin.whoisrws-v1+xml", -1L, 0);

    __try
    {
        // Query thread context.
        if ((context = (PNETWORK_OUTPUT_CONTEXT)Parameter) == NULL)
            __leave;

        PPH_STRING data = NULL;

        get_whois(context->IpAddressString, &data);

        SendMessage(context->WindowHandle, NTM_RECEIVEDWHOIS, 0, (LPARAM)data);
        SendMessage(context->WindowHandle, NTM_RECEIVEDFINISH, 0, 0);

        //PhFree(data);
        __leave;

        // Query PH version.
        if ((phVersion = PhGetPhVersion()) == NULL)
            __leave;

        // Create a user agent string.
        if ((userAgent = PhConcatStrings2(L"Process Hacker ", phVersion->Buffer)) == NULL)
            __leave;

        // Query the current system proxy
        WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);

        // Open the HTTP session with the system proxy configuration if available
        if (!(sessionHandle = WinHttpOpen(
            userAgent->Buffer,
            proxyConfig.lpszProxy != NULL ? WINHTTP_ACCESS_TYPE_NAMED_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            proxyConfig.lpszProxy,
            proxyConfig.lpszProxyBypass,
            0
            )))
        {
            __leave;
        }

        if (WindowsVersion >= WINDOWS_8_1)
        {
            // Enable GZIP and DEFLATE support on Windows 8.1 and above using undocumented flags.
            ULONG httpFlags = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;

            WinHttpSetOption(
                sessionHandle,
                WINHTTP_OPTION_DECOMPRESSION,
                &httpFlags,
                sizeof(ULONG)
                );
        }

        if (!(connectionHandle = WinHttpConnect(
            sessionHandle,
            L"whois.arin.net",
            INTERNET_DEFAULT_HTTP_PORT,
            0
            )))
        {
            __leave;
        }

        if (!(whoisHttpGetString = PhFormatString(L"/rest/ip/%s", context->IpAddressString)))
            __leave;

        if (!(requestHandle = WinHttpOpenRequest(
            connectionHandle,
            NULL,
            whoisHttpGetString->Buffer,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_REFRESH
            )))
        {
            __leave;
        }

        if (!WinHttpAddRequestHeaders(requestHandle, L"Accept: text/plain", -1L, 0))
            __leave;

        if (!WinHttpSendRequest(
            requestHandle,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH, 0
            ))
        {
            __leave;
        }

        if (!WinHttpReceiveResponse(requestHandle, NULL))
            __leave;

        //if (!ReadRequestString(requestHandle, &xmlBuffer, &xmlLength))
        //    __leave;

        PostMessage(context->WindowHandle, NTM_RECEIVEDWHOIS, (WPARAM)xmlLength, (LPARAM)xmlBuffer);
        PostMessage(context->WindowHandle, NTM_RECEIVEDFINISH, 0, 0);

        isSuccess = TRUE;
    }
    __finally
    {
        if (phVersion)
            PhDereferenceObject(phVersion);

        if (userAgent)
            PhDereferenceObject(userAgent);

        if (whoisHttpGetString)
            PhDereferenceObject(whoisHttpGetString);

        if (requestHandle)
            WinHttpCloseHandle(requestHandle);

        if (connectionHandle)
            WinHttpCloseHandle(connectionHandle);

        if (sessionHandle)
            WinHttpCloseHandle(sessionHandle);
    }

    return STATUS_SUCCESS;
}