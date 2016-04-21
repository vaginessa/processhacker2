/*
 * Process Hacker Network Tools -
 *   Whois dialog
 *
 * Copyright (C) 2013-2016 dmex
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

static PPH_STRING TrimString(
    _In_ PPH_STRING String
    )
{
    static PH_STRINGREF whitespace = PH_STRINGREF_INIT(L"  ");
    PH_STRINGREF sr = String->sr;
    PhTrimStringRef(&sr, &whitespace, 0);
    return PhCreateString2(&sr);
}

static BOOLEAN ReadSocketString(
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


BOOLEAN WhoisExtractServerUrl(
    _In_ PPH_STRING WhoisResponce,
    _Out_ PPH_STRING *WhoisServerAddress
    )
{
    ULONG_PTR whoisServerHostnameIndex;
    ULONG_PTR whoisServerHostnameLength;
    PPH_STRING whoisServerName;

    whoisServerHostnameIndex = PhFindStringInString(WhoisResponce, 0, L"whois:");
    if (whoisServerHostnameIndex == -1)
        return FALSE;

    whoisServerHostnameLength = PhFindStringInString(WhoisResponce, whoisServerHostnameIndex, L"\n") - whoisServerHostnameIndex;
    if (whoisServerHostnameLength == -1)
        return FALSE;

    whoisServerName = PhSubstring(
        WhoisResponce,
        whoisServerHostnameIndex + PhCountStringZ(L"whois:"),
        (ULONG)whoisServerHostnameLength - PhCountStringZ(L"whois:")
        );

    *WhoisServerAddress = TrimString(whoisServerName);

    PhDereferenceObject(whoisServerName);

    return TRUE;
}

BOOLEAN WhoisExtractReferralServer(
    _In_ PPH_STRING WhoisResponce,
    _Out_ PPH_STRING *WhoisServerAddress,
    _Out_ PPH_STRING *WhoisServerPort
    )
{
    ULONG_PTR whoisServerHostnameIndex;
    ULONG_PTR whoisServerHostnameLength;
    PPH_STRING whoisServerName;
    PPH_STRING whoisServerHostname;
    WCHAR urlProtocal[0x100] = L"";
    WCHAR urlHost[0x100] = L"";
    WCHAR urlPort[0x100] = L"";
    WCHAR urlPath[0x100] = L"";

    whoisServerHostnameIndex = PhFindStringInString(WhoisResponce, 0, L"ReferralServer:");
    if (whoisServerHostnameIndex == -1)
        return FALSE;

    whoisServerHostnameLength = PhFindStringInString(WhoisResponce, whoisServerHostnameIndex, L"\n") - whoisServerHostnameIndex;
    if (whoisServerHostnameLength == -1)
        return FALSE;

    whoisServerName = PhSubstring(
        WhoisResponce,
        whoisServerHostnameIndex + PhCountStringZ(L"ReferralServer:"),
        (ULONG)whoisServerHostnameLength - PhCountStringZ(L"ReferralServer:")
        );

    whoisServerHostname = TrimString(whoisServerName);
    
    if (swscanf_s(
        whoisServerHostname->Buffer,
        L"%[^:]://%[^:]:%[^/]/%s",
        urlProtocal,
        (unsigned)ARRAYSIZE(urlProtocal),
        urlHost,
        (unsigned)ARRAYSIZE(urlHost),
        urlPort,
        (unsigned)ARRAYSIZE(urlPort),
        urlPath,
        (unsigned)ARRAYSIZE(urlPath)
        ))
    {
        *WhoisServerAddress = PhCreateString(urlHost);
        *WhoisServerPort = PhCreateString(urlPort);

        PhDereferenceObject(whoisServerName);
        PhDereferenceObject(whoisServerHostname);
        return TRUE;
    }

    PhDereferenceObject(whoisServerName);
    PhDereferenceObject(whoisServerHostname);

    return FALSE;
}



BOOLEAN WhoisQueryServer(
    _In_ PWSTR WhoisServerAddress,
    _In_ PWSTR WhoisServerPort,
    _In_ PWSTR QueryString, 
    _In_ PPH_STRING* response
    )
{
    WSADATA winsockStartup;
    PADDRINFOW result = NULL;
    PADDRINFOW ptr = NULL;
    ADDRINFOW hints;
    ULONG whoisResponceLength = 0;
    PSTR whoisResponce = NULL;
    CHAR whoisQuery[0x100] = "";

    if (!WhoisServerPort || PhCountStringZ(WhoisServerPort) < 1)
        WhoisServerPort = L"43";

    if (PhEqualStringZ(WhoisServerAddress, L"whois.arin.net", TRUE))
    {
        _snprintf_s(whoisQuery, sizeof(whoisQuery), _TRUNCATE, "n %S\r\n", QueryString);
    }
    else
    {
        _snprintf_s(whoisQuery, sizeof(whoisQuery), _TRUNCATE, "%S\r\n", QueryString);
    }

    if (WSAStartup(WINSOCK_VERSION, &winsockStartup) != ERROR_SUCCESS)
        return FALSE;

    memset(&hints, 0, sizeof(ADDRINFOW));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (GetAddrInfo(WhoisServerAddress, WhoisServerPort, &hints, &result))
    {
        WSACleanup();
        return FALSE;
    }

    for (ptr = result; ptr; ptr = ptr->ai_next)
    {
        SOCKET socketHandle = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

        if (socketHandle == INVALID_SOCKET)
            continue;

        if (connect(socketHandle, ptr->ai_addr, (INT)ptr->ai_addrlen) == SOCKET_ERROR)
        {
            closesocket(socketHandle);
            continue;
        }

        if (send(socketHandle, whoisQuery, (INT)strlen(whoisQuery), 0) == SOCKET_ERROR)
        {
            closesocket(socketHandle);
            continue;
        }

        if (ReadSocketString(socketHandle, &whoisResponce, &whoisResponceLength))
        {
            closesocket(socketHandle);
            break;
        }
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

BOOLEAN WhoisQueryLookup(
    _In_ PWSTR IpAddress, 
    _In_ PPH_STRING_BUILDER sb
    )
{
    PPH_STRING whoisResponse = NULL;
    PPH_STRING whoisReferralResponse = NULL;
    PPH_STRING whoisServerName = NULL;
    PPH_STRING whoisReferralServerName = NULL;
    PPH_STRING whoisReferralServerPort = NULL;

    if (!WhoisQueryServer(L"whois.iana.org", L"43", IpAddress, &whoisResponse))
    {
        PhAppendFormatStringBuilder(sb, L"Connection to whois.iana.org failed.\n");
        return FALSE;
    }

    if (!WhoisExtractServerUrl(whoisResponse, &whoisServerName))
    {
        PhAppendFormatStringBuilder(sb, L"Error parsing whois.iana.org response:\n%s\n", whoisResponse->Buffer);
        return TRUE;
    }

    PhAppendFormatStringBuilder(sb, L"whois.iana.org found the following authoritative answer from: %s\n", whoisServerName->Buffer);

    if (WhoisQueryServer(whoisServerName->Buffer, L"43", IpAddress, &whoisResponse))
    {
        // Check if the response contains a referral server.
        if (WhoisExtractReferralServer(whoisResponse, &whoisReferralServerName, &whoisReferralServerPort))
        {
            PhAppendFormatStringBuilder(sb, L"%s referred the request to: %s\n", whoisServerName->Buffer, whoisReferralServerName->Buffer);

            if (WhoisQueryServer(whoisReferralServerName->Buffer, whoisReferralServerPort->Buffer, IpAddress, &whoisReferralResponse))
            {
                PhAppendFormatStringBuilder(sb, L"\n%s\n", whoisReferralResponse->Buffer);
                PhAppendFormatStringBuilder(sb, L"\nOriginal request to %s:\n%s\n", whoisServerName->Buffer, whoisResponse->Buffer);

                PhClearReference(&whoisResponse);
                PhClearReference(&whoisReferralResponse);
                PhClearReference(&whoisServerName);
                PhClearReference(&whoisReferralServerName);
                PhClearReference(&whoisReferralServerPort);
                return TRUE;
            }

            PhAppendFormatStringBuilder(sb, L"\n%s", whoisResponse->Buffer);

            PhClearReference(&whoisResponse);
            PhClearReference(&whoisReferralResponse);
            PhClearReference(&whoisServerName);
            PhClearReference(&whoisReferralServerName);
            PhClearReference(&whoisReferralServerPort);
            return TRUE;
        }
        else
        {
            PhAppendFormatStringBuilder(sb, L"\n%s", whoisResponse->Buffer);

            PhClearReference(&whoisResponse);
            PhClearReference(&whoisReferralResponse);
            PhClearReference(&whoisServerName);
            PhClearReference(&whoisReferralServerName);
            PhClearReference(&whoisReferralServerPort);
            return TRUE;
        }
    }

    PhAppendFormatStringBuilder(sb, L"\n%s", whoisResponse->Buffer);

    PhClearReference(&whoisResponse);
    PhClearReference(&whoisReferralResponse);
    PhClearReference(&whoisServerName);
    PhClearReference(&whoisReferralServerName);
    PhClearReference(&whoisReferralServerPort);
    return TRUE;
}





NTSTATUS NetworkWhoisThreadStart(
    _In_ PVOID Parameter
)
{
    PNETWORK_OUTPUT_CONTEXT context = NULL;
    PH_STRING_BUILDER whoisReplySb;

    context = (PNETWORK_OUTPUT_CONTEXT)Parameter;

    PhInitializeStringBuilder(&whoisReplySb, 0x100);

    WhoisQueryLookup(context->IpAddressString, &whoisReplySb);

    PostMessage(context->WindowHandle, NTM_RECEIVEDWHOIS, 0, (LPARAM)PhFinalStringBuilderString(&whoisReplySb));
    PostMessage(context->WindowHandle, NTM_RECEIVEDFINISH, 0, 0);

    return STATUS_SUCCESS;
}