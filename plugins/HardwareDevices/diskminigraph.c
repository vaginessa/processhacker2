#include "devices.h"
#include <toolstatusintf.h>

BOOLEAN graphEnabled = FALSE;
static HWND GraphHandle = NULL;
static PH_GRAPH_STATE GraphState;

BOOLEAN GraphQueryEnabled(VOID)
{
    return !!graphEnabled;
}

VOID GraphSetEnabled(VOID)
{
    graphEnabled = !graphEnabled;

    //PhSetIntegerSetting(SETTING_NAME_TOOLSTATUS_CONFIG, ToolStatusConfig.Flags);

    if (!graphEnabled && GraphHandle)
    {
        PhDeleteGraphState(&GraphState);

        DestroyWindow(GraphHandle);
        GraphHandle = NULL;
    }
}

HWND GraphCreate(VOID)
{
    if (!GraphHandle)
    {
        GraphHandle = CreateWindow(
            PH_GRAPH_CLASSNAME,
            NULL,
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            0,
            0,
            0,
            0,
            PhMainWndHandle,
            NULL,
            NULL,
            NULL
            );
        Graph_SetTooltip(GraphHandle, TRUE);

        PhInitializeGraphState(&GraphState);
    }

    return GraphHandle;
}

VOID GraphUpdate(VOID)
{
    if (GraphHandle)
    {
        GraphState.Valid = FALSE;
        GraphState.TooltipIndex = -1;
        Graph_MoveGrid(GraphHandle, 1);
        Graph_Draw(GraphHandle);
        Graph_UpdateTooltip(GraphHandle);
        InvalidateRect(GraphHandle, NULL, FALSE);
    }
}

VOID GraphNotifyInfo(_In_ LPNMHDR Header)
{
    switch (Header->code)
    {
    case GCN_GETDRAWINFO:
        {
            PPH_GRAPH_GETDRAWINFO getDrawInfo = (PPH_GRAPH_GETDRAWINFO)Header;
            PPH_GRAPH_DRAW_INFO drawInfo = getDrawInfo->DrawInfo;

            drawInfo->Flags = PH_GRAPH_USE_GRID_X | PH_GRAPH_USE_LINE_2;
            PhSiSetColorsGraphDrawInfo(drawInfo, PhGetIntegerSetting(L"ColorIoReadOther"), PhGetIntegerSetting(L"ColorIoWrite"));

            //if (ProcessesUpdatedCount < 2)
            //    return;

            //PhGraphStateGetDrawInfo(&GraphState, getDrawInfo, SystemStatistics.IoReadHistory->Count);

            if (!GraphState.Valid)
            {
                //FLOAT max = 1024 * 1024; // minimum scaling of 1 MB.

                //for (ULONG i = 0; i < drawInfo->LineDataCount; i++)
                //{
                //    IoGraphState.Data1[i] =
                //        (FLOAT)PhGetItemCircularBuffer_ULONG64(SystemStatistics.IoReadHistory, i) +
                //        (FLOAT)PhGetItemCircularBuffer_ULONG64(SystemStatistics.IoOtherHistory, i);
                //    IoGraphState.Data2[i] =
                //        (FLOAT)PhGetItemCircularBuffer_ULONG64(SystemStatistics.IoWriteHistory, i);

                //    if (max < IoGraphState.Data1[i] + IoGraphState.Data2[i])
                //        max = IoGraphState.Data1[i] + IoGraphState.Data2[i];
                //}

                //PhDivideSinglesBySingle(IoGraphState.Data1, max, drawInfo->LineDataCount);
                //PhDivideSinglesBySingle(IoGraphState.Data2, max, drawInfo->LineDataCount);

                GraphState.Valid = TRUE;
            }
        }
        break;
    case GCN_GETTOOLTIPTEXT:
        {
            PPH_GRAPH_GETTOOLTIPTEXT getTooltipText = (PPH_GRAPH_GETTOOLTIPTEXT)Header;

            if (getTooltipText->Index < getTooltipText->TotalCount)
            {
                //ULONG64 ioRead;
                //ULONG64 ioWrite;
                //ULONG64 ioOther;

                //ioRead = PhGetItemCircularBuffer_ULONG64(SystemStatistics.IoReadHistory, getTooltipText->Index);
                //ioWrite = PhGetItemCircularBuffer_ULONG64(SystemStatistics.IoWriteHistory, getTooltipText->Index);
                //ioOther = PhGetItemCircularBuffer_ULONG64(SystemStatistics.IoOtherHistory, getTooltipText->Index);

                //PhMoveReference(&IoGraphState.TooltipText, PhFormatString(
                //    L"R: %s\nW: %s\nO: %s%s\n%s",
                //    PhaFormatSize(ioRead, -1)->Buffer,
                //    PhaFormatSize(ioWrite, -1)->Buffer,
                //    PhaFormatSize(ioOther, -1)->Buffer,
                //    PhGetStringOrEmpty(PhSipGetMaxIoString(getTooltipText->Index)),
                //    PH_AUTO_T(PH_STRING, PhGetStatisticsTimeString(NULL, getTooltipText->Index))->Buffer
                //    ));
                //getTooltipText->Text = IoGraphState.TooltipText->sr;
            }
        }
        break;
    case GCN_MOUSEEVENT:
        {
            PPH_GRAPH_MOUSEEVENT mouseEvent = (PPH_GRAPH_MOUSEEVENT)Header;
            PPH_PROCESS_RECORD record = NULL;

            if (mouseEvent->Message == WM_RBUTTONUP)
            {
                //ShowCustomizeMenu();
            }
        }
        break;
    }
}


VOID MiniCreateGraphs(VOID)
{
    PPH_PLUGIN toolStatusPlugin;
    PTOOLSTATUS_INTERFACE ToolStatusInterface = NULL;

    if (toolStatusPlugin = PhFindPlugin(TOOLSTATUS_PLUGIN_NAME))
    {
        ToolStatusInterface = PhGetPluginInformation(toolStatusPlugin)->Interface;

        if (ToolStatusInterface->Version < TOOLSTATUS_INTERFACE_VERSION)
            ToolStatusInterface = NULL;
    }

    if (ToolStatusInterface)
    {
        for (ULONG i = 0; i < DiskDrivesList->Count; i++)
        {
            PDV_DISK_ENTRY entry = PhReferenceObjectSafe(DiskDrivesList->Items[i]);

            if (!entry)
                continue;

            ToolStatusInterface->RegisterRebarGraph(
                entry->Id.DevicePath->Buffer,
                GraphQueryEnabled,
                GraphSetEnabled,
                GraphCreate,
                GraphUpdate,
                GraphNotifyInfo);
        }
    }
}

