/*
 * Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
 *
 * This file is part of System Informer.
 *
 * Authors:
 *
 *     jxy-s   2022-2026
 *
 */

#pragma once
#include <kph.h>
#include <kphmsg.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphCleanupInformer(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphInitializeInformer(
    VOID
    );

typedef struct _KPH_INFORMER_CONTEXT
{
    ULONG Count;
    PKPH_PROCESS_CONTEXT Items[8];
} KPH_INFORMER_CONTEXT, *PKPH_INFORMER_CONTEXT;

FORCEINLINE
VOID KphInformerAppend(
    _Inout_ PKPH_INFORMER_CONTEXT Context,
    _In_opt_ PKPH_PROCESS_CONTEXT Process
    )
{
    if (!Process)
    {
        return;
    }

    for (ULONG i = 0; i < Context->Count; i++)
    {
        if (Context->Items[i] == Process)
        {
            return;
        }
    }

    if (NT_VERIFY(Context->Count < ARRAYSIZE(Context->Items)))
    {
        Context->Items[Context->Count++] = Process;
        KphReferenceObject(Process);
    }
}

FORCEINLINE
VOID KphInformerMove(
    _Inout_ PKPH_INFORMER_CONTEXT Context,
    _In_opt_ PKPH_PROCESS_CONTEXT Process
    )
{
    KphInformerAppend(Context, Process);

    if (Process)
    {
        KphDereferenceObject(Process);
    }
}

FORCEINLINE
VOID KphInformerInit(
    _Out_ PKPH_INFORMER_CONTEXT Context
    )
{
    RtlZeroMemory(Context, sizeof(KPH_INFORMER_CONTEXT));
    KphInformerMove(Context, KphGetCurrentProcessContext());
    KphInformerMove(Context, KphGetEProcessContext(PsGetThreadProcess(PsGetCurrentThread())));
}

FORCEINLINE
VOID KphInformerDelete(
    _In_ _Post_invalid_ PKPH_INFORMER_CONTEXT Context
    )
{
    for (ULONG i = 0; i < Context->Count; i++)
    {
        KphDereferenceObject(Context->Items[i]);
    }
}

BOOLEAN KphInformerAllowed(
    _In_ ULONG Index,
    _In_opt_ PKPH_INFORMER_CONTEXT Context
    );

#define KphInformerEnabled(name, ctx)                                          \
    KphInformerAllowed(KPH_INFORMER_INDEX(name), (ctx))

KPH_INFORMER_OPTIONS KphInformerOptions(
    _In_opt_ PKPH_INFORMER_CONTEXT Context
    );

#define KphInformerOpts(ctx)           KphInformerOptions((ctx))

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphGetInformerSettings(
    _Out_ PKPH_INFORMER_SETTINGS Settings,
    _In_ KPROCESSOR_MODE AccessMode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSetInformerSettings(
    _In_ PKPH_INFORMER_SETTINGS Settings,
    _In_ KPROCESSOR_MODE AccessMode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphGetInformerProcessSettings(
    _In_ HANDLE ProcessHandle,
    _Out_ PKPH_INFORMER_SETTINGS Settings,
    _In_ KPROCESSOR_MODE AccessMode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSetInformerProcessSettings(
    _In_opt_ HANDLE ProcessHandle,
    _In_ PKPH_INFORMER_SETTINGS Settings,
    _In_ KPROCESSOR_MODE AccessMode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphGetInformerStats(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ PKPH_INFORMER_STATS Stats,
    _In_ KPROCESSOR_MODE AccessMode
    );

// mini-filter informer

extern PFLT_FILTER KphFltFilter;

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphFltRegister(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphFltUnregister(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphFltInformerStart(
    VOID
    );

// process informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphProcessInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphProcessInformerStop(
    VOID
    );

// thread informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphThreadInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphThreadInformerStop(
    VOID
    );

// image informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphImageInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphImageInformerStop(
    VOID
    );

// object informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphObjectInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphObjectInformerStop(
    VOID
    );

// registry informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphRegistryInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphRegistryInformerStop(
    VOID
    );

// debug informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphDebugInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphDebugInformerStop(
    VOID
    );

// silo informer

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSiloInformerStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphSiloInformerStop(
    VOID
    );
