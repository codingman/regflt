extern "C"
{
#include <wdm.h>
}
#include <dontuse.h>
#include <suppress.h>


//	Helper macros
//
#define PtrDiff( p1, p2 ) ( reinterpret_cast<const unsigned char*>(p1) - reinterpret_cast<const unsigned char*>(p2) )
#define Add2Ptr( p, add ) ( reinterpret_cast<const unsigned char*>(p) + (add) )

//	Forward Declarations
//
bool _RfIsKeyMySecretKey( __in PUNICODE_STRING pParentKeyName, __in PUNICODE_STRING pRelativeKeyName );
NTSTATUS _RfSplitParentAndRelativeNames( __in PCUNICODE_STRING pFullObjectName, __out_opt PUNICODE_STRING pParentObjectName, __out_opt PUNICODE_STRING pRelativeObjectName );
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry( __in PDRIVER_OBJECT pDriverObject, __in PUNICODE_STRING pRegistryPath );
NTSTATUS RfKeyHandleClose( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_KEY_HANDLE_CLOSE_INFORMATION CallbackData );
NTSTATUS RfPreCreateKeyEx( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_CREATE_KEY_INFORMATION CallbackData );
NTSTATUS RfPreCreateOrOpenKey( __in PREG_CREATE_KEY_INFORMATION CallbackData );
NTSTATUS RfPreOpenKeyEx( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_OPEN_KEY_INFORMATION CallbackData );
NTSTATUS RfPreRenameKey( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_RENAME_KEY_INFORMATION CallbackData );
NTSTATUS RfRegistryCallback( __in PVOID CallbackContext, __in PVOID Argument1, __in PVOID Argument2 );
void RfUnload( __in PDRIVER_OBJECT pDriverObject );

//	Global Variables
//
LARGE_INTEGER g_CmCookie = { 0 };
PEX_CALLBACK_FUNCTION g_RegistryCallbackTable[ MaxRegNtNotifyClass ] = { 0 };


bool _RfIsKeyMySecretKey( __in PUNICODE_STRING pKeyName )
{
    UNICODE_STRING ParentKeyName;
    UNICODE_STRING RelativeKeyName;
    if ( !NT_SUCCESS( _RfSplitParentAndRelativeNames( pKeyName, &ParentKeyName, &RelativeKeyName ) ) )
    {
        return false;
    }
    return _RfIsKeyMySecretKey( &ParentKeyName, &RelativeKeyName );
}

bool _RfIsKeyMySecretKey( __in PUNICODE_STRING pParentKeyName, __in PUNICODE_STRING pRelativeKeyName )
{
    UNICODE_STRING TestKeyName;
    RtlInitUnicodeString( &TestKeyName, L"\\REGISTRY\\MACHINE\\SOFTWARE" );
    if ( RtlCompareUnicodeString( pParentKeyName, &TestKeyName, TRUE ) )
    {
        return false;
    }

    RtlInitUnicodeString( &TestKeyName, L"MySecretTestKey" );
    return !RtlCompareUnicodeString( pRelativeKeyName, &TestKeyName, TRUE );
}

NTSTATUS _RfSplitParentAndRelativeNames( __in PCUNICODE_STRING pFullObjectName, __out_opt PUNICODE_STRING pParentObjectName, __out_opt PUNICODE_STRING pRelativeObjectName )
{
    //	Defensive programming. These names may come from somebody elses code, so be careful!
    if ( !pFullObjectName->Buffer || 0 == pFullObjectName->Length )
    {
        return STATUS_INVALID_PARAMETER;
    }

    //	Search backward through full object name for the path separator, taking care not to underflow!
    const wchar_t* pCh = &pFullObjectName->Buffer[ (pFullObjectName->Length / sizeof(wchar_t)) - 1 ];
    while ( pCh && pCh >= pFullObjectName->Buffer && *pCh != OBJ_NAME_PATH_SEPARATOR )
    {
        --pCh;
    }

    //	Again, be defensive. The string provided may not have had a backslash.
    if ( pCh <= pFullObjectName->Buffer )
    {
        return STATUS_INVALID_PARAMETER;
    }

    //	Everything before the character we stopped on is the parent, everything after is the relative name
    USHORT cbOffset = (USHORT) PtrDiff( pCh, pFullObjectName->Buffer );
    if ( pParentObjectName )
    {
        pParentObjectName->Length = pParentObjectName->MaximumLength = cbOffset;
        pParentObjectName->Buffer = pFullObjectName->Buffer;
    }

    if ( pRelativeObjectName )
    {
        cbOffset += sizeof( wchar_t );
        pRelativeObjectName->Length = pRelativeObjectName->MaximumLength = pFullObjectName->Length - cbOffset;
        pRelativeObjectName->Buffer = (PWCH) Add2Ptr( pFullObjectName->Buffer, cbOffset );
    }

    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry( __in PDRIVER_OBJECT pDriverObject, __in PUNICODE_STRING pRegistryPath )
{
    UNREFERENCED_PARAMETER( pRegistryPath );

    //	Set up our unload routine
    pDriverObject->DriverUnload = RfUnload;

    //	Set up our registry callback table
    g_RegistryCallbackTable[ RegNtPreCreateKeyEx ] = (PEX_CALLBACK_FUNCTION) RfPreCreateKeyEx;
    g_RegistryCallbackTable[ RegNtPreOpenKeyEx ] = (PEX_CALLBACK_FUNCTION) RfPreOpenKeyEx;
    g_RegistryCallbackTable[ RegNtPreRenameKey ] = (PEX_CALLBACK_FUNCTION) RfPreRenameKey;
    g_RegistryCallbackTable[ RegNtKeyHandleClose ] = (PEX_CALLBACK_FUNCTION) RfKeyHandleClose;

    //	Register our callback with the system
    UNICODE_STRING AltitudeString = RTL_CONSTANT_STRING( L"360000" );
    NTSTATUS status = CmRegisterCallbackEx( RfRegistryCallback, &AltitudeString, pDriverObject, NULL, &g_CmCookie, NULL );
    if ( !NT_SUCCESS( status ) )
    {
        //	Failed to register - probably shouldn't succeed the driver intialization since this is critical
    }

    KdPrint( ( "RegFlt: Loaded\n" ) );

    return status;
}

NTSTATUS RfKeyHandleClose( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_KEY_HANDLE_CLOSE_INFORMATION CallbackData )
{
    UNREFERENCED_PARAMETER( CallbackContext );
    UNREFERENCED_PARAMETER( Argument1 );
    UNREFERENCED_PARAMETER( CallbackData );
    return STATUS_SUCCESS;
}

NTSTATUS RfPreCreateKeyEx( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_CREATE_KEY_INFORMATION CallbackData )
{
    UNREFERENCED_PARAMETER( CallbackContext );
    UNREFERENCED_PARAMETER( Argument1 );
    return RfPreCreateOrOpenKey( CallbackData );
}

NTSTATUS RfPreCreateOrOpenKey( __in PREG_CREATE_KEY_INFORMATION CallbackData )
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNICODE_STRING pLocalCompleteName = NULL;

    //	Get the complete name of the key being opened
    if ( CallbackData->CompleteName->Length == 0 || *CallbackData->CompleteName->Buffer != OBJ_NAME_PATH_SEPARATOR )
    {
        PCUNICODE_STRING pRootObjectName;
        status = CmCallbackGetKeyObjectID( &g_CmCookie, CallbackData->RootObject, NULL, &pRootObjectName );
        if ( NT_SUCCESS( status ) )
        {
            //	Build the new name
            USHORT cbBuffer = pRootObjectName->Length;
            cbBuffer += sizeof( wchar_t );
            cbBuffer += CallbackData->CompleteName->Length;
            ULONG cbUString = sizeof(UNICODE_STRING) + cbBuffer;

            pLocalCompleteName = (PUNICODE_STRING) ExAllocatePoolWithTag( PagedPool, cbUString, 'tlFR' );
            if ( pLocalCompleteName )
            {
                pLocalCompleteName->Length = 0;
                pLocalCompleteName->MaximumLength = cbBuffer;
                pLocalCompleteName->Buffer = (PWCH) ( (PCCH) pLocalCompleteName + sizeof( UNICODE_STRING ) );

                RtlCopyUnicodeString( pLocalCompleteName, pRootObjectName );
                RtlAppendUnicodeToString( pLocalCompleteName, L"\\" );
                RtlAppendUnicodeStringToString( pLocalCompleteName, CallbackData->CompleteName );
            }
        }
        else
        {
            //	Could not get the complete name since we have a relative name and were
            //	unable to get the name of the root object
            goto LExit;
        }
    }

    PUNICODE_STRING pKeyNameBeingOpened = pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName;

    //	Prevent callers from opening our secret registry key
    if ( _RfIsKeyMySecretKey( pKeyNameBeingOpened ) )
    {
        KdPrint( ( "RegFlt: Create/Open for %wZ being denied!\n", pKeyNameBeingOpened ) );
        status = STATUS_ACCESS_DENIED;
        goto LExit;
    }

LExit:
    if ( pLocalCompleteName )
    {
        ExFreePool( pLocalCompleteName );
    }

    return status;
}

NTSTATUS RfPreOpenKeyEx( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_OPEN_KEY_INFORMATION CallbackData )
{
    UNREFERENCED_PARAMETER( CallbackContext );
    UNREFERENCED_PARAMETER( Argument1 );
    return RfPreCreateOrOpenKey( CallbackData );
}

NTSTATUS RfPreRenameKey( __in PVOID CallbackContext, __in PVOID Argument1, __in PREG_RENAME_KEY_INFORMATION CallbackData )
{
    UNREFERENCED_PARAMETER( CallbackContext );
    UNREFERENCED_PARAMETER( Argument1 );

    NTSTATUS status = STATUS_SUCCESS;

    //	Get the full name of the new key
    PCUNICODE_STRING pObjectName;
    status = CmCallbackGetKeyObjectID( &g_CmCookie, CallbackData->Object, NULL, &pObjectName );
    if ( !NT_SUCCESS( status ) )
    {
        goto LExit;
    }

    //	Find the last path separator character and get a "parent object" key name
    UNICODE_STRING ParentObjectName;
    status = _RfSplitParentAndRelativeNames( pObjectName, &ParentObjectName, NULL );
    if ( !NT_SUCCESS( status ) )
    {
        goto LExit;
    }

    //	Prevent callers from opening our secret registry key
    if ( _RfIsKeyMySecretKey( &ParentObjectName, CallbackData->NewName ) )
    {
        KdPrint( ( "RegFlt: Rename of key to %wZ being denied!\n", CallbackData->NewName ) );
        status = STATUS_ACCESS_DENIED;
        goto LExit;
    }

LExit:
    return status;
}

NTSTATUS RfRegistryCallback( __in PVOID CallbackContext, __in PVOID Argument1, __in PVOID Argument2 )
{
    REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS) (ULONG_PTR) Argument1;

    //	If we have no operation callback routine for this operation then just return to Cm
    if ( !g_RegistryCallbackTable[ Operation ] )
    {
        return STATUS_SUCCESS;
    }

    //	Call our operation callback routine
    return g_RegistryCallbackTable[ Operation ]( CallbackContext, Argument1, Argument2 );
}

void RfUnload( __in PDRIVER_OBJECT pDriverObject )
{
    UNREFERENCED_PARAMETER( pDriverObject );
    PAGED_CODE();

    NTSTATUS status = CmUnRegisterCallback( g_CmCookie );
    if ( !NT_SUCCESS( status ) )
    {
        //	Failed to unregister - try to handle gracefully
    }

    KdPrint( ( "RegFlt: Unloaded\n" ) );
}
