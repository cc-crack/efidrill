#

#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/SmmMemLib.h>
#include <Guid/EventGroup.h>

EFI_GUID DummyGuid =   {0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0xAA, 0xBB }};
EFI_GUID gMyfaultSMMGdui = {0xD300ECE6,0x9CA6,0x40E3,{0xAE,0xBF, 0x75,0x3E, 0xD6,0x7F,0x15,0x92}};
EFI_HANDLE        mSmmMyfaultHandle;
/*
typedef enum _FAULT_TYPE_T
{
    // Triggers an overflow from BS->CopyMem()
    POOL_OVERFLOW_COPY_MEM = 1,
    // Triggers an underflow from BS->CopyMem()
    POOL_UNDERFLOW_COPY_MEM = 2,
    // Triggers an overflow from BS->SetMem()
    POOL_OVERFLOW_SET_MEM = 3,
    // Triggers an underflow from BS->SetMem()
    POOL_UNDERFLOW_SET_MEM = 4,
    // Triggers an overflow from user code
    POOL_OVERFLOW_USER_CODE = 5,
    // Triggers an underflow from user code
    POOL_UNDERFLOW_USER_CODE = 6,
    // Triggers an out-of-bounds read ahead of the buffer
    POOL_OOB_READ_AHEAD = 7,
    // Triggers an out-of-bounds read behind the buffer
    POOL_OOB_READ_BEHIND = 8,
    // Frees the same pool block twice in a row
    POOL_DOUBLE_FREE = 9,
    // Frees a pointer which wasn't allocated by BS->AllocatePool()
    POOL_INVALID_FREE = 10,
    // Reads from the buffer after it was freed
    POOL_UAF_READ = 11,
    // Writes to the buffer after it was freed
    POOL_UAF_WRITE = 12,
    // Writes to the NULL page
    NULL_DEREFERENCE_DETERMINISTIC = 13,
    // Allocates a buffer with BS->AllocatePool(), then uses it without checking for NULL first
    NULL_DEREFERENCE_NON_DETERMINISTIC = 14,
    // Stack-based buffer overflow
    STACK_BUFFER_OVERFLOW = 15,
    // Leak uninitialized stack memory
    STACK_UNINITIALIZED_MEMORY_LEAK = 16
} FAULT_TYPE_T;

// A hand-rolled implementation for memset()
VOID MySetMem(IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)
{
    UINTN i;
    UINT8 * OutputBuffer = (UINT8 *)Buffer;
    for (i = 0; i < Size; i++) {
        OutputBuffer[i] = Value;
    }
}


EFI_STATUS UninitializedStackMemoryLeak(IN EFI_SYSTEM_TABLE  *SystemTable)
{
    UINT8 VariableData[32]; // Uninitialized
    UINTN VariableDataSize = sizeof(VariableData);
    UINT32 Attributes = 0;
    EFI_STATUS status = EFI_SUCCESS;
    
    // Read the variable to stack memory.
    // We'll re-use 'FaultType' for this purpose.
    status = SystemTable->RuntimeServices->GetVariable(L"FaultType",
                                                       &DummyGuid,
                                                       &Attributes,
                                                       &VariableDataSize,
                                                       VariableData);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    // Write it back to NVRAM.
    // The bug is that we're using the original maximum size and not the actual size.
    status = SystemTable->RuntimeServices->SetVariable(L"FaultType",
                                                       &DummyGuid,
                                                       Attributes,
                                                       sizeof(VariableData),
                                                       VariableData);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return status;
}
*/
char* benboba(){
    static char s[0x123] = {0};
    for(int i = 0; i<0x123;i++){
        s[i]=1;
    }
    return s;
}

char* baboben(){
    static char s[0x123] = {0};
    for(int i = 0x122; i>=0;i--){
        s[i]=1;
    }
    return s;
}

EFI_STATUS TocTou(VOID* CommBuffer,UINTN * CommBufferSize){

    VOID *DestinationBuffer = NULL;
    UINTN size = *CommBufferSize;
    UINTN foo = *(UINTN*)CommBuffer;
    //Check
     if ( !SmmIsBufferOutsideSmmValid((EFI_PHYSICAL_ADDRESS)CommBuffer, *CommBufferSize)
     || (gSmst->SmmAllocatePool(EfiRuntimeServicesData, size, &DestinationBuffer) & 0x8000000000000000LL) != 0 )
    {
        return 0;
    }
    //Safe using
    if(foo == 0){
        benboba();
    }
    if(*(UINTN*)CommBuffer == 1){
        baboben();
    }
    if(DestinationBuffer){
        gSmst->SmmFreePool(DestinationBuffer);
    }
    return 0;
}
EFI_STATUS
EFIAPI
SmiHandlerMyFaultHandler (
  IN     EFI_HANDLE                                DispatchHandle,
  IN     CONST VOID                                *RegisterContext,
  IN OUT VOID                                      *CommBuffer,
  IN OUT UINTN                                     *CommBufferSize
  )
  {
    EFI_STATUS s = 0;
    DispatchHandle = DispatchHandle;
    RegisterContext = RegisterContext;
    s=  TocTou(CommBuffer,CommBufferSize);
    return s==0?0:1;
  }



EFI_STATUS EFIAPI Install_SMI_Handler(  
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable)
    {
    EFI_STATUS  Status;
    EFI_HANDLE  DispatchHandle;

  Status = gSmst->SmiHandlerRegister (
                    SmiHandlerMyFaultHandler,
                    &gMyfaultSMMGdui,
                    &DispatchHandle
                    );

    baboben();
    return Status;
}
/*
EFI_STATUS
EFIAPI
_ModuleEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    UINT32 FaultType = 0;
    UINTN DataSize = sizeof(FaultType);
    UINT32 Attributes = 0;
    UINT8 * Buffer = NULL;
    UINTN BufferSize = 8;
    VOID * MaybeNull = NULL;
    EFI_STATUS status = EFI_SUCCESS;

    status = Install_SMI_Handler(ImageHandle,SystemTable);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    // Allocate the vulnerable pool buffer.
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData,
                                                     BufferSize,
                                                     (VOID **)&Buffer);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
  
    // Get the contents of the 'FaultType' variable.
    status = SystemTable->RuntimeServices->GetVariable(L"FaultType",
                                                       &DummyGuid,
                                                       &Attributes,
                                                       &DataSize,
                                                       &FaultType);
    if (EFI_ERROR(status)) {
        goto Exit;
    }

    // Carry-out the selected fault.
    switch (FaultType)
    {
    case POOL_OVERFLOW_COPY_MEM:
        SystemTable->BootServices->CopyMem(Buffer, &DummyGuid, BufferSize + 1);
        break;
        
    case POOL_UNDERFLOW_COPY_MEM:
        SystemTable->BootServices->CopyMem(Buffer - 1, &DummyGuid, BufferSize);
        break;
        
    case POOL_OVERFLOW_SET_MEM:
        SystemTable->BootServices->SetMem(Buffer, BufferSize + 1, 0xAA);
        break;

    case POOL_UNDERFLOW_SET_MEM:
        SystemTable->BootServices->SetMem(Buffer - 1, BufferSize, 0xAA);
        break;

    case POOL_OVERFLOW_USER_CODE:
        MySetMem(Buffer, BufferSize + 1, 0xAA);
        break;

    case POOL_UNDERFLOW_USER_CODE:
        MySetMem(Buffer - 1, BufferSize, 0xAA);
        break;

    case POOL_OOB_READ_AHEAD:
        status = *(Buffer + BufferSize);
        break;

    case POOL_OOB_READ_BEHIND:
        status = *(Buffer - 1);
        break;

    case POOL_DOUBLE_FREE:
        SystemTable->BootServices->FreePool(Buffer);
        SystemTable->BootServices->FreePool(Buffer);
        break;

    case POOL_INVALID_FREE:
        SystemTable->BootServices->FreePool(Buffer + 1);
        break;
    
    case POOL_UAF_READ:
        SystemTable->BootServices->FreePool(Buffer);
        status = Buffer[2];
        break;
        
    case POOL_UAF_WRITE:
        SystemTable->BootServices->FreePool(Buffer);
        Buffer[2] = 0xAA;
        break;
        
    case NULL_DEREFERENCE_DETERMINISTIC:
        *(UINT8 *)NULL = 0xAA;
        break;

    case NULL_DEREFERENCE_NON_DETERMINISTIC:
        SystemTable->BootServices->AllocatePool(EfiLoaderData,
                                                BufferSize,
                                                &MaybeNull);
        // We're not checking for the return value from AllocatePool()
        *(UINT8 *)MaybeNull = 0xAA;
        SystemTable->BootServices->FreePool(MaybeNull);
        break;
        
    case STACK_BUFFER_OVERFLOW:
        SystemTable->BootServices->SetMem(&Buffer, 0x100, 0xAA);
        break;
        
    case STACK_UNINITIALIZED_MEMORY_LEAK:
        status = UninitializedStackMemoryLeak(SystemTable);
        break;

    default:
        break;
  }

Exit:
  return status;
}
*/



