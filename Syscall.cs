using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Ar_syscall.Native;

namespace Ar_syscall
{
    class Syscall
    {    // 从WinDbg获得
        static byte[] bNtAllocateVirtualMemory =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0x18, 0x00, 0x00, 0x00,   // mov eax,18h
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            uint AllocationType,
            uint Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory; //定义本地API NTCreateFile的汇编指令

            //指定不安全块
            unsafe
            {
                //NTCreateFile 的指针
                fixed (byte* ptr = syscall)   
                {   
                    //把指针转化为IntPtr类型
                    IntPtr memoryAddress = (IntPtr)ptr;

                    //把NTCreateFile汇编指令数组的内存区域权限改为 执行
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    //获取 NtWaitForSingleObject 的委托
                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)assembledFunction(
                        ProcessHandle,
                        ref BaseAddress,
                        ZeroBits,
                        ref RegionSize,
                        AllocationType,
                        Protect);
                }
            }
        }
        // 从WinDbg获得
        static byte[] bNtCreateThreadEx =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0xc1, 0x00, 0x00, 0x00,   // moveax,0C1h
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        //https://www.pinvoke.net/default.aspx/ntdll/NtCreateThreadEx.html

         public static NTSTATUS NtCreateThreadEx(
            out IntPtr hThread,
            ACCESS_MASK DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
            )


        {
            byte[] syscall = bNtCreateThreadEx; //定义本地API NTCreateFile的汇编指令

            //指定不安全块
            unsafe
            {
                //NTCreateFile 的指针
                fixed (byte* ptr = syscall)
                {
                    //把指针转化为IntPtr类型
                    IntPtr memoryAddress = (IntPtr)ptr;

                    //把NTCreateFile汇编指令数组的内存区域权限改为 执行
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    //获取 NtWaitForSingleObject 的委托
                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

                    return (NTSTATUS)assembledFunction(
                        out hThread,
                        DesiredAccess,
                        ObjectAttributes,
                        ProcessHandle,
                        lpStartAddress,
                        lpParameter,
                        CreateSuspended,
                        StackZeroBits,
                        SizeOfStackCommit,
                        SizeOfStackReserve,
                        lpBytesBuffer
                        );
                }
            }
         }
        static byte[] bNtWaitForSingleObject =
{
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0x04, 0x00, 0x00, 0x00,   // mov eax,4
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };
        public static NTSTATUS NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
        {
            byte[] syscall = bNtWaitForSingleObject;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }
                    Delegates.NtWaitForSingleObject assembledFunction = (Delegates.NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWaitForSingleObject));

                    return (NTSTATUS)assembledFunction(Object, Alertable, Timeout);
                }
            }
        }

        public struct Delegates
        {
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref UIntPtr RegionSize,
                ulong AllocationType,
                ulong Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtCreateThreadEx(
                out IntPtr hThread,
                ACCESS_MASK DesiredAccess,
                IntPtr ObjectAttributes,
                IntPtr ProcessHandle,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                bool CreateSuspended,
                uint StackZeroBits,
                uint SizeOfStackCommit,
                uint SizeOfStackReserve,
                IntPtr lpBytesBuffer
                );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);
        };
        
    }
}
