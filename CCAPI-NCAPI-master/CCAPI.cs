﻿// ************************************************* //
//    --- Copyright (c) 2014 iMCS Productions ---    //
// ************************************************* //
//              PS3Lib v4 By FM|T iMCSx              //
//                                                   //
// Features v4.4 :                                   //
// - Support CCAPI v2.8 C# by hcw                    //
// - Set Boot Console ID                             //
// - Popup better form with icon                     //
// - CCAPI Consoles List Popup French/English        //
// - CCAPI Get Console Info                          //
// - CCAPI Get Console List                          //
// - CCAPI Get Number Of Consoles                    //
// - Get Console Name TMAPI/CCAPI                    //
//                                                   //
// Credits : FM|T Enstone , Buc-ShoTz                //
//                                                   //
// Follow me :                                       //
//                                                   //
// FrenchModdingTeam.com                             //
// Youtube.com/iMCSx                                 //
// Twitter.com/iMCSx                                 //
// Facebook.com/iMCSx                                //
//                                                   //
// ************************************************* //

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Reflection;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using System.Security.Cryptography;

namespace CCAPI_NCAPI
{
    public class CCAPI
    {
        [DllImport("user32.dll")]
        internal static extern IntPtr SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIConnectConsole_t(string ip);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIDisconnectConsole_t();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetConnectionStatus_t(ref int status);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPISetBootConsoleIds_t(int idType, int on, byte[] id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPISetConsoleIds_t(int idType, byte[] id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPISetMemory_t(uint pid, ulong addr, uint size, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetMemory_t(uint pid, ulong addr, uint size, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetProcessList_t(ref uint npid, IntPtr pids);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetProcessName_t(uint pid, IntPtr name);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetTemperature_t(ref int cell, ref int rsx);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIShutdown_t(int mode);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIRingBuzzer_t(int type);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPISetConsoleLed_t(int color, int status);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetFirmwareInfo_t(ref int firmware, ref int ccapiVersion, ref int consoleType);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIVshNotify_t(int mode, string msg);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetNumberOfConsoles_t();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetConsoleInfo_t(int index, IntPtr name, IntPtr ip);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CCAPIGetDllVersion_t();

        

        private CCAPI.CCAPIConnectConsole_t connectConsole;

        private CCAPI.CCAPIDisconnectConsole_t disconnectConsole;

        private CCAPI.CCAPIGetConnectionStatus_t getConnectionStatus;

        private CCAPI.CCAPIGetConsoleInfo_t getConsoleInfo;

        private CCAPI.CCAPIGetDllVersion_t getDllVersion;

        private CCAPI.CCAPIGetFirmwareInfo_t getFirmwareInfo;

        private CCAPI.CCAPIGetNumberOfConsoles_t getNumberOfConsoles;

        private CCAPI.CCAPIGetProcessList_t getProcessList;

        private CCAPI.CCAPIGetMemory_t getProcessMemory;

        private CCAPI.CCAPIGetProcessName_t getProcessName;

        private CCAPI.CCAPIGetTemperature_t getTemperature;

        private CCAPI.CCAPIVshNotify_t notify;

        private CCAPI.CCAPIRingBuzzer_t ringBuzzer;

        private CCAPI.CCAPISetBootConsoleIds_t setBootConsoleIds;

        private CCAPI.CCAPISetConsoleIds_t setConsoleIds;

        private CCAPI.CCAPISetConsoleLed_t setConsoleLed;

        private CCAPI.CCAPISetMemory_t setProcessMemory;

        private CCAPI.CCAPIShutdown_t shutdown;


        private IntPtr libModule = IntPtr.Zero;
       // private readonly string CCAPIHASH = "C2FE9E1C387CF29AAC781482C28ECF86";
        private readonly string CCAPIHASH = "44F8C8BC576CA8BA3F99EF46C2E4B9C3";
        private string programPath = "";

        public CCAPI()
        {
            RegistryKey Key = Registry
                .CurrentUser
                .OpenSubKey(@"Software\FrenchModdingTeam\CCAPI\InstallFolder");

            if (Key != null)
            {
                string Path = Key.GetValue("path") as String;
                programPath = Path;
                if (!string.IsNullOrEmpty(Path))
                {
                    string DllUrl = Path + @"\CCAPI.dll";
                    if (File.Exists(DllUrl))
                    {
                        if (BitConverter.ToString(MD5.Create()
                          .ComputeHash(File.ReadAllBytes(DllUrl)))
                            .Replace("-", "").Equals(CCAPIHASH))
                            
                        {
                            if (libModule == IntPtr.Zero)
                                libModule = LoadLibrary(DllUrl);

                            if (libModule != IntPtr.Zero)
                            {
                                this.connectConsole = (CCAPI.CCAPIConnectConsole_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIConnectConsole"), typeof(CCAPI.CCAPIConnectConsole_t));
                                this.disconnectConsole = (CCAPI.CCAPIDisconnectConsole_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIDisconnectConsole"), typeof(CCAPI.CCAPIDisconnectConsole_t));
                                this.getConnectionStatus = (CCAPI.CCAPIGetConnectionStatus_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetConnectionStatus"), typeof(CCAPI.CCAPIGetConnectionStatus_t));
                                this.getConsoleInfo = (CCAPI.CCAPIGetConsoleInfo_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetConsoleInfo"), typeof(CCAPI.CCAPIGetConsoleInfo_t));
                                this.getDllVersion = (CCAPI.CCAPIGetDllVersion_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetDllVersion"), typeof(CCAPI.CCAPIGetDllVersion_t));
                                this.getFirmwareInfo = (CCAPI.CCAPIGetFirmwareInfo_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetFirmwareInfo"), typeof(CCAPI.CCAPIGetFirmwareInfo_t));
                                this.getNumberOfConsoles = (CCAPI.CCAPIGetNumberOfConsoles_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetNumberOfConsoles"), typeof(CCAPI.CCAPIGetNumberOfConsoles_t));
                                this.getProcessList = (CCAPI.CCAPIGetProcessList_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetProcessList"), typeof(CCAPI.CCAPIGetProcessList_t));
                                this.getProcessMemory = (CCAPI.CCAPIGetMemory_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetMemory"), typeof(CCAPI.CCAPIGetMemory_t));
                                this.getProcessName = (CCAPI.CCAPIGetProcessName_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetProcessName"), typeof(CCAPI.CCAPIGetProcessName_t));
                                this.getTemperature = (CCAPI.CCAPIGetTemperature_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIGetTemperature"), typeof(CCAPI.CCAPIGetTemperature_t));
                                this.notify = (CCAPI.CCAPIVshNotify_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIVshNotify"), typeof(CCAPI.CCAPIVshNotify_t));
                                this.ringBuzzer = (CCAPI.CCAPIRingBuzzer_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIRingBuzzer"), typeof(CCAPI.CCAPIRingBuzzer_t));
                                this.setBootConsoleIds = (CCAPI.CCAPISetBootConsoleIds_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPISetBootConsoleIds"), typeof(CCAPI.CCAPISetBootConsoleIds_t));
                                this.setConsoleIds = (CCAPI.CCAPISetConsoleIds_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPISetConsoleIds"), typeof(CCAPI.CCAPISetConsoleIds_t));
                                this.setConsoleLed = (CCAPI.CCAPISetConsoleLed_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPISetConsoleLed"), typeof(CCAPI.CCAPISetConsoleLed_t));
                                this.setProcessMemory = (CCAPI.CCAPISetMemory_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPISetMemory"), typeof(CCAPI.CCAPISetMemory_t));
                                this.shutdown = (CCAPI.CCAPIShutdown_t)Marshal.GetDelegateForFunctionPointer(CCAPI.GetProcAddress(this.libModule, "CCAPIShutdown"), typeof(CCAPI.CCAPIShutdown_t));
                            }
                            else
                            {
                                MessageBox.Show("Impossible to load CCAPI.dll version 2.80.", "CCAPI.dll cannot be load", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                        }
                        else
                        {
                            MessageBox.Show("You're not using the right CCAPI.dll please install the version 2.80.", "CCAPI.dll version incorrect", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    else
                    {
                        MessageBox.Show("You need to install CCAPI to use this library.", "CCAPI.dll not found", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    MessageBox.Show("Invalid CCAPI folder, please re-install it.", "CCAPI not installed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                MessageBox.Show("You need to install CCAPI to use this library.", "CCAPI not installed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public enum IdType
        {
            IDPS,
            PSID
        }

        public enum NotifyIcon
        {
            INFO,
            CAUTION,
            FRIEND,
            SLIDER,
            WRONGWAY,
            DIALOG,
            DIALOGSHADOW,
            TEXT,
            POINTER,
            GRAB,
            HAND,
            PEN,
            FINGER,
            ARROW,
            ARROWRIGHT,
            PROGRESS,
            TROPHY1,
            TROPHY2,
            TROPHY3,
            TROPHY4
        }

        public enum ConsoleType
        {
            CEX = 1,
            DEX = 2,
            TOOL = 3
        }

        public enum ProcessType
        {
            VSH,
            SYS_AGENT,
            CURRENTGAME
        }

        public enum RebootFlags
        {
            ShutDown = 1,
            SoftReboot = 2,
            HardReboot = 3
        }

        public enum BuzzerMode
        {
            Continuous,
            Single,
            Double
        }

        public enum LedColor
        {
            Green = 1,
            Red = 2
        }

        public enum LedMode
        {
            Off,
            On,
            Blink
        }

        private TargetInfo pInfo = new TargetInfo();

        private IntPtr ReadDataFromUnBufPtr<T>(IntPtr unBuf, ref T storage)
        {
            storage = (T)Marshal.PtrToStructure(unBuf, typeof(T));
            return new IntPtr(unBuf.ToInt64() + Marshal.SizeOf((T)storage));
        }

        private class System
        {
            public static int
                connectionID = -1;
            public static uint
                processID = 0;
            public static uint[]
                processIDs;
        }

        /// <summary>Get informations from your target.</summary>
        public class TargetInfo
        {
            public int
                Firmware = 0,
                CCAPI = 0,
                ConsoleType = 0,
                TempCell = 0,
                TempRSX = 0;
            public ulong
                SysTable = 0;
        }

        /// <summary>Get Info for targets.</summary>
        public class ConsoleInfo
        {
            public string
                Name,
                Ip;
        }

        private void CompleteInfo(ref TargetInfo Info, int fw, int ccapi, ulong sysTable, int consoleType, int tempCELL, int tempRSX)
        {
            Info.Firmware = fw;
            Info.CCAPI = ccapi;
            Info.SysTable = sysTable;
            Info.ConsoleType = consoleType;
            Info.TempCell = tempCELL;
            Info.TempRSX = tempRSX;
        }

        public bool OpenManager()
        {
            if (programPath == null || programPath == "")
                return false;

            string[] files = Directory.GetFiles(programPath, "*.exe", SearchOption.AllDirectories);
            for (int x = 0; x < files.Length; x++)
            {
                if (files[x].IndexOf("Manager") > 0)
                {
                    //Check if process already open
                    Process[] res = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(files[x]));
                    if (res.Length > 0) //Open existing process
                    {
                        IntPtr hWnd = res[0].MainWindowHandle;
                        if (hWnd != IntPtr.Zero)
                        {
                            SetForegroundWindow(hWnd);
                            ShowWindow(hWnd, 1);
                        }
                    }
                    else //Open new instance
                    {
                        Process.Start(files[x]);
                    }

                    return true;
                }
            }

            return false;
        }

        /// <summary>Return true if a ccapi function return a good integer.</summary>
        public bool SUCCESS(int Void)
        {
            if (Void == 0)
                return true;
            else return false;
        }

        /// <summary>Connect your console by console list.</summary>
        public PS3API ps3api = new PS3API();
        public bool ConnectTarget()
        {
            return new PS3API.ConsoleList(ps3api).Show();
        }

        /// <summary>Connect your console by ip address.</summary>
        public int ConnectTarget(string targetIP)
        {
            int code = connectConsole(targetIP);
            return code;
        }

        /// <summary>Get the status of the console.</summary>
        public int GetConnectionStatus()
        {
            int status = 0;
            getConnectionStatus(ref status);
            return status;
        }

        /// <summary>Disconnect your console.</summary>
        public int DisconnectTarget()
        {
            return disconnectConsole();
        }

        /// <summary>Attach the default process (Current Game).</summary>
        public int AttachProcess()
        {
            int result = -1; System.processID = 0;
            result = GetProcessList(out System.processIDs);
            if (SUCCESS(result) && System.processIDs.Length > 0)
            {
                for (int i = 0; i < System.processIDs.Length; i++)
                {
                    string name = String.Empty;
                    result = GetProcessName(System.processIDs[i], out name);
                    if (!SUCCESS(result))
                        break;
                    if (!name.Contains("flash"))
                    {
                        System.processID = System.processIDs[i];
                        break;
                    }
                    else result = -1;
                }
                if (System.processID == 0)
                    System.processID = System.processIDs[System.processIDs.Length - 1];
            }
            else result = -1;
            return result;
        }

        /// <summary>Attach your desired process.</summary>
        public int AttachProcess(ProcessType procType)
        {
            int result = -1; System.processID = 0;
            result = GetProcessList(out System.processIDs);
            if (result >= 0 && System.processIDs.Length > 0)
            {
                for (int i = 0; i < System.processIDs.Length; i++)
                {
                    string name = String.Empty;
                    result = GetProcessName(System.processIDs[i], out name);
                    if (result < 0)
                        break;
                    if (procType == ProcessType.VSH && name.Contains("vsh"))
                    {
                        System.processID = System.processIDs[i]; break;
                    }
                    else if (procType == ProcessType.SYS_AGENT && name.Contains("agent"))
                    {
                        System.processID = System.processIDs[i]; break;
                    }
                    else if (procType == ProcessType.CURRENTGAME && !name.Contains("flash"))
                    {
                        System.processID = System.processIDs[i]; break;
                    }
                }
                if (System.processID == 0)
                    System.processID = System.processIDs[System.processIDs.Length - 1];
            }
            else result = -1;
            return result;
        }

        /// <summary>Attach your desired process.</summary>
        public int AttachProcess(uint process)
        {
            int result = -1;
            uint[] procs = new uint[64];
            result = GetProcessList(out procs);
            if (SUCCESS(result))
            {
                for (int i = 0; i < procs.Length; i++)
                {
                    if (procs[i] == process)
                    {
                        result = 0;
                        System.processID = process;
                        break;
                    }
                    else result = -1;
                }
            }
            procs = null;
            return result;
        }

        /// <summary>Get a list of all processes available.</summary>
        public int GetProcessList(out uint[] processIds)
        {
            uint numOfProcs = 64; int result = -1;
            IntPtr ptr = Marshal.AllocHGlobal((int)(4 * 0x40));
            result = getProcessList(ref numOfProcs, ptr);
            processIds = new uint[numOfProcs];
            if (SUCCESS(result))
            {
                IntPtr unBuf = ptr;
                for (uint i = 0; i < numOfProcs; i++)
                    unBuf = ReadDataFromUnBufPtr<uint>(unBuf, ref processIds[i]);
            }
            Marshal.FreeHGlobal(ptr);
            return result;
        }

        /// <summary>Get the process name of your choice.</summary>
        public int GetProcessName(uint processId, out string name)
        {
            IntPtr ptr = Marshal.AllocHGlobal((int)(0x211)); int result = -1;
            result = getProcessName(processId, ptr);
            name = String.Empty;
            if (SUCCESS(result))
                name = Marshal.PtrToStringAnsi(ptr);
            Marshal.FreeHGlobal(ptr);
            return result;
        }

        /// <summary>Return the current process attached. Use this function only if you called AttachProcess before.</summary>
        public uint GetAttachedProcess()
        {
            return System.processID;
        }

        /// <summary>Set memory to offset (uint).</summary>
        public int SetMemory(uint offset, byte[] buffer)
        {
            return setProcessMemory(System.processID, (ulong)offset, (uint)buffer.Length, buffer);
        }

        /// <summary>Set memory to offset (ulong).</summary>
        public int SetMemory(ulong offset, byte[] buffer)
        {
            return setProcessMemory(System.processID, offset, (uint)buffer.Length, buffer);
        }

        /// <summary>Set memory to offset (string hex).</summary>
        public int SetMemory(ulong offset, string hexadecimal)
        {
            byte[] Entry = StringToByteArray(hexadecimal);
            Array.Reverse(Entry);
            return setProcessMemory(System.processID, offset, (uint)Entry.Length, Entry);
        }

        /// <summary>Get memory from offset (uint).</summary>
        public int GetMemory(uint offset, byte[] buffer)
        {
            return getProcessMemory(System.processID, (ulong)offset, (uint)buffer.Length, buffer);
        }

        /// <summary>Get memory from offset (ulong).</summary>
        public int GetMemory(ulong offset, byte[] buffer)
        {
            return getProcessMemory(System.processID, offset, (uint)buffer.Length, buffer);
        }

        /// <summary>Like Get memory but this function return directly the buffer from the offset (uint).</summary>
        public byte[] GetBytes(uint offset, uint length)
        {
            byte[] buffer = new byte[length];
            GetMemory(offset, buffer);
            return buffer;
        }

        /// <summary>Like Get memory but this function return directly the buffer from the offset (ulong).</summary>
        public byte[] GetBytes(ulong offset, uint length)
        {
            byte[] buffer = new byte[length];
            GetMemory(offset, buffer);
            return buffer;
        }

        /// <summary>Display the notify message on your PS3.</summary>
        public int Notify(NotifyIcon icon, string message)
        {
            return notify((int)icon, message);
        }

        /// <summary>Display the notify message on your PS3.</summary>
        public int Notify(int icon, string message)
        {
            return notify(icon, message);
        }

        /// <summary>You can shutdown the console or just reboot her according the flag selected.</summary>
        public int ShutDown(RebootFlags flag)
        {
            return shutdown((int)flag);
        }

        /// <summary>Your console will emit a song.</summary>
        public int RingBuzzer(BuzzerMode flag)
        {
            return ringBuzzer((int)flag);
        }

        /// <summary>Change leds for your console.</summary>
        public int SetConsoleLed(LedColor color, LedMode mode)
        {
            return setConsoleLed((int)color, (int)mode);
        }

        private int GetTargetInfo()
        {
            int result = -1; int[] sysTemp = new int[2];
            int fw = 0, ccapi = 0, consoleType = 0; ulong sysTable = 0;
            result = getFirmwareInfo(ref fw, ref ccapi, ref consoleType);
            if (result >= 0)
            {
                result = getTemperature(ref sysTemp[0], ref sysTemp[1]);
                if (result >= 0)
                    CompleteInfo(ref pInfo, fw, ccapi, sysTable, consoleType, sysTemp[0], sysTemp[1]);
            }

            return result;
        }

        /// <summary>Get informations of your console and store them into TargetInfo class.</summary>
        public int GetTargetInfo(out TargetInfo Info)
        {
            Info = new TargetInfo();
            int result = -1; int[] sysTemp = new int[2];
            int fw = 0, ccapi = 0, consoleType = 0; ulong sysTable = 0;
            result = getFirmwareInfo(ref fw, ref ccapi, ref consoleType);
            if (result >= 0)
            {
                result = getTemperature(ref sysTemp[0], ref sysTemp[1]);
                if (result >= 0)
                {
                    CompleteInfo(ref Info, fw, ccapi, sysTable, consoleType, sysTemp[0], sysTemp[1]);
                    CompleteInfo(ref pInfo, fw, ccapi, sysTable, consoleType, sysTemp[0], sysTemp[1]);
                }
            }
            return result;
        }

        /// <summary>Return the current firmware of your console in string format.</summary>
        public string GetFirmwareVersion()
        {
            if (pInfo.Firmware == 0)
                GetTargetInfo();

            string ver = pInfo.Firmware.ToString("X8");
            string char1 = ver.Substring(1, 1) + ".";
            string char2 = ver.Substring(3, 1);
            string char3 = ver.Substring(4, 1);
            return char1 + char2 + char3;
        }

        /// <summary>Return the current temperature of your system in string.</summary>
        public string GetTemperatureCELL()
        {
            if (pInfo.TempCell == 0)
                GetTargetInfo(out pInfo);

            return pInfo.TempCell.ToString() + " C";
        }

        /// <summary>Return the current temperature of your system in string.</summary>
        public string GetTemperatureRSX()
        {
            if (pInfo.TempRSX == 0)
                GetTargetInfo(out pInfo);
            return pInfo.TempRSX.ToString() + " C";
        }

        /// <summary>Return the type of your firmware in string format.</summary>
        public string GetFirmwareType()
        {
            if (pInfo.ConsoleType.ToString() == "")
                GetTargetInfo(out pInfo);
            string type = String.Empty;
            if (pInfo.ConsoleType == (int)ConsoleType.CEX)
                type = "CEX";
            else if (pInfo.ConsoleType == (int)ConsoleType.DEX)
                type = "DEX";
            else if (pInfo.ConsoleType == (int)ConsoleType.TOOL)
                type = "TOOL";
            return type;
        }

        /// <summary>Clear informations into the DLL (PS3Lib).</summary>
        public void ClearTargetInfo()
        {
            pInfo = new TargetInfo();
        }

        /// <summary>Set a new ConsoleID in real time. (string)</summary>
        public int SetConsoleID(string consoleID)
        {
            if (string.IsNullOrEmpty(consoleID))
            {
                MessageBox.Show("Cannot send an empty value", "Empty or null console id", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return -1;
            }
            string newCID = String.Empty;
            if (consoleID.Length >= 32)
                newCID = consoleID.Substring(0, 32);
            return SetConsoleID(StringToByteArray(newCID));
        }

        /// <summary>Set a new ConsoleID in real time. (bytes)</summary>
        public int SetConsoleID(byte[] consoleID)
        {
            if (consoleID.Length <= 0)
            {
                MessageBox.Show("Cannot send an empty value", "Empty or null console id", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return -1;
            }
            return setConsoleIds((int)IdType.IDPS, consoleID);
        }

        /// <summary>Set a new PSID in real time. (string)</summary>
        public int SetPSID(string PSID)
        {
            if (string.IsNullOrEmpty(PSID))
            {
                MessageBox.Show("Cannot send an empty value", "Empty or null psid", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return -1;
            }
            string PS_ID = String.Empty;
            if (PSID.Length >= 32)
                PS_ID = PSID.Substring(0, 32);
            return SetPSID(StringToByteArray(PS_ID));
        }

        /// <summary>Set a new PSID in real time. (bytes)</summary>
        public int SetPSID(byte[] consoleID)
        {
            if (consoleID.Length <= 0)
            {
                MessageBox.Show("Cannot send an empty value", "Empty or null psid", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return -1;
            }
            return setConsoleIds((int)IdType.PSID, consoleID);
        }

        /// <summary>Set a console ID when the console is running. (string)</summary>
        public int SetBootConsoleID(string consoleID, IdType Type = IdType.IDPS)
        {
            string newCID = String.Empty;
            if (consoleID.Length >= 32)
                newCID = consoleID.Substring(0, 32);
            return SetBootConsoleID(StringToByteArray(consoleID), Type);
        }

        /// <summary>Set a console ID when the console is running. (bytes)</summary>
        public int SetBootConsoleID(byte[] consoleID, IdType Type = IdType.IDPS)
        {
            return setBootConsoleIds((int)Type, 1, consoleID);
        }

        /// <summary>Reset a console ID when the console is running.</summary>
        public int ResetBootConsoleID(IdType Type = IdType.IDPS)
        {
            return setBootConsoleIds((int)Type, 0, null);
        }

        /// <summary>Return CCAPI Version.</summary>
        public int GetDllVersion()
        {
            return getDllVersion();
        }

        /// <summary>Return a list of informations for each console available.</summary>
        public List<ConsoleInfo> GetConsoleList()
        {
            List<ConsoleInfo> data = new List<ConsoleInfo>();
            int targetCount = getNumberOfConsoles();
            IntPtr name = Marshal.AllocHGlobal((int)(256)),
                       ip = Marshal.AllocHGlobal((int)(256));
            for (int i = 0; i < targetCount; i++)
            {
                ConsoleInfo Info = new ConsoleInfo();
                getConsoleInfo(i, name, ip);
                Info.Name = Marshal.PtrToStringAnsi(name);
                Info.Ip = Marshal.PtrToStringAnsi(ip);
                data.Add(Info);
            }
            Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(ip);
            return data;
        }

        internal static byte[] StringToByteArray(string hex)
        {
            try
            {
                string replace = hex.Replace("0x", "");
                string Stringz = replace.Insert(replace.Length - 1, "0");

                int Odd = replace.Length;
                bool Nombre;
                if (Odd % 2 == 0)
                    Nombre = true;
                else
                    Nombre = false;
                if (Nombre == true)
                {
                    return Enumerable.Range(0, replace.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(replace.Substring(x, 2), 16))
                    .ToArray();
                }
                else
                {
                    return Enumerable.Range(0, replace.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(Stringz.Substring(x, 2), 16))
                    .ToArray();
                }
            }
            catch
            {
                MessageBox.Show("Incorrect value (empty)", "StringToByteArray Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return new byte[1];
            }
        }
    }
}
