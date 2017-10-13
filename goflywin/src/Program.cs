using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace goflywin
{
    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            if (!SingletonInstance.Start()) return;
            
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new formMain());

            SingletonInstance.Stop();
        }
    }

    static class SingletonInstance
    {
        public static string guid = "64026F49-4E6B-4071-9647-BD5517D16358";
        public static Mutex mutex;

        public static bool Start()
        {
            if (System.Diagnostics.Debugger.IsAttached)
            {
                guid = Guid.NewGuid().ToString();
            }

            bool onlyInstance = false;
            mutex = new Mutex(true, "Local\\" + guid, out onlyInstance);
            return onlyInstance;
        }

        public static void Stop()
        {
            mutex.ReleaseMutex();
        }
    }
}
