using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace goflywin
{
    static class CrossThread
    {
        public static void PerformSafely(this Control target, Action action)
        {
            if (target.InvokeRequired)
            {
                target.Invoke(action);
            }
            else
            {
                action();
            }
        }
    }

    static class Util
    {
        public static class ResourceManager
        {
            private static string _i18n = "zh-CN";

            public static void Use(string i18n)
            {
                _i18n = i18n;
            }

            public static bool GetString(string name, out string value)
            {
                string ret;
                switch (_i18n)
                {
                    case "zh-CN":
                        ret = Form_zh_CN.ResourceManager.GetString(name);
                        break;
                    default:
                        ret = Form_en_US.ResourceManager.GetString(name);
                        break;
                }

                value = ret;
                return ret != null;
            }

            public static string GetString(string name)
            {
                string ret;
                GetString(name, out ret);
                return ret;
            }
        }

        public static string BufferToString(byte[] buf)
        {
            return Encoding.ASCII.GetString(buf).Replace("\0", string.Empty);
        }

        public static string Escape(string text)
        {
            return text.Replace("|", "\\|");
        }

        public static string Unecape(string text)
        {
            return text.Replace("\\|", "|");
        }
    }

    static class Config
    {
        private static string INI = System.IO.Path.GetDirectoryName(Application.ExecutablePath) + "\\goflywin.ini";

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern long WritePrivateProfileString(string Section, string Key, string Value, string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetPrivateProfileString(string Section, string Key, string Default, StringBuilder RetVal, int Size, string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] // note ascii sections only in our .ini
        private static extern int GetPrivateProfileSectionNames(byte[] lpReturnedString, int nSize, string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern long GetLastError();

        public static List<string> GetSections()
        {
            byte[] lpReturnedString = new byte[1 << 16];
            int len = GetPrivateProfileSectionNames(lpReturnedString, 1 << 16, INI);

            List<string> sections = new List<string>();
            List<byte> buf = lpReturnedString.Take(len).ToList();

            int ii = 0;
            for (int i = 0; i < buf.Count; i++)
            {
                if (buf[i] == 0)
                {
                    if (i == ii) break;

                    sections.Add(Encoding.ASCII.GetString(buf.GetRange(ii, i - ii).ToArray()));
                    ii = i + 1;
                }
            }

            return sections;
        }

        public static string Read(string section, string key, string defaultValue)
        {
            var ret = new StringBuilder(1023);

            if (GetPrivateProfileString(section, key, "", ret, 1023, INI) == 0)
                return defaultValue;

            return ret.ToString();
        }

        public static bool ReadBool(string section, string key, bool defaultValue)
        {
            string ret = Read(section, key, defaultValue.ToString());
            return bool.Parse(ret);
        }

        public static int ReadInt(string section, string key, int defaultValue)
        {
            string ret = Read(section, key, defaultValue.ToString());
            return int.Parse(ret);
        }

        public static void Write<T>(string section, string Key, T Value)
        {
            if (WritePrivateProfileString(section, Key, Value.ToString(), INI) == 0)
                MessageBox.Show("ini error: " + GetLastError().ToString());
        }

        public static void DeleteKey(string section, string key)
        {
            Write(key, null, section);
        }

        public static void DeleteSection(string section)
        {
            WritePrivateProfileString(section, null, null, INI);
        }
    }

    class Server
    {
        public string AuthUser;
        public string AuthPass;
        public string ServerAddr;
        public string LocalAddr;
        public string Key;
        public string Domain;
        public bool Partial;
        public int UDP;
        public int UDP_TCP;

        public static Server FromSection(string section)
        {
            Server s = new Server();
            s.ServerAddr = Config.Read(section, "Address", "");
            s.LocalAddr = Config.Read(section, "Local", "");
            s.Key = Config.Read(section, "Key", "");
            s.AuthUser = Config.Read(section, "Username", "");
            s.AuthPass = Config.Read(section, "Password", "");
            s.Partial = Config.ReadBool(section, "Partial", false);
            s.UDP = Config.ReadInt(section, "UDP", 8731);
            s.UDP_TCP = Config.ReadInt(section, "UDPoverTCP", 3);
            s.Domain = Config.Read(section, "Domain", "");
            return s;
        }

        public void ToSection()
        {
            string section = "server-" + this.ServerAddr;
            Config.Write(section, "Address", ServerAddr);
            Config.Write(section, "Local", LocalAddr);
            Config.Write(section, "Key", Key);
            Config.Write(section, "Username", AuthUser);
            Config.Write(section, "Password", AuthPass);
            Config.Write(section, "Partial", Partial);
            Config.Write(section, "UDP", UDP);
            Config.Write(section, "UDPoverTCP", UDP_TCP);
            Config.Write(section, "Domain", Domain);
        }

        public static Server FromUI(formMain form)
        {
            Server s = new Server();
            s.ServerAddr = form.comboServer.Text;
            s.LocalAddr = form.textPort.Text;
            s.Key = form.textKey.Text;
            s.AuthUser = form.textAuthUser.Text;
            s.AuthPass = form.textAuthPass.Text;
            s.Partial = form.checkPartial.Checked;
            s.UDP = (int)form.textUDP.Value;
            s.UDP_TCP = (int)form.textUDP_TCP.Value;
            s.Domain = form.textDomain.Text;
            return s;
        }

        public void ToUI(formMain form)
        {
            // do not set server addr
            form.textPort.Text = LocalAddr;
            form.textKey.Text = Key;
            form.textAuthUser.Text = AuthUser;
            form.textAuthPass.Text = AuthPass;
            form.checkPartial.Checked = Partial;
            form.textUDP.Value = UDP;
            form.textUDP_TCP.Value = UDP_TCP;
            form.textDomain.Text = Domain;
        }
    }
}
