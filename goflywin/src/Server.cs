using System;
using System.Collections.Generic;
using System.Linq;
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

        public static void PerformSafely<T1>(this Control target, Action<T1> action, T1 parameter)
        {
            if (target.InvokeRequired)
            {
                target.Invoke(action, parameter);
            }
            else
            {
                action(parameter);
            }
        }

        public static void PerformSafely<T1, T2>(this Control target, Action<T1, T2> action, T1 p1, T2 p2)
        {
            if (target.InvokeRequired)
            {
                target.Invoke(action, p1, p2);
            }
            else
            {
                action(p1, p2);
            }
        }
    }

    class Util
    {
        public static string Escape(string text)
        {
            return text.Replace("|", "\\|");
        }

        public static string Unecape(string text)
        {
            return text.Replace("\\|", "|");
        }
    }

    class Server
    {
        public string AuthUser;
        public string AuthPass;
        public string ServerAddr;
        public string LocalAddr;
        public string Key;
        public bool Partial;
        public int UDP;
        public int UDP_TCP;

        public static Server FromString(string text)
        {
            List<string> parts = new List<string>();
            int i = 0, ii = 0;

            text += "|";
            while (i < text.Length)
            {
                if (text[i] == '|' && i > 0 && text[i - 1] != '\\')
                {
                    parts.Add(Util.Unecape(text.Substring(ii, i - ii)));
                    i++;
                    ii = i;
                    continue;
                }

                i++;
            }

            if (parts.Count() < 8) return null;

            Server s = new Server();
            s.ServerAddr = parts[0];
            s.LocalAddr = parts[1];
            s.Key = parts[2];
            s.AuthUser = parts[3];
            s.AuthPass = parts[4];
            s.Partial = parts[5] == "1";
            s.UDP = int.Parse(parts[6]);
            s.UDP_TCP = int.Parse(parts[7]);
            return s;
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
            return s;
        }

        public override string ToString()
        {
            return Util.Escape(ServerAddr) + "|" + Util.Escape(LocalAddr) + "|" + Util.Escape(Key) + "|" +
                Util.Escape(AuthUser) + "|" + Util.Escape(AuthPass) + "|" +
                (Partial ? "1" : "0") + "|" + UDP.ToString() + "|" + UDP_TCP.ToString();
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
        }
    }
}
