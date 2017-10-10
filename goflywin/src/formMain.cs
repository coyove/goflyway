using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Resources;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace goflywin
{
    public partial class formMain : Form
    {
        private static uint SVR_ALREADY_STARTED = 1;
        private static uint SVR_ERROR_CODE   = 1 << 15;
        private static uint SVR_ERROR_EXITED = 1 << 1;
        private static uint SVR_ERROR_CREATE = 1 << 2;
        private static uint SVR_ERROR_PANIC  = 1 << 3;
        private static  int SVR_GLOBAL       = 1 << 16 + 0;
        private static  int SVR_IPLIST       = 1 << 16 + 1;
        private static  int SVR_NONE         = 1 << 16 + 2;

        private NotifyIcon notifyIcon;
        private MenuItem[] menuProxyType;

        private bool realExit = false;

        private Dictionary<string, Server> serverlist = new Dictionary<string, Server>();

        private ResourceManager rm = new ResourceManager("goflywin.Form", typeof(Program).Assembly);

        public delegate void LogCallback();

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_nickname([Out, MarshalAs(UnmanagedType.LPArray)] byte[] buf);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_switch(int type);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_unlock();

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int gofw_start(
            [MarshalAs(UnmanagedType.FunctionPtr)]LogCallback created,
            string log_level, string china_list, string upstream, string localaddr, string auth, string key,
            int partial, int dns_size, int udp_port, int udp_tcp);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_stop();

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong gofw_log_len();

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong gofw_log_read(ulong idx, [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buf);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_log_delete_since(ulong idx);

        public formMain()
        {
            InitializeComponent();
        }

        private void addLog(long ts, string msg)
        {
            if (msg == "") return;

            listLog.PerformSafely(() =>
            {
                if (listLog.Items.Count > 100)
                {
                    listLog.Items.RemoveAt(0);
                }

                if (checkLogtxt.Checked)
                {
                    System.IO.File.AppendAllText("log.txt", msg + "\n");
                }

                listLog.Items.Add(msg);
                listLog.TopIndex = listLog.Items.Count - 1;

            });
        }

        private void notifyStop()
        {
            this.PerformSafely(() =>
            {
                buttonStart.Enabled = true;
                buttonStop.Enabled = false;
                buttonConsole.Enabled = false;
                enableMenuProxyType(false, -1);
                labelState.Text = rm.GetString("NOTRUNNING");
                this.WindowState = FormWindowState.Normal;
            });
        }

        private void updateServerListToDisk()
        {
            List<string> lines = new List<string>();
            foreach (var server in serverlist)
            {
                lines.Add(server.Value.ToString());
            }

            System.IO.File.WriteAllText("server.txt", string.Join("\n", lines));
        }

        private void setTitle(string title, bool start)
        {
            this.PerformSafely(() => 
            {
                this.Text = title;
                labelServer.Enabled = !start;
                notifyIcon.Text = title;
            });
        }

        private void buttonStart_Click(object sender, EventArgs e)
        {
            if (comboServer.Text == "" || textPort.Text == "" || textKey.Text == "")
            {
                MessageBox.Show(rm.GetString("msgPleaseCheckInput"), Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }
            
            Server s = Server.FromUI(this);
            if (!serverlist.ContainsKey(s.ServerAddr)) comboServer.Items.Add(s.ServerAddr);
            serverlist[s.ServerAddr] = s;
            updateServerListToDisk();

            string auth = "", logl = comboLogLevel.Text, server = comboServer.Text, local = textPort.Text, key = textKey.Text;
            int partial = checkPartial.Checked ? 1 : 0, dns = (int)textDNS.Value, udp = (int)textUDP.Value, udptcp = (int)textUDP_TCP.Value;

            if (textAuthUser.Text != "" && textAuthPass.Text != "")
                auth = textAuthUser.Text + ":" + textAuthPass.Text;

            // gofw_start is a blocking method, so start it in a new thread
            new Thread(() =>
            {
                Thread.CurrentThread.CurrentUICulture = new CultureInfo(Properties.Settings.Default.Lang);
                Thread.CurrentThread.IsBackground = true;

                bool running = true;
                setTitle(Application.ProductName + " " + server, true);
                uint flag = (uint)gofw_start(() =>
                {
                    byte[] buf = new byte[32];
                    gofw_nickname(buf);
                    labelState.Text = Encoding.ASCII.GetString(buf);

                    buttonStart.Enabled = false;
                    buttonStop.Enabled = true;
                    buttonConsole.Enabled = true;
                    int idx = 0;

                    switch (comboProxyType.Text)
                    {
                        case "global":
                            gofw_switch(SVR_GLOBAL);
                            idx = 1;
                            break;
                        case "none":
                            gofw_switch(SVR_NONE);
                            idx = 2;
                            break;
                    }

                    if (checkAutoMin.Checked) this.WindowState = FormWindowState.Minimized;
                    enableMenuProxyType(true, idx);
                    addLog(0, "====     proxy started      ====");

                    // client has been created (but may not start to serve)
                    // start a thread to fetch logs
                    new Thread(() =>
                    {
                        while (true)
                        {
                            ulong ln = gofw_log_len();
                            if (ln == ulong.MaxValue || !running) break;
                            if (ln > 0)
                            {
                                for (ulong i = 0; i < ln; i++)
                                {
                                    byte[] pbuf = new byte[2048];
                                    ulong ts = gofw_log_read(i, pbuf);
                                    addLog((long)ts, Encoding.ASCII.GetString(pbuf).Replace("\0", string.Empty));
                                }

                                gofw_log_delete_since(ln - 1);
                            }

                            Thread.Sleep(200);
                        }

                        addLog(0, "====  logging thread exited  ====");
                    }).Start(); 
                }, 
                logl, "", server, local, auth, key, partial, dns, udp, udptcp);
                running = false;
                setTitle(Application.ProductName, false);

                if (flag == SVR_ALREADY_STARTED)
                    addLog(flag, "====  proxy already started  ====");

                if ((flag & SVR_ERROR_EXITED) != 0)
                    addLog(flag, "====      proxy exited       ====");

                if ((flag & SVR_ERROR_PANIC) != 0)
                    addLog(flag, "====     proxy panicked      ====");

                if ((flag & SVR_ERROR_CREATE) != 0)
                    addLog(flag, "==== proxy cannot be created ====");

                notifyStop();
            }).Start();
        }

        private void enableMenuProxyType(bool flag, int check)
        {
            for (int i = 0; i < menuProxyType.Count(); i++)
            {
                menuProxyType[i].Checked = i == check;
                menuProxyType[i].Enabled = flag;
            }
        }

        private void translateUI(Control ctrl)
        {
            CultureInfo zh = new CultureInfo(Properties.Settings.Default.Lang);
            Thread.CurrentThread.CurrentCulture = zh;
            Thread.CurrentThread.CurrentUICulture = zh;

            foreach (Control control in ctrl.Controls)
            {
                try
                {
                    control.Text = rm.GetString(control.Name);
                }
                catch (MissingManifestResourceException) { }

                if (control is GroupBox) translateUI(control);
            }

            comboLang.Text = Properties.Settings.Default.Lang;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            System.IO.File.Delete("log.txt");
            System.IO.File.Delete("error.txt");

            comboLogLevel.Text = Properties.Settings.Default.LogLevel;
            comboProxyType.Text = Properties.Settings.Default.ProxyType;
            comboLang.Text = Properties.Settings.Default.Lang;
            checkAutoMin.Checked = Properties.Settings.Default.AutoMin;
            checkAutostart.Checked = Properties.Settings.Default.Autostart;
            textDNS.Value = Properties.Settings.Default.DNSCache;

            translateUI(this);

            ContextMenu contextMenu = new ContextMenu();
            MenuItem menuShow = new MenuItem();
            menuShow.Text = rm.GetString("menuShow");
            menuShow.Click += new System.EventHandler(notifyIcon_DoubleClick);

            MenuItem menuExit = new MenuItem();
            menuExit.Text = rm.GetString("menuExit");
            menuExit.Click += new System.EventHandler(buttonQuit_Click);

            MenuItem menuConsole = new MenuItem();
            menuConsole.Text = rm.GetString("buttonConsole");
            menuConsole.Click += new System.EventHandler(buttonUnlock_Click);

            menuProxyType = new MenuItem[3];
            for (int i = 0; i < menuProxyType.Count(); i++)
            {
                menuProxyType[i] = new MenuItem();
                menuProxyType[i].Text = rm.GetString("menuProxyType").Split('|')[i];
                menuProxyType[i].Click += new System.EventHandler(proxy_Click);
            }

            notifyStop();

            contextMenu.MenuItems.AddRange(menuProxyType);
            contextMenu.MenuItems.Add("-");
            contextMenu.MenuItems.Add(menuConsole);
            contextMenu.MenuItems.Add(menuShow);
            contextMenu.MenuItems.Add(menuExit);

            notifyIcon = new NotifyIcon();
            notifyIcon.BalloonTipIcon = System.Windows.Forms.ToolTipIcon.Info;
            notifyIcon.BalloonTipText = rm.GetString("msgSystray");
            notifyIcon.Icon = Resource1.logo_ZS6_icon;
            notifyIcon.Text = Application.ProductName;
            notifyIcon.Visible = false;
            notifyIcon.ContextMenu = contextMenu;
            notifyIcon.DoubleClick += new System.EventHandler(notifyIcon_DoubleClick);

            try
            {
                foreach (string line in System.IO.File.ReadAllText("server.txt").Split('\n'))
                {
                    Server s = Server.FromString(line);
                    if (s != null)
                    {
                        serverlist[s.ServerAddr] = s;
                        comboServer.Items.Add(s.ServerAddr);
                    }
                }

                comboServer.SelectedIndex = 0;
             } catch { }
        }

        private void notifyIcon_DoubleClick(object sender, EventArgs e)
        {
            notifyIcon.Visible = false;
            this.ShowInTaskbar = true;
            this.Visible = true;
            this.WindowState = FormWindowState.Normal;
            this.Show();
        }

        private void proxy_Click(object sender, EventArgs e)
        {
            int i = 0;
            for (i = 0; i < menuProxyType.Count(); i++)
            {
                if (menuProxyType[i] == sender) break;
            }

            enableMenuProxyType(true, i);
            switchType(i);
        }

        private void switchType(int i)
        {
            switch (i)
            {
                case 0:
                    gofw_switch(SVR_IPLIST);
                    break;
                case 1:
                    gofw_switch(SVR_GLOBAL);
                    break;
                case 2:
                    gofw_switch(SVR_NONE);
                    break;
            }
        }

        private void buttonStop_Click(object sender, EventArgs e)
        {
            gofw_stop();
            notifyStop();
        }

        private void comboServer_SelectedIndexChanged(object sender, EventArgs e)
        {
            string k = comboServer.Text;
            if (serverlist.ContainsKey(k)) serverlist[k].ToUI(this);
        }

        private void notifyUser()
        {
            notifyIcon.Visible = true;
            notifyIcon.ShowBalloonTip(2000);
            this.ShowInTaskbar = false;
        }

        private void formMain_Resize(object sender, EventArgs e)
        {
            if (this.WindowState == FormWindowState.Minimized)
            {
                notifyUser();
            }
        }

        private void formMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (realExit)
            {
                Properties.Settings.Default.LogLevel = comboLogLevel.Text;
                Properties.Settings.Default.ProxyType = comboProxyType.Text;
                Properties.Settings.Default.AutoMin = checkAutoMin.Checked;
                Properties.Settings.Default.DNSCache = (int)textDNS.Value;
                Properties.Settings.Default.Autostart = checkAutostart.Checked;
                Properties.Settings.Default.Lang = comboLang.Text;
                Properties.Settings.Default.Save();
                return;
            }

            e.Cancel = true;
            this.Visible = false;
            notifyUser();
        }

        private void buttonQuit_Click(object sender, EventArgs e)
        {
            buttonStop.PerformClick();
            realExit = true;
            this.Close();
            Application.Exit();
        }

        private void labelState_Click(object sender, EventArgs e)
        {

        }

        private void buttonDelServer_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(rm.GetString("msgConfirmDelete"), Application.ProductName, MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                serverlist.Remove(comboServer.Text);
                int old = comboServer.SelectedIndex;
                comboServer.Items.RemoveAt(comboServer.SelectedIndex);
                comboServer.SelectedIndex = old;
                updateServerListToDisk();
            }
        }

        private void comboLang_SelectedIndexChanged(object sender, EventArgs e)
        {
            Properties.Settings.Default.Lang = comboLang.Text;
            translateUI(this);
        }

        private void checkAutostart_CheckedChanged(object sender, EventArgs e)
        {
            RegistryKey rkApp = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);

            if (checkAutostart.Checked)
            {
                rkApp.SetValue(Application.ProductName, Application.ExecutablePath);
            }
            else
            {
                rkApp.DeleteValue(Application.ProductName, false);
            }
        }

        private void buttonUnlock_Click(object sender, EventArgs e)
        {
            string addr = textPort.Text;
            int idx = addr.LastIndexOf(':');
            System.Diagnostics.Process.Start("http://127.0.0.1:" + addr.Substring(idx + 1) + "/?goflyway-console");
        }

        private void comboProxyType_SelectedIndexChanged(object sender, EventArgs e)
        {
            switchType(comboProxyType.SelectedIndex);
        }
    }
}
