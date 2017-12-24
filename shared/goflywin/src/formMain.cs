using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Resources;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
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
        private static  int SVR_GLOBAL       = (1 << 16) + 0;
        private static  int SVR_IPLIST       = (1 << 16) + 1;
        private static  int SVR_NONE         = (1 << 16) + 2;

        private NotifyIcon notifyIcon;
        private MenuItem[] menuProxyType;
        private MenuItem menuMITM;

        private bool realExit = false;

        private Dictionary<string, Server> serverlist = new Dictionary<string, Server>();

        private bool running = false;

        public delegate void LogCallback();

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_nickname([Out, MarshalAs(UnmanagedType.LPArray)] byte[] buf);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int gofw_switch(int type);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_mitm(int enabled);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int gofw_start(
            [MarshalAs(UnmanagedType.FunctionPtr)]LogCallback created,
            string log_level, string china_list, string upstream, string localaddr, string auth, string key, string domain,
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
                this.WindowState = FormWindowState.Normal;
            });
        }

        private void updateServerListToDisk()
        {
            foreach (var server in serverlist)
            {
                server.Value.ToSection();
            }
        }

        private void updateControls(string title, bool start)
        {
            this.PerformSafely(() => 
            {
                this.Text = title;
                labelServer.Enabled = !start;
                labelLogLevel.Enabled = comboLogLevel.Enabled = !start;
                labelDNS.Enabled = textDNS.Enabled = !start;
                checkAutoMin.Enabled = !start;
                menuMITM.Enabled = start;
                notifyIcon.Text = title;
            });
        }

        private void buttonStart_Click(object sender, EventArgs e)
        {
            if (comboServer.Text == "" || textPort.Text == "" || textKey.Text == "")
            {
                MessageBox.Show(Util.ResourceManager.GetString("msgPleaseCheckInput"), 
                    Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }
            
            Server s = Server.FromUI(this);
            if (!serverlist.ContainsKey(s.ServerAddr)) comboServer.Items.Add(s.ServerAddr);
            serverlist[s.ServerAddr] = s;
            updateServerListToDisk();

            string
                auth = "",
                chinalist = "",
                logl = comboLogLevel.Text,
                server = comboServer.Text,
                local = textPort.Text,
                key = textKey.Text,
                domain = textDomain.Text;
            try
            {
                // sliently read chinalist.txt
                chinalist = System.IO.File.ReadAllText("chinalist.txt");
            } catch (Exception) { }

            int 
                partial = checkPartial.Checked ? 1 : 0, 
                dns = (int)textDNS.Value, 
                udp = (int)textUDP.Value, 
                udptcp = (int)textUDP_TCP.Value;

            if (textAuthUser.Text != "" && textAuthPass.Text != "")
                auth = textAuthUser.Text + ":" + textAuthPass.Text;

            // gofw_start is a blocking method, so start it in a new thread
            new Thread(() =>
            {
                Thread.CurrentThread.CurrentUICulture = new CultureInfo(Config.Read("default", "Lang", ""));
                Thread.CurrentThread.IsBackground = true;

                running = true;
                uint flag = (uint)gofw_start(() =>
                {
                    byte[] buf = new byte[32];
                    gofw_nickname(buf);
                    updateControls(Application.ProductName + " - " + Util.BufferToString(buf)  + "/" + server, true);

                    buttonStart.Enabled = false;
                    buttonStop.Enabled = true;
                    buttonConsole.Enabled = true;

                    if (checkAutoMin.Checked) this.WindowState = FormWindowState.Minimized;
                    addLog(0, "====      proxy started      ====");

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
                                    addLog((long)ts, Util.BufferToString(pbuf));
                                }

                                gofw_log_delete_since(ln - 1);
                            }

                            Thread.Sleep(200);
                        }

                        addLog(0, "====  logging thread exited  ====");
                    }).Start();

                    new Thread(() =>
                    {
                        // an ugly workaround
                        Thread.Sleep(2000);

                        if (menuMITM.Checked = checkMITM.Checked)
                            gofw_mitm(1);

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
                        enableMenuProxyType(true, idx);
                    }).Start();
                }, 
                logl, chinalist, server, local, auth, key, domain, partial, dns, udp, udptcp);
                running = false;
                updateControls(Application.ProductName, false);

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
            string lang = Config.Read("default", "Lang", "zh-CN");
            Util.ResourceManager.Use(lang);

            foreach (Control control in ctrl.Controls)
            {
                string v;
                if (Util.ResourceManager.GetString(control.Name, out v))
                    control.Text = v;

                if (control.HasChildren)
                    translateUI(control);
            }

            comboLang.Text = lang;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            if (!System.IO.File.Exists("chinalist.txt")) System.IO.File.WriteAllText("chinalist.txt", Form_Resource.chinalist);
            if (!System.IO.File.Exists("ca.pem")) System.IO.File.WriteAllBytes("ca.pem", Form_Resource.ca);

            comboLogLevel.Text = Config.Read("default", "LogLevel", "log");
            comboProxyType.Text = Config.Read("default", "ProxyType", "iplist");
            comboLang.Text = Config.Read("default", "Lang", "zh-CN");
            checkAutoMin.Checked = Config.ReadBool("default", "AutoMin", true);
            checkAutostart.Checked = Config.ReadBool("default", "Autostart", false);
            checkMITM.Checked = Config.ReadBool("default", "MITM", false);
            textDNS.Value = Config.ReadInt("default", "DNSCache", 1024);

            translateUI(this);

            ContextMenu contextMenu = new ContextMenu();
            MenuItem menuShow = new MenuItem();
            menuShow.Text = Util.ResourceManager.GetString("menuShow");
            menuShow.Click += new System.EventHandler(notifyIcon_DoubleClick);

            MenuItem menuExit = new MenuItem();
            menuExit.Text = Util.ResourceManager.GetString("menuExit");
            menuExit.Click += new System.EventHandler(buttonQuit_Click);

            MenuItem menuConsole = new MenuItem();
            menuConsole.Text = Util.ResourceManager.GetString("buttonConsole");
            menuConsole.Click += new System.EventHandler(buttonUnlock_Click);

            menuMITM = new MenuItem();
            menuMITM.Text = Util.ResourceManager.GetString("checkMITM");
            menuMITM.Click += new System.EventHandler(menuMITM_Click);

            menuProxyType = new MenuItem[3];
            for (int i = 0; i < menuProxyType.Count(); i++)
            {
                menuProxyType[i] = new MenuItem();
                menuProxyType[i].Text = Util.ResourceManager.GetString("menuProxyType").Split('|')[i];
                menuProxyType[i].Click += new System.EventHandler(proxy_Click);
            }

            notifyStop();

            contextMenu.MenuItems.Add(menuMITM);
            contextMenu.MenuItems.Add("-");
            contextMenu.MenuItems.AddRange(menuProxyType);
            contextMenu.MenuItems.Add("-");
            contextMenu.MenuItems.Add(menuConsole);
            contextMenu.MenuItems.Add(menuShow);
            contextMenu.MenuItems.Add(menuExit);

            notifyIcon = new NotifyIcon();
            notifyIcon.BalloonTipIcon = System.Windows.Forms.ToolTipIcon.Info;
            notifyIcon.BalloonTipText = Util.ResourceManager.GetString("msgSystray");
            notifyIcon.Icon = Form_Resource.logo_ZS6_icon;
            notifyIcon.Text = Application.ProductName;
            notifyIcon.Visible = false;
            notifyIcon.ContextMenu = contextMenu;
            notifyIcon.DoubleClick += new System.EventHandler(notifyIcon_DoubleClick);

            Config.GetSections().Where(x => x.StartsWith("server-")).ToList().ForEach(section =>
            {
                Server s = Server.FromSection(section);
                serverlist[s.ServerAddr] = s;
                comboServer.Items.Add(s.ServerAddr);
                comboServer.SelectedIndex = 0;
            });
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
                    i = gofw_switch(SVR_IPLIST);
                    break;
                case 1:
                    i = gofw_switch(SVR_GLOBAL);
                    break;
                case 2:
                    i = gofw_switch(SVR_NONE);
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
                Config.Write("default", "LogLevel", comboLogLevel.Text);
                Config.Write("default", "ProxyType", comboProxyType.Text);
                Config.Write("default", "AutoMin", checkAutoMin.Checked);
                Config.Write("default", "DNSCache", (int)textDNS.Value);
                Config.Write("default", "Autostart", checkAutostart.Checked);
                Config.Write("default", "Lang", comboLang.Text);
                Config.Write("default", "MITM", checkMITM.Checked);
                return;
            }

            e.Cancel = true;
            this.Visible = false;
            notifyUser();
        }

        private void buttonQuit_Click(object sender, EventArgs e)
        {
            if (running) buttonStop.PerformClick();
            realExit = true;
            notifyIcon.Visible = false;
            this.Close();
            Application.Exit();
        }

        private void labelState_Click(object sender, EventArgs e)
        {

        }

        private void buttonDelServer_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(Util.ResourceManager.GetString("msgConfirmDelete"), 
                Application.ProductName, MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                serverlist.Remove(comboServer.Text);
                Config.DeleteSection("server-" + comboServer.Text);

                int old = comboServer.SelectedIndex;
                comboServer.Items.RemoveAt(comboServer.SelectedIndex);
                comboServer.SelectedIndex = old > comboServer.Items.Count - 1 ? 0 : old;
                updateServerListToDisk();
            }
        }

        private void comboLang_SelectedIndexChanged(object sender, EventArgs e)
        {
            Config.Write("default", "Lang", comboLang.Text);
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
            if (running) enableMenuProxyType(true, comboProxyType.SelectedIndex);
        }

        private void checkMITM_CheckedChanged(object sender, EventArgs e)
        {
            if (running)
            {
                gofw_mitm(checkMITM.Checked ? 1 : 0);
            }
        }

        private void menuMITM_Click(object sender, EventArgs e)
        {
            menuMITM.Checked = !menuMITM.Checked;
            checkMITM.Checked = menuMITM.Checked;
            checkMITM_CheckedChanged(sender, e);
        }
    }
}
