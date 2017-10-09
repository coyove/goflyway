using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.Linq;
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
        private static uint SVR_ERROR_CODE   = 1 << 15;
        private static uint SVR_ERROR_EXITED = 1 << 1;
        private static uint SVR_ERROR_CREATE = 1 << 2;
        private static uint SVR_ERROR_PANIC  = 1 << 3;
        private static  int SVR_GLOBAL       = 1 << 16 + 0;
        private static  int SVR_IPLIST       = 1 << 16 + 1;
        private static  int SVR_NONE         = 1 << 16 + 2;

        private NotifyIcon notifyIcon;
        private ContextMenu contextMenu;
        private MenuItem menuShow;
        private MenuItem menuExit;
        private MenuItem[] menuProxyType;

        private bool realExit = false;

        private Dictionary<string, Server> serverlist = new Dictionary<string, Server>();

        private ResourceManager rm = new ResourceManager("goflywin.Form", typeof(Program).Assembly);

        public delegate void LogCallback(long ts, string msg);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern string gofw_nickname();

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_switch(int type);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int gofw_start(
            string log_level, string china_list,
            [MarshalAs(UnmanagedType.FunctionPtr)]LogCallback log,
            [MarshalAs(UnmanagedType.FunctionPtr)]LogCallback err,
            string upstream, string localaddr, string auth, string key,
            int partial, int dns_size, int udp_port, int udp_tcp);

        [DllImport("goflyway.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void gofw_stop();

        public formMain()
        {
            InitializeComponent();
        }

        private void addLog(long ts, string msg)
        {
            if (listLog.Items.Count > 1000)
            {
                listLog.Items.RemoveAt(0);
            }

            if (checkLogtxt.Checked)
            {
                System.IO.File.AppendAllText("log.txt", msg + "\n");
            }

            listLog.Items.Add(msg);
            listLog.TopIndex = listLog.Items.Count - 1;
        }

        private void notifyStop()
        {
            buttonStart.Enabled = true;
            buttonStop.Enabled = false;
            enableMenuProxyType(false, -1);
            labelState.Text = rm.GetString("NOTRUNNING");
        }

        private void handleError(long ts, string msg)
        {
            ulong flag = (ulong)ts;

            if ((flag & SVR_ERROR_EXITED) != 0)
            {
                addLog(0, "==== proxy server exited ====");
            }

            if ((flag & SVR_ERROR_PANIC) != 0)
            {
                addLog(0, "==== proxy server panicked ====");
                addLog(0, msg);
            }

            notifyStop();
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

        private void buttonStart_Click(object sender, EventArgs e)
        {
            if (comboServer.Text == "" || textPort.Text == "" || textKey.Text == "")
            {
                MessageBox.Show(rm.GetString("msgPleaseCheckInput"), Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            Server s = Server.FromUI(this);
            serverlist[s.ServerAddr] = s;
            updateServerListToDisk();

            string auth = "";
            if (textAuthUser.Text != "" && textAuthPass.Text != "")
            {
                auth = textAuthUser.Text + ":" + textAuthPass.Text;
            }

            uint flag = (uint)gofw_start(comboLogLevel.Text, "", addLog, handleError, 
                comboServer.Text, textPort.Text, auth, textKey.Text, checkPartial.Checked ? 1 : 0, 
                (int)textDNS.Value, (int)textUDP.Value, (int)textUDP_TCP.Value);

            if ((flag & SVR_ERROR_CREATE) == 0)
            {
                buttonStart.Enabled = false;
                buttonStop.Enabled = true;
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

                labelState.Text = rm.GetString("RUNNING");
                if (checkAutoMin.Checked) this.WindowState = FormWindowState.Minimized;
                enableMenuProxyType(true, idx);
            }
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
            foreach (Control control in ctrl.Controls)
            {
                try
                {
                    control.Text = rm.GetString(control.Name);
                }
                catch (MissingManifestResourceException) { }

                if (control is GroupBox) translateUI(control);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            System.IO.File.Delete("log.txt");

            comboLogLevel.Text = Properties.Settings.Default.LogLevel;
            comboProxyType.Text = Properties.Settings.Default.ProxyType;
            checkAutoMin.Checked = Properties.Settings.Default.AutoMin;
            textDNS.Value = Properties.Settings.Default.DNSCache;

            translateUI(this);

            contextMenu = new ContextMenu();
            menuShow = new MenuItem();
            menuShow.Text = rm.GetString("menuShow");
            menuShow.Click += new System.EventHandler(notifyIcon_DoubleClick);

            menuExit = new MenuItem();
            menuExit.Text = rm.GetString("menuExit");
            menuExit.Click += new System.EventHandler(buttonQuit_Click);

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
        }

        private void labelState_Click(object sender, EventArgs e)
        {

        }

        private void buttonDelServer_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(rm.GetString("msgConfirmDelete"), Application.ProductName, MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                serverlist.Remove(comboServer.Text);
                comboServer.Items.RemoveAt(comboServer.SelectedIndex);
                updateServerListToDisk();
            }
        }
    }
}
