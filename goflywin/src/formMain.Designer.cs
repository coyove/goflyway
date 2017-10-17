namespace goflywin
{
    partial class formMain
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(formMain));
            this.buttonStart = new System.Windows.Forms.Button();
            this.buttonStop = new System.Windows.Forms.Button();
            this.buttonQuit = new System.Windows.Forms.Button();
            this.listLog = new System.Windows.Forms.ListBox();
            this.textUDP_TCP = new System.Windows.Forms.NumericUpDown();
            this.textUDP = new System.Windows.Forms.NumericUpDown();
            this.comboProxyType = new System.Windows.Forms.ComboBox();
            this.labelProxyType = new System.Windows.Forms.Label();
            this.checkAutostart = new System.Windows.Forms.CheckBox();
            this.comboLang = new System.Windows.Forms.ComboBox();
            this.label1 = new System.Windows.Forms.Label();
            this.checkLogtxt = new System.Windows.Forms.CheckBox();
            this.buttonConsole = new System.Windows.Forms.Button();
            this.labelServer = new System.Windows.Forms.GroupBox();
            this.layoutServer = new System.Windows.Forms.TableLayoutPanel();
            this.textDomain = new System.Windows.Forms.TextBox();
            this.labelDomain = new System.Windows.Forms.Label();
            this.labelUDP_TCP = new System.Windows.Forms.Label();
            this.labelUDP = new System.Windows.Forms.Label();
            this.labelAuthPass = new System.Windows.Forms.Label();
            this.textAuthPass = new System.Windows.Forms.TextBox();
            this.labelAuthUser = new System.Windows.Forms.Label();
            this.textAuthUser = new System.Windows.Forms.TextBox();
            this.checkPartial = new System.Windows.Forms.CheckBox();
            this.labelKey = new System.Windows.Forms.Label();
            this.textKey = new System.Windows.Forms.TextBox();
            this.labelPort = new System.Windows.Forms.Label();
            this.textPort = new System.Windows.Forms.TextBox();
            this.comboServer = new System.Windows.Forms.ComboBox();
            this.buttonDelServer = new System.Windows.Forms.Button();
            this.tableLayoutPanel2 = new System.Windows.Forms.TableLayoutPanel();
            this.labelMITMNote = new System.Windows.Forms.Label();
            this.labelDNS = new System.Windows.Forms.Label();
            this.labelLogLevel = new System.Windows.Forms.Label();
            this.comboLogLevel = new System.Windows.Forms.ComboBox();
            this.textDNS = new System.Windows.Forms.NumericUpDown();
            this.checkAutoMin = new System.Windows.Forms.CheckBox();
            this.checkMITM = new System.Windows.Forms.CheckBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            ((System.ComponentModel.ISupportInitialize)(this.textUDP_TCP)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.textUDP)).BeginInit();
            this.labelServer.SuspendLayout();
            this.layoutServer.SuspendLayout();
            this.tableLayoutPanel2.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.textDNS)).BeginInit();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // buttonStart
            // 
            this.buttonStart.Location = new System.Drawing.Point(459, 321);
            this.buttonStart.Margin = new System.Windows.Forms.Padding(2);
            this.buttonStart.Name = "buttonStart";
            this.buttonStart.Size = new System.Drawing.Size(90, 28);
            this.buttonStart.TabIndex = 13;
            this.buttonStart.Text = "Start";
            this.buttonStart.UseVisualStyleBackColor = true;
            this.buttonStart.Click += new System.EventHandler(this.buttonStart_Click);
            // 
            // buttonStop
            // 
            this.buttonStop.Enabled = false;
            this.buttonStop.Location = new System.Drawing.Point(459, 353);
            this.buttonStop.Margin = new System.Windows.Forms.Padding(2);
            this.buttonStop.Name = "buttonStop";
            this.buttonStop.Size = new System.Drawing.Size(90, 28);
            this.buttonStop.TabIndex = 14;
            this.buttonStop.Text = "Stop";
            this.buttonStop.UseVisualStyleBackColor = true;
            this.buttonStop.Click += new System.EventHandler(this.buttonStop_Click);
            // 
            // buttonQuit
            // 
            this.buttonQuit.Location = new System.Drawing.Point(459, 417);
            this.buttonQuit.Margin = new System.Windows.Forms.Padding(2);
            this.buttonQuit.Name = "buttonQuit";
            this.buttonQuit.Size = new System.Drawing.Size(90, 28);
            this.buttonQuit.TabIndex = 15;
            this.buttonQuit.Text = "Quit";
            this.buttonQuit.UseVisualStyleBackColor = true;
            this.buttonQuit.Click += new System.EventHandler(this.buttonQuit_Click);
            // 
            // listLog
            // 
            this.listLog.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.listLog.FormattingEnabled = true;
            this.listLog.HorizontalScrollbar = true;
            this.listLog.Location = new System.Drawing.Point(10, 321);
            this.listLog.Margin = new System.Windows.Forms.Padding(2);
            this.listLog.Name = "listLog";
            this.listLog.Size = new System.Drawing.Size(445, 121);
            this.listLog.TabIndex = 0;
            // 
            // textUDP_TCP
            // 
            this.textUDP_TCP.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textUDP_TCP.Location = new System.Drawing.Point(88, 192);
            this.textUDP_TCP.Name = "textUDP_TCP";
            this.textUDP_TCP.Size = new System.Drawing.Size(184, 20);
            this.textUDP_TCP.TabIndex = 21;
            this.textUDP_TCP.Value = new decimal(new int[] {
            3,
            0,
            0,
            0});
            // 
            // textUDP
            // 
            this.textUDP.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textUDP.Location = new System.Drawing.Point(88, 165);
            this.textUDP.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.textUDP.Minimum = new decimal(new int[] {
            1,
            0,
            0,
            0});
            this.textUDP.Name = "textUDP";
            this.textUDP.Size = new System.Drawing.Size(184, 20);
            this.textUDP.TabIndex = 22;
            this.textUDP.Value = new decimal(new int[] {
            8731,
            0,
            0,
            0});
            // 
            // comboProxyType
            // 
            this.comboProxyType.Dock = System.Windows.Forms.DockStyle.Fill;
            this.comboProxyType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboProxyType.FormattingEnabled = true;
            this.comboProxyType.Items.AddRange(new object[] {
            "iplist",
            "global",
            "none"});
            this.comboProxyType.Location = new System.Drawing.Point(71, 59);
            this.comboProxyType.Name = "comboProxyType";
            this.comboProxyType.Size = new System.Drawing.Size(172, 21);
            this.comboProxyType.TabIndex = 26;
            this.comboProxyType.SelectedIndexChanged += new System.EventHandler(this.comboProxyType_SelectedIndexChanged);
            // 
            // labelProxyType
            // 
            this.labelProxyType.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelProxyType.AutoSize = true;
            this.labelProxyType.Location = new System.Drawing.Point(2, 63);
            this.labelProxyType.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelProxyType.Name = "labelProxyType";
            this.labelProxyType.Size = new System.Drawing.Size(60, 13);
            this.labelProxyType.TabIndex = 25;
            this.labelProxyType.Text = "Proxy Type";
            // 
            // checkAutostart
            // 
            this.checkAutostart.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.checkAutostart, 2);
            this.checkAutostart.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checkAutostart.Location = new System.Drawing.Point(3, 253);
            this.checkAutostart.Name = "checkAutostart";
            this.checkAutostart.Size = new System.Drawing.Size(240, 24);
            this.checkAutostart.TabIndex = 35;
            this.checkAutostart.Text = "Launch goflywin at startup";
            this.checkAutostart.UseVisualStyleBackColor = true;
            this.checkAutostart.CheckedChanged += new System.EventHandler(this.checkAutostart_CheckedChanged);
            // 
            // comboLang
            // 
            this.comboLang.Dock = System.Windows.Forms.DockStyle.Fill;
            this.comboLang.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboLang.FormattingEnabled = true;
            this.comboLang.Items.AddRange(new object[] {
            "zh-CN",
            "en-US"});
            this.comboLang.Location = new System.Drawing.Point(71, 87);
            this.comboLang.Name = "comboLang";
            this.comboLang.Size = new System.Drawing.Size(172, 21);
            this.comboLang.TabIndex = 34;
            this.comboLang.SelectedIndexChanged += new System.EventHandler(this.comboLang_SelectedIndexChanged);
            // 
            // label1
            // 
            this.label1.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(2, 91);
            this.label1.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(55, 13);
            this.label1.TabIndex = 33;
            this.label1.Text = "Language";
            // 
            // checkLogtxt
            // 
            this.checkLogtxt.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.checkLogtxt, 2);
            this.checkLogtxt.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checkLogtxt.Location = new System.Drawing.Point(3, 226);
            this.checkLogtxt.Name = "checkLogtxt";
            this.checkLogtxt.Size = new System.Drawing.Size(240, 21);
            this.checkLogtxt.TabIndex = 32;
            this.checkLogtxt.Text = "Explicitly log to \'log.txt\'";
            this.checkLogtxt.UseVisualStyleBackColor = true;
            // 
            // buttonConsole
            // 
            this.buttonConsole.Enabled = false;
            this.buttonConsole.Location = new System.Drawing.Point(459, 385);
            this.buttonConsole.Margin = new System.Windows.Forms.Padding(2);
            this.buttonConsole.Name = "buttonConsole";
            this.buttonConsole.Size = new System.Drawing.Size(90, 28);
            this.buttonConsole.TabIndex = 32;
            this.buttonConsole.Text = "Open Console";
            this.buttonConsole.UseVisualStyleBackColor = true;
            this.buttonConsole.Click += new System.EventHandler(this.buttonUnlock_Click);
            // 
            // labelServer
            // 
            this.labelServer.Controls.Add(this.layoutServer);
            this.labelServer.Location = new System.Drawing.Point(10, 12);
            this.labelServer.Name = "labelServer";
            this.labelServer.Size = new System.Drawing.Size(281, 299);
            this.labelServer.TabIndex = 33;
            this.labelServer.TabStop = false;
            this.labelServer.Text = "Server Address (IP:Port)";
            // 
            // layoutServer
            // 
            this.layoutServer.AutoSize = true;
            this.layoutServer.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.layoutServer.ColumnCount = 2;
            this.layoutServer.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.layoutServer.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.layoutServer.Controls.Add(this.textDomain, 1, 8);
            this.layoutServer.Controls.Add(this.labelDomain, 0, 8);
            this.layoutServer.Controls.Add(this.labelUDP_TCP, 0, 7);
            this.layoutServer.Controls.Add(this.textUDP_TCP, 1, 7);
            this.layoutServer.Controls.Add(this.labelUDP, 0, 6);
            this.layoutServer.Controls.Add(this.textUDP, 1, 6);
            this.layoutServer.Controls.Add(this.labelAuthPass, 0, 5);
            this.layoutServer.Controls.Add(this.textAuthPass, 1, 5);
            this.layoutServer.Controls.Add(this.labelAuthUser, 0, 4);
            this.layoutServer.Controls.Add(this.textAuthUser, 1, 4);
            this.layoutServer.Controls.Add(this.checkPartial, 0, 3);
            this.layoutServer.Controls.Add(this.labelKey, 0, 2);
            this.layoutServer.Controls.Add(this.textKey, 1, 2);
            this.layoutServer.Controls.Add(this.labelPort, 0, 1);
            this.layoutServer.Controls.Add(this.textPort, 1, 1);
            this.layoutServer.Controls.Add(this.comboServer, 0, 0);
            this.layoutServer.Controls.Add(this.buttonDelServer, 1, 9);
            this.layoutServer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.layoutServer.Location = new System.Drawing.Point(3, 16);
            this.layoutServer.Name = "layoutServer";
            this.layoutServer.RowCount = 10;
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 11.11111F));
            this.layoutServer.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.layoutServer.Size = new System.Drawing.Size(275, 280);
            this.layoutServer.TabIndex = 34;
            // 
            // textDomain
            // 
            this.textDomain.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textDomain.Location = new System.Drawing.Point(87, 218);
            this.textDomain.Margin = new System.Windows.Forms.Padding(2);
            this.textDomain.Name = "textDomain";
            this.textDomain.Size = new System.Drawing.Size(186, 20);
            this.textDomain.TabIndex = 46;
            // 
            // labelDomain
            // 
            this.labelDomain.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelDomain.AutoSize = true;
            this.labelDomain.Location = new System.Drawing.Point(2, 223);
            this.labelDomain.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelDomain.Name = "labelDomain";
            this.labelDomain.Size = new System.Drawing.Size(81, 13);
            this.labelDomain.TabIndex = 42;
            this.labelDomain.Text = "Dummy Domain";
            // 
            // labelUDP_TCP
            // 
            this.labelUDP_TCP.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelUDP_TCP.AutoSize = true;
            this.labelUDP_TCP.Location = new System.Drawing.Point(2, 196);
            this.labelUDP_TCP.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelUDP_TCP.Name = "labelUDP_TCP";
            this.labelUDP_TCP.Size = new System.Drawing.Size(78, 13);
            this.labelUDP_TCP.TabIndex = 41;
            this.labelUDP_TCP.Text = "UDP over TCP";
            // 
            // labelUDP
            // 
            this.labelUDP.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelUDP.AutoSize = true;
            this.labelUDP.Location = new System.Drawing.Point(2, 169);
            this.labelUDP.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelUDP.Name = "labelUDP";
            this.labelUDP.Size = new System.Drawing.Size(52, 13);
            this.labelUDP.TabIndex = 40;
            this.labelUDP.Text = "UDP Port";
            // 
            // labelAuthPass
            // 
            this.labelAuthPass.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelAuthPass.AutoSize = true;
            this.labelAuthPass.Location = new System.Drawing.Point(2, 142);
            this.labelAuthPass.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelAuthPass.Name = "labelAuthPass";
            this.labelAuthPass.Size = new System.Drawing.Size(53, 13);
            this.labelAuthPass.TabIndex = 39;
            this.labelAuthPass.Text = "Password";
            // 
            // textAuthPass
            // 
            this.textAuthPass.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textAuthPass.Location = new System.Drawing.Point(87, 137);
            this.textAuthPass.Margin = new System.Windows.Forms.Padding(2);
            this.textAuthPass.Name = "textAuthPass";
            this.textAuthPass.Size = new System.Drawing.Size(186, 20);
            this.textAuthPass.TabIndex = 45;
            // 
            // labelAuthUser
            // 
            this.labelAuthUser.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelAuthUser.AutoSize = true;
            this.labelAuthUser.Location = new System.Drawing.Point(2, 115);
            this.labelAuthUser.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelAuthUser.Name = "labelAuthUser";
            this.labelAuthUser.Size = new System.Drawing.Size(55, 13);
            this.labelAuthUser.TabIndex = 38;
            this.labelAuthUser.Text = "Username";
            // 
            // textAuthUser
            // 
            this.textAuthUser.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textAuthUser.Location = new System.Drawing.Point(87, 110);
            this.textAuthUser.Margin = new System.Windows.Forms.Padding(2);
            this.textAuthUser.Name = "textAuthUser";
            this.textAuthUser.Size = new System.Drawing.Size(186, 20);
            this.textAuthUser.TabIndex = 46;
            // 
            // checkPartial
            // 
            this.checkPartial.AutoSize = true;
            this.layoutServer.SetColumnSpan(this.checkPartial, 2);
            this.checkPartial.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checkPartial.Location = new System.Drawing.Point(2, 83);
            this.checkPartial.Margin = new System.Windows.Forms.Padding(2);
            this.checkPartial.Name = "checkPartial";
            this.checkPartial.Size = new System.Drawing.Size(271, 23);
            this.checkPartial.TabIndex = 42;
            this.checkPartial.Text = "Partial encryption";
            this.checkPartial.UseVisualStyleBackColor = true;
            // 
            // labelKey
            // 
            this.labelKey.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelKey.AutoSize = true;
            this.labelKey.Location = new System.Drawing.Point(2, 61);
            this.labelKey.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelKey.Name = "labelKey";
            this.labelKey.Size = new System.Drawing.Size(25, 13);
            this.labelKey.TabIndex = 36;
            this.labelKey.Text = "Key";
            // 
            // textKey
            // 
            this.textKey.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textKey.Location = new System.Drawing.Point(87, 56);
            this.textKey.Margin = new System.Windows.Forms.Padding(2);
            this.textKey.Name = "textKey";
            this.textKey.Size = new System.Drawing.Size(186, 20);
            this.textKey.TabIndex = 37;
            this.textKey.Text = "0123456789abcdef";
            // 
            // labelPort
            // 
            this.labelPort.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelPort.AutoSize = true;
            this.labelPort.Location = new System.Drawing.Point(2, 34);
            this.labelPort.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelPort.Name = "labelPort";
            this.labelPort.Size = new System.Drawing.Size(64, 13);
            this.labelPort.TabIndex = 20;
            this.labelPort.Text = "Local Listen";
            // 
            // textPort
            // 
            this.textPort.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textPort.Location = new System.Drawing.Point(87, 29);
            this.textPort.Margin = new System.Windows.Forms.Padding(2);
            this.textPort.Name = "textPort";
            this.textPort.Size = new System.Drawing.Size(186, 20);
            this.textPort.TabIndex = 35;
            this.textPort.Text = ":8100";
            // 
            // comboServer
            // 
            this.layoutServer.SetColumnSpan(this.comboServer, 2);
            this.comboServer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.comboServer.FormattingEnabled = true;
            this.comboServer.Location = new System.Drawing.Point(2, 2);
            this.comboServer.Margin = new System.Windows.Forms.Padding(2);
            this.comboServer.Name = "comboServer";
            this.comboServer.Size = new System.Drawing.Size(271, 21);
            this.comboServer.TabIndex = 47;
            this.comboServer.SelectedIndexChanged += new System.EventHandler(this.comboServer_SelectedIndexChanged);
            // 
            // buttonDelServer
            // 
            this.buttonDelServer.Location = new System.Drawing.Point(87, 245);
            this.buttonDelServer.Margin = new System.Windows.Forms.Padding(2);
            this.buttonDelServer.Name = "buttonDelServer";
            this.buttonDelServer.Size = new System.Drawing.Size(106, 28);
            this.buttonDelServer.TabIndex = 48;
            this.buttonDelServer.Text = "Delete";
            this.buttonDelServer.UseVisualStyleBackColor = true;
            this.buttonDelServer.Click += new System.EventHandler(this.buttonDelServer_Click);
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.AutoSize = true;
            this.tableLayoutPanel2.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.tableLayoutPanel2.ColumnCount = 2;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Controls.Add(this.labelMITMNote, 0, 5);
            this.tableLayoutPanel2.Controls.Add(this.labelDNS, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.comboLang, 1, 3);
            this.tableLayoutPanel2.Controls.Add(this.labelLogLevel, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.label1, 0, 3);
            this.tableLayoutPanel2.Controls.Add(this.comboLogLevel, 1, 0);
            this.tableLayoutPanel2.Controls.Add(this.textDNS, 1, 1);
            this.tableLayoutPanel2.Controls.Add(this.labelProxyType, 0, 2);
            this.tableLayoutPanel2.Controls.Add(this.comboProxyType, 1, 2);
            this.tableLayoutPanel2.Controls.Add(this.checkAutostart, 0, 8);
            this.tableLayoutPanel2.Controls.Add(this.checkLogtxt, 0, 7);
            this.tableLayoutPanel2.Controls.Add(this.checkAutoMin, 1, 6);
            this.tableLayoutPanel2.Controls.Add(this.checkMITM, 0, 4);
            this.tableLayoutPanel2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel2.Location = new System.Drawing.Point(3, 16);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 8;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092226F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092233F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092233F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092233F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092233F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092233F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.092226F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.088593F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.088593F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 9.088593F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(246, 280);
            this.tableLayoutPanel2.TabIndex = 34;
            // 
            // labelMITMNote
            // 
            this.labelMITMNote.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.labelMITMNote, 2);
            this.labelMITMNote.Location = new System.Drawing.Point(2, 140);
            this.labelMITMNote.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelMITMNote.Name = "labelMITMNote";
            this.tableLayoutPanel2.SetRowSpan(this.labelMITMNote, 2);
            this.labelMITMNote.Size = new System.Drawing.Size(235, 39);
            this.labelMITMNote.TabIndex = 36;
            this.labelMITMNote.Text = "Please import \'ca.pem\' into the \'Trusted Root Certification Authority\' store firs" +
    "t, then MITM can work properly.";
            // 
            // labelDNS
            // 
            this.labelDNS.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelDNS.AutoSize = true;
            this.labelDNS.Location = new System.Drawing.Point(2, 35);
            this.labelDNS.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelDNS.Name = "labelDNS";
            this.labelDNS.Size = new System.Drawing.Size(64, 13);
            this.labelDNS.TabIndex = 30;
            this.labelDNS.Text = "DNS Cache";
            // 
            // labelLogLevel
            // 
            this.labelLogLevel.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.labelLogLevel.AutoSize = true;
            this.labelLogLevel.Location = new System.Drawing.Point(2, 7);
            this.labelLogLevel.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.labelLogLevel.Name = "labelLogLevel";
            this.labelLogLevel.Size = new System.Drawing.Size(54, 13);
            this.labelLogLevel.TabIndex = 24;
            this.labelLogLevel.Text = "Log Level";
            // 
            // comboLogLevel
            // 
            this.comboLogLevel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.comboLogLevel.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboLogLevel.FormattingEnabled = true;
            this.comboLogLevel.Items.AddRange(new object[] {
            "dbg",
            "log",
            "warn",
            "err",
            "off"});
            this.comboLogLevel.Location = new System.Drawing.Point(71, 3);
            this.comboLogLevel.Name = "comboLogLevel";
            this.comboLogLevel.Size = new System.Drawing.Size(172, 21);
            this.comboLogLevel.TabIndex = 25;
            // 
            // textDNS
            // 
            this.textDNS.Dock = System.Windows.Forms.DockStyle.Fill;
            this.textDNS.Location = new System.Drawing.Point(71, 31);
            this.textDNS.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.textDNS.Minimum = new decimal(new int[] {
            1,
            0,
            0,
            0});
            this.textDNS.Name = "textDNS";
            this.textDNS.Size = new System.Drawing.Size(172, 20);
            this.textDNS.TabIndex = 32;
            this.textDNS.Value = new decimal(new int[] {
            1024,
            0,
            0,
            0});
            // 
            // checkAutoMin
            // 
            this.checkAutoMin.AutoSize = true;
            this.checkAutoMin.Checked = true;
            this.checkAutoMin.CheckState = System.Windows.Forms.CheckState.Checked;
            this.tableLayoutPanel2.SetColumnSpan(this.checkAutoMin, 2);
            this.checkAutoMin.Cursor = System.Windows.Forms.Cursors.Default;
            this.checkAutoMin.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checkAutoMin.Location = new System.Drawing.Point(3, 199);
            this.checkAutoMin.Name = "checkAutoMin";
            this.checkAutoMin.Size = new System.Drawing.Size(240, 21);
            this.checkAutoMin.TabIndex = 27;
            this.checkAutoMin.Text = "Minimize to systray when proxy started";
            this.checkAutoMin.UseVisualStyleBackColor = true;
            // 
            // checkMITM
            // 
            this.checkMITM.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.checkMITM, 2);
            this.checkMITM.Cursor = System.Windows.Forms.Cursors.Default;
            this.checkMITM.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checkMITM.Location = new System.Drawing.Point(3, 115);
            this.checkMITM.Name = "checkMITM";
            this.checkMITM.Size = new System.Drawing.Size(240, 22);
            this.checkMITM.TabIndex = 36;
            this.checkMITM.Text = "Enable man-in-the-middle";
            this.checkMITM.UseVisualStyleBackColor = true;
            this.checkMITM.CheckedChanged += new System.EventHandler(this.checkMITM_CheckedChanged);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.tableLayoutPanel2);
            this.groupBox1.Location = new System.Drawing.Point(297, 12);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(252, 299);
            this.groupBox1.TabIndex = 35;
            this.groupBox1.TabStop = false;
            // 
            // formMain
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(556, 453);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.buttonConsole);
            this.Controls.Add(this.listLog);
            this.Controls.Add(this.buttonQuit);
            this.Controls.Add(this.buttonStop);
            this.Controls.Add(this.buttonStart);
            this.Controls.Add(this.labelServer);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MaximizeBox = false;
            this.Name = "formMain";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "goflywin";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.formMain_FormClosing);
            this.Load += new System.EventHandler(this.Form1_Load);
            this.Resize += new System.EventHandler(this.formMain_Resize);
            ((System.ComponentModel.ISupportInitialize)(this.textUDP_TCP)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.textUDP)).EndInit();
            this.labelServer.ResumeLayout(false);
            this.labelServer.PerformLayout();
            this.layoutServer.ResumeLayout(false);
            this.layoutServer.PerformLayout();
            this.tableLayoutPanel2.ResumeLayout(false);
            this.tableLayoutPanel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.textDNS)).EndInit();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.Button buttonStart;
        private System.Windows.Forms.Button buttonStop;
        private System.Windows.Forms.Button buttonQuit;
        private System.Windows.Forms.Label labelProxyType;
        public System.Windows.Forms.NumericUpDown textUDP_TCP;
        public System.Windows.Forms.NumericUpDown textUDP;
        public System.Windows.Forms.ComboBox comboProxyType;
        public System.Windows.Forms.ComboBox comboLang;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button buttonConsole;
        private System.Windows.Forms.GroupBox labelServer;
        private System.Windows.Forms.TableLayoutPanel layoutServer;
        public System.Windows.Forms.TextBox textPort;
        private System.Windows.Forms.Label labelPort;
        private System.Windows.Forms.Label labelKey;
        private System.Windows.Forms.Label labelUDP_TCP;
        public System.Windows.Forms.TextBox textKey;
        private System.Windows.Forms.Label labelUDP;
        public System.Windows.Forms.CheckBox checkPartial;
        private System.Windows.Forms.Label labelAuthPass;
        private System.Windows.Forms.Label labelAuthUser;
        public System.Windows.Forms.TextBox textAuthPass;
        public System.Windows.Forms.TextBox textAuthUser;
        public System.Windows.Forms.ComboBox comboServer;
        private System.Windows.Forms.Button buttonDelServer;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel2;
        private System.Windows.Forms.Label labelLogLevel;
        public System.Windows.Forms.ComboBox comboLogLevel;
        private System.Windows.Forms.Label labelDNS;
        public System.Windows.Forms.NumericUpDown textDNS;
        public System.Windows.Forms.CheckBox checkLogtxt;
        public System.Windows.Forms.CheckBox checkAutostart;
        private System.Windows.Forms.GroupBox groupBox1;
        public System.Windows.Forms.ListBox listLog;
        private System.Windows.Forms.Label labelDomain;
        public System.Windows.Forms.TextBox textDomain;
        public System.Windows.Forms.CheckBox checkAutoMin;
        public System.Windows.Forms.CheckBox checkMITM;
        private System.Windows.Forms.Label labelMITMNote;
    }
}

