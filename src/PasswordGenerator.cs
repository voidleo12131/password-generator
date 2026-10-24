// 密碼產生器 - 單一檔案 WinForms 程式
// 編譯: 執行 build.ps1 (使用 Windows 內建的 .NET Framework csc.exe)

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("密碼產生器")]
[assembly: System.Reflection.AssemblyProduct("密碼產生器")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]

namespace PwGen
{
    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--selftest")
            {
                Environment.Exit(SelfTest.Run());
                return;
            }
            if (Environment.OSVersion.Version.Major >= 6) SetProcessDPIAware();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // ------------------------------------------------------------------
    // 密碼產生核心
    // ------------------------------------------------------------------
    static class Generator
    {
        public const string Digits = "0123456789";
        public const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public const string Lower = "abcdefghijklmnopqrstuvwxyz";
        public const string Confusing = "0Oo1Il|`'\"";

        static readonly string[] KeyRows = { "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./" };
        static readonly string[] ShiftRows = { "~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?" };
        static readonly Dictionary<char, int[]> KeyPos = BuildKeyPos();
        static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        static Dictionary<char, int[]> BuildKeyPos()
        {
            var d = new Dictionary<char, int[]>();
            for (int r = 0; r < KeyRows.Length; r++)
                for (int c = 0; c < KeyRows[r].Length; c++)
                {
                    d[KeyRows[r][c]] = new[] { r, c };
                    d[ShiftRows[r][c]] = new[] { r, c };
                }
            return d;
        }

        // 密碼學安全、無偏差的亂數 [0, max)
        public static int NextInt(int max)
        {
            if (max <= 1) return 0;
            byte[] b = new byte[4];
            uint limit = (uint.MaxValue / (uint)max) * (uint)max;
            uint v;
            do
            {
                Rng.GetBytes(b);
                v = BitConverter.ToUInt32(b, 0);
            } while (v >= limit);
            return (int)(v % (uint)max);
        }

        // 只保留可見的 ASCII 符號 (排除英數與空白)，並去除重複
        public static string CleanSymbols(string s, bool excludeConfusing)
        {
            var sb = new StringBuilder();
            foreach (char c in s ?? "")
            {
                if (c < 33 || c > 126 || char.IsLetterOrDigit(c)) continue;
                if (excludeConfusing && Confusing.IndexOf(c) >= 0) continue;
                if (sb.ToString().IndexOf(c) >= 0) continue;
                sb.Append(c);
            }
            return sb.ToString();
        }

        static string Filter(string s, bool excludeConfusing)
        {
            if (!excludeConfusing) return s;
            return new string(s.Where(c => Confusing.IndexOf(c) < 0).ToArray());
        }

        // 依設定建立各類字元池；有錯誤時回傳 null 並給出原因
        public static List<string> BuildPools(bool digits, bool upper, bool lower, bool symbols,
            string symbolChars, bool excludeConfusing, int length, out string error)
        {
            error = null;
            var pools = new List<string>();
            if (digits) pools.Add(Filter(Digits, excludeConfusing));
            if (upper) pools.Add(Filter(Upper, excludeConfusing));
            if (lower) pools.Add(Filter(Lower, excludeConfusing));
            if (symbols)
            {
                string s = CleanSymbols(symbolChars, excludeConfusing);
                if (s.Length == 0)
                {
                    error = "符號規則中沒有可用的符號，請輸入至少一個符號或取消勾選「符號」。";
                    return null;
                }
                pools.Add(s);
            }
            if (pools.Count == 0)
            {
                error = "請至少勾選一種字元類型。";
                return null;
            }
            if (length < pools.Count)
            {
                error = string.Format("密碼長度至少需要 {0} 位，才能包含每一種勾選的字元類型。", pools.Count);
                return null;
            }
            return pools;
        }

        public static double EntropyBits(List<string> pools, int length)
        {
            int n = pools.Sum(p => p.Length);
            return n <= 1 ? 0 : length * Math.Log(n, 2);
        }

        public static string StrengthText(double bits)
        {
            if (bits < 40) return "弱";
            if (bits < 60) return "普通";
            if (bits < 80) return "強";
            return "非常強";
        }

        public static string Generate(int length, List<string> pools, bool avoidPatterns)
        {
            string all = string.Concat(pools);

            // 每一種勾選的類型至少出現一次，放在隨機位置
            string[] slotPool = new string[length];
            for (int i = 0; i < length; i++) slotPool[i] = all;
            int[] positions = Enumerable.Range(0, length).ToArray();
            Shuffle(positions);
            for (int k = 0; k < pools.Count; k++) slotPool[positions[k]] = pools[k];

            char[] result = new char[length];
            var candidates = new List<char>(all.Length);
            for (int i = 0; i < length; i++)
            {
                string pool = slotPool[i];
                candidates.Clear();
                foreach (char c in pool)
                    if (!avoidPatterns || IsAllowed(result, i, c)) candidates.Add(c);
                if (candidates.Count == 0) candidates.AddRange(pool); // 字元池太小時無法避免，退回不限制
                result[i] = candidates[NextInt(candidates.Count)];
            }
            return new string(result);
        }

        static bool IsAllowed(char[] r, int i, char c)
        {
            char lc = char.ToLowerInvariant(c);
            // 不可與前一或前二個字元相同 (避免 aa、aba、aA)
            if (i >= 1 && char.ToLowerInvariant(r[i - 1]) == lc) return false;
            if (i >= 2 && char.ToLowerInvariant(r[i - 2]) == lc) return false;
            // 不可形成三個字元的連號或鍵盤順序
            if (i >= 2 && IsRun(r[i - 2], r[i - 1], c)) return false;
            return true;
        }

        // abc / cba / 123 / 321 / qwe / ewq / !@# / asd ... 等三連
        public static bool IsRun(char a, char b, char c)
        {
            char x = char.ToLowerInvariant(a), y = char.ToLowerInvariant(b), z = char.ToLowerInvariant(c);
            int d1 = y - x, d2 = z - y;
            if (d1 == d2 && (d1 == 1 || d1 == -1)) return true;

            int[] p, q, s;
            if (KeyPos.TryGetValue(x, out p) && KeyPos.TryGetValue(y, out q) && KeyPos.TryGetValue(z, out s))
            {
                if (p[0] == q[0] && q[0] == s[0])
                {
                    int e1 = q[1] - p[1], e2 = s[1] - q[1];
                    if (e1 == e2 && (e1 == 1 || e1 == -1)) return true;
                }
            }
            return false;
        }

        static void Shuffle(int[] a)
        {
            for (int i = a.Length - 1; i > 0; i--)
            {
                int j = NextInt(i + 1);
                int t = a[i]; a[i] = a[j]; a[j] = t;
            }
        }
    }

    // ------------------------------------------------------------------
    // 設定與複製紀錄的儲存
    // ------------------------------------------------------------------
    class HistoryItem
    {
        public DateTime Time;
        public string Password;
        public string Note;
    }

    static class Store
    {
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("PwGen.History.v1");
        const int MaxHistory = 500;

        static string Dir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordGenerator"); }
        }
        static string SettingsPath { get { return Path.Combine(Dir, "settings.ini"); } }
        static string HistoryPath { get { return Path.Combine(Dir, "history.dat"); } }

        static string Escape(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n");
        }

        static string Unescape(string s)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 1 < s.Length)
                {
                    char n = s[++i];
                    sb.Append(n == 'n' ? '\n' : n == 'r' ? '\r' : n);
                }
                else sb.Append(s[i]);
            }
            return sb.ToString();
        }

        public static List<KeyValuePair<string, string>> LoadSettings()
        {
            var list = new List<KeyValuePair<string, string>>();
            try
            {
                if (!File.Exists(SettingsPath)) return list;
                foreach (string line in File.ReadAllLines(SettingsPath, Encoding.UTF8))
                {
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    list.Add(new KeyValuePair<string, string>(line.Substring(0, eq), Unescape(line.Substring(eq + 1))));
                }
            }
            catch { }
            return list;
        }

        public static void SaveSettings(List<KeyValuePair<string, string>> settings)
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllLines(SettingsPath, settings.Select(kv => kv.Key + "=" + Escape(kv.Value)), Encoding.UTF8);
            }
            catch { }
        }

        static string B64(string s) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(s ?? "")); }
        static string UnB64(string s) { return Encoding.UTF8.GetString(Convert.FromBase64String(s)); }

        public static List<HistoryItem> LoadHistory()
        {
            var list = new List<HistoryItem>();
            try
            {
                if (!File.Exists(HistoryPath)) return list;
                byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(HistoryPath), Entropy, DataProtectionScope.CurrentUser);
                foreach (string line in Encoding.UTF8.GetString(plain).Split('\n'))
                {
                    string[] parts = line.Split('\t');
                    if (parts.Length < 3) continue;
                    list.Add(new HistoryItem
                    {
                        Time = new DateTime(long.Parse(parts[0])),
                        Password = UnB64(parts[1]),
                        Note = UnB64(parts[2])
                    });
                }
            }
            catch { }
            return list;
        }

        public static void SaveHistory(List<HistoryItem> history)
        {
            try
            {
                Directory.CreateDirectory(Dir);
                string text = string.Join("\n", history.Take(MaxHistory)
                    .Select(h => h.Time.Ticks + "\t" + B64(h.Password) + "\t" + B64(h.Note)));
                byte[] enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(text), Entropy, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(HistoryPath, enc);
            }
            catch { }
        }

        public static void DeleteHistoryFile()
        {
            try { if (File.Exists(HistoryPath)) File.Delete(HistoryPath); }
            catch { }
        }
    }

    // ------------------------------------------------------------------
    // 主視窗
    // ------------------------------------------------------------------
    class PresetItem
    {
        public string Name;
        public string Chars; // null 代表「自訂」
        public bool IsUser;
        public override string ToString() { return (IsUser ? "★ " : "") + Name; }
    }

    class MainForm : Form
    {
        static readonly PresetItem[] BuiltinPresets =
        {
            new PresetItem { Name = "預設符號", Chars = "!@#$%^&*-_=+?" },
            new PresetItem { Name = "全部符號", Chars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" },
            new PresetItem { Name = "常見網站相容", Chars = "!@#$%^&*" },
            new PresetItem { Name = "最保守 (!@#$)", Chars = "!@#$" },
        };
        const int MaxHistoryCount = 500;
        const int ClipboardClearSeconds = 30;

        TrackBar trkLen;
        NumericUpDown numLen, numCount;
        CheckBox chkDigit, chkUpper, chkLower, chkSymbol, chkConfusing, chkPattern, chkRemember, chkAutoClear, chkShowHist;
        ComboBox cboPreset;
        TextBox txtSymbols;
        Button btnSavePreset, btnDelPreset, btnGenerate, btnCopySel, btnCopyAll;
        Label lblInfo;
        ListView lvResult, lvHistory;
        ToolStripStatusLabel lblStatus;
        Timer clipTimer;

        List<HistoryItem> history = new List<HistoryItem>();
        List<PresetItem> userPresets = new List<PresetItem>();
        bool suppressEvents;
        string lastCopied;

        public MainForm()
        {
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Microsoft JhengHei UI", 9F);
            Text = "密碼產生器";
            ClientSize = new Size(640, 630);
            MinimumSize = new Size(660, 600);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            BuildUi();
            ResumeLayout(false);
            PerformLayout();

            LoadSettings();
            if (chkRemember.Checked) history = Store.LoadHistory();
            RefreshHistoryList();
            UpdateInfo();
            DoGenerate();

            clipTimer = new Timer { Interval = ClipboardClearSeconds * 1000 };
            clipTimer.Tick += delegate { clipTimer.Stop(); ClearClipboardIfOurs(true); };
        }

        // ---------------- UI 建構 ----------------
        void BuildUi()
        {
            var status = new StatusStrip();
            lblStatus = new ToolStripStatusLabel("就緒") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            status.Items.Add(lblStatus);

            // 用 Dock 而非 Anchor：高 DPI 縮放時 Anchor 會把分頁算得比視窗還寬
            Padding = new Padding(8, 8, 8, 2);
            var tabs = new TabControl { Size = new Size(624, 598), Dock = DockStyle.Fill };
            var tabGen = new TabPage("產生密碼") { UseVisualStyleBackColor = true };
            var tabHist = new TabPage("複製紀錄") { UseVisualStyleBackColor = true };
            tabs.TabPages.Add(tabGen);
            tabs.TabPages.Add(tabHist);
            tabs.SelectedIndexChanged += delegate { if (tabs.SelectedTab == tabHist) RefreshHistoryList(); };

            BuildGeneratorTab(tabGen);
            BuildHistoryTab(tabHist);

            Controls.Add(tabs);
            Controls.Add(status);
            AcceptButton = btnGenerate;
            FormClosing += OnClosing;
        }

        void BuildGeneratorTab(TabPage page)
        {
            var grp = new GroupBox { Text = "設定", Location = new Point(0, 0), Size = new Size(600, 262) };

            grp.Controls.Add(new Label { Text = "密碼長度：", Location = new Point(12, 28), AutoSize = true });
            trkLen = new TrackBar { Location = new Point(90, 22), Size = new Size(380, 45), Minimum = 2, Maximum = 99, TickFrequency = 5, LargeChange = 4, Value = 16 };
            numLen = new NumericUpDown { Location = new Point(478, 23), Width = 60, Minimum = 2, Maximum = 99, Value = 16, Font = new Font(Font.FontFamily, 10F, FontStyle.Bold) };
            grp.Controls.Add(new Label { Text = "位", Location = new Point(544, 28), AutoSize = true });
            trkLen.ValueChanged += delegate { if (numLen.Value != trkLen.Value) numLen.Value = trkLen.Value; };
            numLen.ValueChanged += delegate { if (trkLen.Value != (int)numLen.Value) trkLen.Value = (int)numLen.Value; UpdateInfo(); };

            grp.Controls.Add(new Label { Text = "產生組數：", Location = new Point(12, 72), AutoSize = true });
            numCount = new NumericUpDown { Location = new Point(92, 69), Width = 64, Minimum = 1, Maximum = 10, Value = 5 };
            grp.Controls.Add(new Label { Text = "組 (1 ~ 10)", Location = new Point(162, 72), AutoSize = true, ForeColor = SystemColors.GrayText });

            grp.Controls.Add(new Label { Text = "字元類型：", Location = new Point(12, 106), AutoSize = true });
            chkDigit = MakeCheck("數字 0-9", 92, 104, true);
            chkUpper = MakeCheck("大寫 A-Z", 202, 104, true);
            chkLower = MakeCheck("小寫 a-z", 312, 104, true);
            chkSymbol = MakeCheck("符號", 422, 104, true);
            chkSymbol.CheckedChanged += delegate { UpdateSymbolEnabled(); };

            grp.Controls.Add(new Label { Text = "符號規則：", Location = new Point(12, 141), AutoSize = true });
            cboPreset = new ComboBox { Location = new Point(92, 137), Width = 150, DropDownStyle = ComboBoxStyle.DropDownList };
            txtSymbols = new TextBox { Location = new Point(248, 137), Width = 214, Font = new Font("Consolas", 10F) };
            btnSavePreset = new Button { Text = "儲存規則", Location = new Point(468, 135), Size = new Size(62, 27) };
            btnDelPreset = new Button { Text = "刪除", Location = new Point(534, 135), Size = new Size(52, 27) };
            cboPreset.SelectedIndexChanged += OnPresetChanged;
            txtSymbols.TextChanged += delegate { if (suppressEvents) return; SyncPresetToText(); UpdateInfo(); };
            btnSavePreset.Click += delegate { SaveUserPreset(); };
            btnDelPreset.Click += delegate { DeleteUserPreset(); };

            chkConfusing = MakeCheck("排除易混淆字元（ 0 O o 1 I l | ` ' \" ）", 12, 176, true);
            chkPattern = MakeCheck("避免規律排列（相鄰重複 aa / aba、連號 abc / 321、鍵盤順序 qwe / !@#）", 12, 202, true);

            lblInfo = new Label { Location = new Point(12, 232), AutoSize = true };

            var tip = new ToolTip();
            tip.SetToolTip(txtSymbols, "可直接編輯要使用的符號，只允許可見的 ASCII 符號，重複的會自動忽略。");
            tip.SetToolTip(btnSavePreset, "把目前的符號存成規則，下次可以直接選 (例如某個網站只允許的符號)。");
            tip.SetToolTip(chkPattern, "密碼以密碼學亂數產生，並逐字檢查，避免出現人眼看得出的規律。");

            grp.Controls.AddRange(new Control[] { trkLen, numLen, numCount, chkDigit, chkUpper, chkLower, chkSymbol,
                cboPreset, txtSymbols, btnSavePreset, btnDelPreset, chkConfusing, chkPattern, lblInfo });

            btnGenerate = new Button { Text = "產生密碼", Location = new Point(0, 270), Size = new Size(140, 36), Font = new Font(Font.FontFamily, 10F, FontStyle.Bold) };
            btnCopySel = new Button { Text = "複製選取", Location = new Point(148, 270), Size = new Size(100, 36) };
            btnCopyAll = new Button { Text = "全部複製", Location = new Point(254, 270), Size = new Size(100, 36) };
            var lblHint = new Label { Text = "提示：雙擊密碼即可複製", Location = new Point(364, 281), AutoSize = true, ForeColor = SystemColors.GrayText };
            btnGenerate.Click += delegate { DoGenerate(); };
            btnCopySel.Click += delegate { CopyResultItems(lvResult.SelectedItems.Cast<ListViewItem>().ToList()); };
            btnCopyAll.Click += delegate { CopyResultItems(lvResult.Items.Cast<ListViewItem>().ToList()); };

            lvResult = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false,
                Font = new Font("Consolas", 11.5F)
            };
            lvResult.Columns.Add("#", 36);
            lvResult.Columns.Add("密碼", 380);
            lvResult.Columns.Add("強度", 80);
            lvResult.Columns.Add("狀態", 90);
            lvResult.DoubleClick += delegate { CopyResultItems(lvResult.SelectedItems.Cast<ListViewItem>().ToList()); };
            lvResult.KeyDown += (s, e) =>
            {
                if (e.Control && e.KeyCode == Keys.C) { CopyResultItems(lvResult.SelectedItems.Cast<ListViewItem>().ToList()); e.Handled = true; }
                if (e.Control && e.KeyCode == Keys.A) { foreach (ListViewItem it in lvResult.Items) it.Selected = true; e.Handled = true; }
            };

            chkRemember = new CheckBox { Text = "記住複製紀錄（以 Windows DPAPI 加密存在本機，只有你的 Windows 帳號能讀取）", Location = new Point(0, 8), AutoSize = true, Checked = true };
            chkAutoClear = new CheckBox { Text = "複製後 " + ClipboardClearSeconds + " 秒自動清除剪貼簿", Location = new Point(0, 34), AutoSize = true };
            chkRemember.CheckedChanged += OnRememberChanged;

            AddToPage(page,
                DockPanel(DockStyle.Top, 314, grp, btnGenerate, btnCopySel, btnCopyAll, lblHint),
                lvResult,
                DockPanel(DockStyle.Bottom, 60, chkRemember, chkAutoClear));
        }

        // 版面一律用 Dock 組成 (上 / 中間填滿 / 下)，高 DPI 縮放時才不會跑位
        static Panel DockPanel(DockStyle dock, int height, params Control[] controls)
        {
            var p = new Panel { Size = new Size(600, height) };
            p.Controls.AddRange(controls);
            p.Dock = dock;
            return p;
        }

        static void AddToPage(TabPage page, Control top, Control fill, Control bottom)
        {
            var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 8, 8, 0) };
            host.Controls.Add(fill);   // Fill 要最先加入，才會填滿上下以外的空間
            if (top != null) host.Controls.Add(top);
            host.Controls.Add(bottom);
            page.Controls.Add(host);
        }

        CheckBox MakeCheck(string text, int x, int y, bool isChecked)
        {
            var c = new CheckBox { Text = text, Location = new Point(x, y), AutoSize = true, Checked = isChecked };
            c.CheckedChanged += delegate { if (!suppressEvents) UpdateInfo(); };
            return c;
        }

        void BuildHistoryTab(TabPage page)
        {
            lvHistory = new ListView
            {
                Location = new Point(8, 8), Size = new Size(600, 470),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, LabelEdit = true
            };
            lvHistory.Columns.Add("備註（用途 / 網站）", 150);
            lvHistory.Columns.Add("密碼", 240);
            lvHistory.Columns.Add("長度", 50);
            lvHistory.Columns.Add("複製時間", 160);
            lvHistory.AfterLabelEdit += (s, e) =>
            {
                if (e.Label == null) return;
                var h = (HistoryItem)lvHistory.Items[e.Item].Tag;
                h.Note = e.Label.Trim();
                SaveHistory();
            };
            lvHistory.DoubleClick += delegate { CopyHistorySelected(); };
            lvHistory.KeyDown += (s, e) =>
            {
                if (e.Control && e.KeyCode == Keys.C) { CopyHistorySelected(); e.Handled = true; }
                if (e.KeyCode == Keys.Delete) { DeleteHistorySelected(); e.Handled = true; }
                if (e.KeyCode == Keys.F2) { EditHistoryNote(); e.Handled = true; }
            };

            var menu = new ContextMenuStrip();
            menu.Items.Add("複製密碼", null, delegate { CopyHistorySelected(); });
            menu.Items.Add("編輯備註 (F2)", null, delegate { EditHistoryNote(); });
            menu.Items.Add("刪除 (Del)", null, delegate { DeleteHistorySelected(); });
            lvHistory.ContextMenuStrip = menu;

            lvHistory.Dock = DockStyle.Fill;
            chkShowHist = new CheckBox { Text = "顯示密碼", Location = new Point(0, 12), AutoSize = true };
            chkShowHist.CheckedChanged += delegate { RefreshHistoryList(); };
            var hint = new Label { Text = "雙擊可再次複製；按 F2 或右鍵可寫備註，記下這組密碼用在哪裡。", Location = new Point(0, 42), AutoSize = true, ForeColor = SystemColors.GrayText };

            var btnCopy = new Button { Text = "複製", Location = new Point(288, 8), Size = new Size(70, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            var btnNote = new Button { Text = "編輯備註", Location = new Point(362, 8), Size = new Size(76, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            var btnDel = new Button { Text = "刪除選取", Location = new Point(442, 8), Size = new Size(76, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            var btnClear = new Button { Text = "全部清除", Location = new Point(522, 8), Size = new Size(78, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnCopy.Click += delegate { CopyHistorySelected(); };
            btnNote.Click += delegate { EditHistoryNote(); };
            btnDel.Click += delegate { DeleteHistorySelected(); };
            btnClear.Click += delegate
            {
                if (history.Count == 0) return;
                if (MessageBox.Show(this, "確定要清除全部 " + history.Count + " 筆複製紀錄嗎？此動作無法復原。", "清除紀錄",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                history.Clear();
                SaveHistory();
                RefreshHistoryList();
                SetStatus("已清除全部複製紀錄");
            };

            AddToPage(page, null, lvHistory, DockPanel(DockStyle.Bottom, 66, chkShowHist, hint, btnCopy, btnNote, btnDel, btnClear));
        }

        // ---------------- 符號規則 ----------------
        void RebuildPresetCombo()
        {
            suppressEvents = true;
            cboPreset.Items.Clear();
            foreach (var p in BuiltinPresets) cboPreset.Items.Add(p);
            foreach (var p in userPresets) cboPreset.Items.Add(p);
            cboPreset.Items.Add(new PresetItem { Name = "(自訂)", Chars = null });
            suppressEvents = false;
            SyncPresetToText();
        }

        void SyncPresetToText()
        {
            suppressEvents = true;
            int match = -1;
            for (int i = 0; i < cboPreset.Items.Count; i++)
            {
                var p = (PresetItem)cboPreset.Items[i];
                if (p.Chars != null && p.Chars == txtSymbols.Text)
                {
                    // 若目前選的就是相符的規則就保留，否則選第一個相符的
                    if (cboPreset.SelectedIndex == i) { match = i; break; }
                    if (match < 0) match = i;
                }
            }
            cboPreset.SelectedIndex = match >= 0 ? match : cboPreset.Items.Count - 1;
            suppressEvents = false;
            UpdatePresetButtons();
        }

        void OnPresetChanged(object sender, EventArgs e)
        {
            if (suppressEvents) return;
            var p = cboPreset.SelectedItem as PresetItem;
            if (p != null && p.Chars != null)
            {
                suppressEvents = true;
                txtSymbols.Text = p.Chars;
                suppressEvents = false;
            }
            UpdatePresetButtons();
            UpdateInfo();
        }

        void UpdatePresetButtons()
        {
            var p = cboPreset.SelectedItem as PresetItem;
            btnDelPreset.Enabled = chkSymbol.Checked && p != null && p.IsUser;
        }

        void UpdateSymbolEnabled()
        {
            cboPreset.Enabled = txtSymbols.Enabled = btnSavePreset.Enabled = chkSymbol.Checked;
            UpdatePresetButtons();
        }

        void SaveUserPreset()
        {
            string chars = Generator.CleanSymbols(txtSymbols.Text, false);
            if (chars.Length == 0)
            {
                MessageBox.Show(this, "請先在右邊的欄位輸入要使用的符號。", "儲存規則", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var cur = cboPreset.SelectedItem as PresetItem;
            string name = InputBox("儲存符號規則", "替這組符號規則取個名字（例如網站名稱）：\n" + chars,
                cur != null && cur.IsUser ? cur.Name : "");
            if (name == null) return;
            name = name.Replace("=", "").Replace("\r", "").Replace("\n", "").Trim();
            if (name.Length == 0) return;

            var existing = userPresets.FirstOrDefault(p => p.Name == name);
            if (existing != null) existing.Chars = chars;
            else userPresets.Add(new PresetItem { Name = name, Chars = chars, IsUser = true });

            suppressEvents = true;
            txtSymbols.Text = chars;
            suppressEvents = false;
            RebuildPresetCombo();
            for (int i = 0; i < cboPreset.Items.Count; i++)
            {
                var p = (PresetItem)cboPreset.Items[i];
                if (p.IsUser && p.Name == name) { suppressEvents = true; cboPreset.SelectedIndex = i; suppressEvents = false; }
            }
            UpdatePresetButtons();
            SaveSettings();
            SetStatus("已儲存符號規則「" + name + "」");
        }

        void DeleteUserPreset()
        {
            var p = cboPreset.SelectedItem as PresetItem;
            if (p == null || !p.IsUser) return;
            if (MessageBox.Show(this, "確定要刪除符號規則「" + p.Name + "」嗎？", "刪除規則",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            userPresets.Remove(p);
            RebuildPresetCombo();
            SaveSettings();
            SetStatus("已刪除符號規則「" + p.Name + "」");
        }

        // ---------------- 產生 ----------------
        List<string> GetPools(out string error)
        {
            return Generator.BuildPools(chkDigit.Checked, chkUpper.Checked, chkLower.Checked, chkSymbol.Checked,
                txtSymbols.Text, chkConfusing.Checked, (int)numLen.Value, out error);
        }

        void UpdateInfo()
        {
            if (lblInfo == null || txtSymbols == null) return;
            string error;
            var pools = GetPools(out error);
            if (pools == null)
            {
                lblInfo.ForeColor = Color.Firebrick;
                lblInfo.Text = "⚠ " + error;
                return;
            }
            double bits = Generator.EntropyBits(pools, (int)numLen.Value);
            lblInfo.ForeColor = bits < 40 ? Color.Firebrick : bits < 60 ? Color.DarkOrange : Color.ForestGreen;
            lblInfo.Text = string.Format("可用字元：{0} 個　｜　每組約 {1:0} bits　｜　強度：{2}",
                pools.Sum(p => p.Length), bits, Generator.StrengthText(bits));
        }

        void DoGenerate()
        {
            string error;
            var pools = GetPools(out error);
            if (pools == null)
            {
                MessageBox.Show(this, error, "無法產生密碼", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            int len = (int)numLen.Value, count = (int)numCount.Value;
            double bits = Generator.EntropyBits(pools, len);
            var seen = new HashSet<string>(history.Select(h => h.Password));

            lvResult.BeginUpdate();
            lvResult.Items.Clear();
            for (int i = 0; i < count; i++)
            {
                string pw;
                int guard = 0;
                do { pw = Generator.Generate(len, pools, chkPattern.Checked); }
                while (seen.Contains(pw) && ++guard < 100);
                seen.Add(pw);

                var item = new ListViewItem((i + 1).ToString()) { Tag = pw, UseItemStyleForSubItems = false };
                item.SubItems.Add(pw);
                item.SubItems.Add(Generator.StrengthText(bits));
                item.SubItems.Add("");
                lvResult.Items.Add(item);
            }
            lvResult.Columns[1].Width = -1; // 依內容自動調整寬度
            if (lvResult.Columns[1].Width < 380) lvResult.Columns[1].Width = 380;
            lvResult.EndUpdate();
            if (lvResult.Items.Count > 0) { lvResult.Items[0].Selected = true; lvResult.Items[0].Focused = true; }
            SetStatus(string.Format("已產生 {0} 組 {1} 位密碼", count, len));
        }

        // ---------------- 複製與紀錄 ----------------
        bool SetClipboard(string text)
        {
            try
            {
                var data = new DataObject();
                data.SetData(DataFormats.UnicodeText, text);
                // 不讓密碼進入 Windows 剪貼簿歷程 (Win+V) 與雲端同步
                data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[] { 0, 0, 0, 0 }));
                data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
                data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
                Clipboard.SetDataObject(data, true, 5, 100);
                lastCopied = text;
                if (chkAutoClear.Checked) { clipTimer.Stop(); clipTimer.Start(); }
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "無法寫入剪貼簿：" + ex.Message, "複製失敗", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        void ClearClipboardIfOurs(bool showStatus)
        {
            try
            {
                if (lastCopied != null && Clipboard.ContainsText() && Clipboard.GetText() == lastCopied)
                {
                    Clipboard.Clear();
                    if (showStatus) SetStatus("已自動清除剪貼簿中的密碼");
                }
            }
            catch { }
            lastCopied = null;
        }

        void CopyResultItems(List<ListViewItem> items)
        {
            if (items.Count == 0) { SetStatus("請先選取要複製的密碼"); return; }
            var pws = items.Select(i => (string)i.Tag).ToList();
            if (!SetClipboard(string.Join(Environment.NewLine, pws))) return;
            foreach (var it in items)
            {
                AddHistory((string)it.Tag);
                it.SubItems[3].Text = "✔ 已複製";
                it.SubItems[3].ForeColor = Color.ForestGreen;
            }
            SaveHistory();
            RefreshHistoryList();
            SetStatus(items.Count == 1
                ? "已複製第 " + items[0].Text + " 組密碼到剪貼簿" + AutoClearSuffix()
                : "已複製 " + items.Count + " 組密碼到剪貼簿 (每行一組)" + AutoClearSuffix());
        }

        string AutoClearSuffix()
        {
            return chkAutoClear.Checked ? "，" + ClipboardClearSeconds + " 秒後自動清除" : "";
        }

        void AddHistory(string pw)
        {
            var old = history.FirstOrDefault(h => h.Password == pw);
            if (old != null) history.Remove(old);
            history.Insert(0, new HistoryItem { Time = DateTime.Now, Password = pw, Note = old != null ? old.Note : "" });
            if (history.Count > MaxHistoryCount) history.RemoveRange(MaxHistoryCount, history.Count - MaxHistoryCount);
        }

        void SaveHistory()
        {
            if (chkRemember.Checked) Store.SaveHistory(history);
        }

        void RefreshHistoryList()
        {
            if (lvHistory == null) return;
            var selected = new HashSet<HistoryItem>(lvHistory.SelectedItems.Cast<ListViewItem>().Select(i => (HistoryItem)i.Tag));
            lvHistory.BeginUpdate();
            lvHistory.Items.Clear();
            foreach (var h in history)
            {
                var item = new ListViewItem(h.Note ?? "") { Tag = h };
                item.SubItems.Add(chkShowHist.Checked ? h.Password : new string('•', Math.Min(h.Password.Length, 16)));
                item.SubItems.Add(h.Password.Length.ToString());
                item.SubItems.Add(h.Time.ToString("yyyy-MM-dd HH:mm:ss"));
                item.Selected = selected.Contains(h);
                lvHistory.Items.Add(item);
            }
            lvHistory.EndUpdate();
        }

        void CopyHistorySelected()
        {
            var items = lvHistory.SelectedItems.Cast<ListViewItem>().Select(i => (HistoryItem)i.Tag).ToList();
            if (items.Count == 0) return;
            if (!SetClipboard(string.Join(Environment.NewLine, items.Select(h => h.Password)))) return;
            SetStatus("已從紀錄複製 " + items.Count + " 組密碼" + AutoClearSuffix());
        }

        void EditHistoryNote()
        {
            if (lvHistory.SelectedItems.Count == 0) return;
            lvHistory.Focus();
            lvHistory.SelectedItems[0].BeginEdit();
        }

        void DeleteHistorySelected()
        {
            var items = lvHistory.SelectedItems.Cast<ListViewItem>().Select(i => (HistoryItem)i.Tag).ToList();
            if (items.Count == 0) return;
            if (MessageBox.Show(this, "確定要刪除選取的 " + items.Count + " 筆紀錄嗎？", "刪除紀錄",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            foreach (var h in items) history.Remove(h);
            SaveHistory();
            RefreshHistoryList();
            SetStatus("已刪除 " + items.Count + " 筆紀錄");
        }

        void OnRememberChanged(object sender, EventArgs e)
        {
            if (suppressEvents) return;
            if (chkRemember.Checked)
            {
                Store.SaveHistory(history);
                SetStatus("複製紀錄將加密儲存在本機");
            }
            else
            {
                if (MessageBox.Show(this, "之後的複製紀錄只會保留到關閉程式為止。\n要同時刪除已經存在本機的紀錄檔嗎？",
                    "不記住複製紀錄", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    Store.DeleteHistoryFile();
                    SetStatus("已刪除本機的複製紀錄檔");
                }
            }
            SaveSettings();
        }

        // ---------------- 設定 ----------------
        void LoadSettings()
        {
            var s = Store.LoadSettings();
            Func<string, string, string> get = (k, def) =>
            {
                foreach (var kv in s) if (kv.Key == k) return kv.Value;
                return def;
            };
            Func<string, bool, bool> getBool = (k, def) => get(k, def ? "1" : "0") == "1";
            Func<string, int, int, int, int> getInt = (k, def, min, max) =>
            {
                int v;
                if (!int.TryParse(get(k, def.ToString()), out v)) v = def;
                return Math.Max(min, Math.Min(max, v));
            };

            suppressEvents = true;
            numLen.Value = getInt("length", 16, 2, 99);
            numCount.Value = getInt("count", 5, 1, 10);
            chkDigit.Checked = getBool("digits", true);
            chkUpper.Checked = getBool("upper", true);
            chkLower.Checked = getBool("lower", true);
            chkSymbol.Checked = getBool("symbols", true);
            txtSymbols.Text = get("symbolChars", BuiltinPresets[0].Chars);
            chkConfusing.Checked = getBool("excludeConfusing", true);
            chkPattern.Checked = getBool("avoidPatterns", true);
            chkRemember.Checked = getBool("rememberHistory", true);
            chkAutoClear.Checked = getBool("autoClearClipboard", false);
            chkShowHist.Checked = false;
            userPresets.Clear();
            foreach (var kv in s)
                if (kv.Key.StartsWith("preset:") && kv.Key.Length > 7)
                    userPresets.Add(new PresetItem { Name = kv.Key.Substring(7), Chars = kv.Value, IsUser = true });
            suppressEvents = false;

            RebuildPresetCombo();
            UpdateSymbolEnabled();
        }

        void SaveSettings()
        {
            var s = new List<KeyValuePair<string, string>>();
            Action<string, string> put = (k, v) => s.Add(new KeyValuePair<string, string>(k, v));
            put("length", numLen.Value.ToString());
            put("count", numCount.Value.ToString());
            put("digits", chkDigit.Checked ? "1" : "0");
            put("upper", chkUpper.Checked ? "1" : "0");
            put("lower", chkLower.Checked ? "1" : "0");
            put("symbols", chkSymbol.Checked ? "1" : "0");
            put("symbolChars", txtSymbols.Text);
            put("excludeConfusing", chkConfusing.Checked ? "1" : "0");
            put("avoidPatterns", chkPattern.Checked ? "1" : "0");
            put("rememberHistory", chkRemember.Checked ? "1" : "0");
            put("autoClearClipboard", chkAutoClear.Checked ? "1" : "0");
            foreach (var p in userPresets) put("preset:" + p.Name, p.Chars);
            Store.SaveSettings(s);
        }

        void OnClosing(object sender, FormClosingEventArgs e)
        {
            SaveSettings();
            SaveHistory();
            if (chkAutoClear.Checked) ClearClipboardIfOurs(false);
        }

        void SetStatus(string text)
        {
            lblStatus.Text = DateTime.Now.ToString("HH:mm:ss") + "　" + text;
        }

        string InputBox(string title, string prompt, string defaultValue)
        {
            using (var f = new Form())
            {
                f.AutoScaleDimensions = new SizeF(96F, 96F);
                f.AutoScaleMode = AutoScaleMode.Dpi;
                f.Font = Font;
                f.Text = title;
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.StartPosition = FormStartPosition.CenterParent;
                f.MinimizeBox = f.MaximizeBox = false;
                f.ShowInTaskbar = false;
                f.ClientSize = new Size(360, 140);
                var lbl = new Label { Text = prompt, Location = new Point(12, 12), Size = new Size(336, 44) };
                var tb = new TextBox { Location = new Point(12, 62), Width = 336, Text = defaultValue };
                var ok = new Button { Text = "確定", DialogResult = DialogResult.OK, Location = new Point(192, 100), Size = new Size(75, 28) };
                var cancel = new Button { Text = "取消", DialogResult = DialogResult.Cancel, Location = new Point(273, 100), Size = new Size(75, 28) };
                f.Controls.AddRange(new Control[] { lbl, tb, ok, cancel });
                f.AcceptButton = ok;
                f.CancelButton = cancel;
                return f.ShowDialog(this) == DialogResult.OK ? tb.Text : null;
            }
        }
    }

    // ------------------------------------------------------------------
    // 自我檢查: PasswordGenerator.exe --selftest
    // ------------------------------------------------------------------
    static class SelfTest
    {
        public static int Run()
        {
            var log = new StringBuilder();
            int failures = 0;
            Action<bool, string> check = (ok, msg) => { if (!ok) { failures++; log.AppendLine("FAIL: " + msg); } };

            string err;
            var pools = Generator.BuildPools(true, true, true, true, "!@#$%^&*-_=+?", true, 16, out err);
            check(pools != null && pools.Count == 4, "build pools");

            for (int n = 0; n < 20000; n++)
            {
                int len = 2 + (n % 98);
                if (len < 4) len = 4;
                string pw = Generator.Generate(len, pools, true);
                check(pw.Length == len, "length " + len);
                check(pw.Any(char.IsDigit) && pw.Any(char.IsUpper) && pw.Any(char.IsLower) && pw.Any(c => !char.IsLetterOrDigit(c)), "categories: " + pw);
                check(pw.All(c => Generator.Confusing.IndexOf(c) < 0), "confusing: " + pw);
                for (int i = 1; i < pw.Length; i++)
                    check(char.ToLowerInvariant(pw[i]) != char.ToLowerInvariant(pw[i - 1]), "repeat: " + pw);
                for (int i = 2; i < pw.Length; i++)
                    check(!Generator.IsRun(pw[i - 2], pw[i - 1], pw[i]), "run: " + pw);
                if (failures > 10) break;
            }

            check(Generator.IsRun('a', 'b', 'c') && Generator.IsRun('3', '2', '1') && Generator.IsRun('q', 'w', 'e')
                  && Generator.IsRun('!', '@', '#') && Generator.IsRun('A', 's', 'D') && !Generator.IsRun('a', 'c', 'e'), "IsRun cases");

            var digitsOnly = Generator.BuildPools(true, false, false, false, "", true, 99, out err);
            string d = Generator.Generate(99, digitsOnly, true);
            check(d.Length == 99 && d.All(c => "23456789".IndexOf(c) >= 0), "digits only: " + d);

            var tooShort = Generator.BuildPools(true, true, true, true, "!", false, 3, out err);
            check(tooShort == null && err != null, "too short rejected");

            var single = Generator.BuildPools(false, false, false, true, "!", false, 5, out err);
            check(Generator.Generate(5, single, true) == "!!!!!", "single-char pool fallback");

            // 字元分布大致均勻 (卡方粗檢)
            var counts = new Dictionary<char, int>();
            string all = string.Concat(pools);
            foreach (char c in all) counts[c] = 0;
            for (int n = 0; n < 5000; n++) foreach (char c in Generator.Generate(20, pools, true)) counts[c]++;
            double expected = 5000.0 * 20 / all.Length;
            check(counts.Values.All(v => v > expected * 0.5 && v < expected * 1.6), "distribution");

            log.AppendLine(failures == 0 ? "ALL PASSED" : failures + " FAILURES");
            log.AppendLine("sample: " + Generator.Generate(16, pools, true) + "  " + Generator.Generate(24, pools, true));
            File.WriteAllText(Path.Combine(Path.GetTempPath(), "pwgen-selftest.txt"), log.ToString());
            return failures == 0 ? 0 : 1;
        }
    }
}
