import os
import threading
import time
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Input, Tree, Button, Label, ProgressBar, DirectoryTree
from textual.containers import Horizontal, Vertical, VerticalScroll, Grid
from textual.message import Message
from textual.binding import Binding
from textual.screen import Screen, ModalScreen

from textual.widgets import Sparkline
# pyrefly: ignore [missing-import]
from textual_plotext import PlotextPlot

class PacketMessage(Message):
    def __init__(self, packet_features: dict, flow_features: dict, decoded_info: dict, ml_prediction: dict = None):
        self.packet_features = packet_features
        self.flow_features = flow_features
        self.decoded_info = decoded_info
        self.ml_prediction = ml_prediction
        super().__init__()

class FlowUpdateMessage(Message):
    def __init__(self, flows: list):
        self.flows = flows
        super().__init__()

class StatsMessage(Message):
    def __init__(self, stats: dict):
        self.stats = stats
        super().__init__()

class ForecastMessage(Message):
    def __init__(self, forecast: dict):
        self.forecast = forecast
        super().__init__()

class FileAnalysisProgressMessage(Message):
    def __init__(self, message: str, percentage: int):
        self.message = message
        self.percentage = percentage
        super().__init__()

class FileAnalysisCompleteMessage(Message):
    def __init__(self, results: dict):
        self.results = results
        super().__init__()


class HelpModal(ModalScreen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Dismiss"),
        ("question_mark", "app.pop_screen", "Dismiss"),
    ]
    
    def compose(self) -> ComposeResult:
        with Vertical(id="help-modal-container"):
            yield Static("[bold #7aa2f7]Keyboard Shortcuts[/bold]", classes="section-title")
            yield Static("Press [b]?[/b] or [b]Esc[/b] to close this dialog.\n", id="help-subtitle")
            
            with Grid(id="help-grid"):
                yield Static("[bold]Data Actions[/bold]", classes="help-category")
                yield Static("")
                yield Static("[b]l[/b]", classes="help-key")
                yield Static("Live Network Capture", classes="help-desc")
                yield Static("[b]a[/b]", classes="help-key")
                yield Static("Analyze Offline PCAP/CSV", classes="help-desc")
                yield Static("[b]n[/b]", classes="help-key")
                yield Static("View Captured Traffic Table", classes="help-desc")
                
                yield Static("[bold]Playback Controls[/bold]", classes="help-category")
                yield Static("")
                yield Static("[b]Space[/b]", classes="help-key")
                yield Static("Pause / Resume", classes="help-desc")
                
                yield Static("[bold]View Controls[/bold]", classes="help-category")
                yield Static("")
                yield Static("[b]d[/b]", classes="help-key")
                yield Static("Dashboard", classes="help-desc")
                yield Static("[b]ctrl+p[/b]", classes="help-key")
                yield Static("Command Palette", classes="help-desc")
                yield Static("[b]?[/b]", classes="help-key")
                yield Static("Show Help", classes="help-desc")
                
                yield Static("[bold]App Controls[/bold]", classes="help-category")
                yield Static("")
                yield Static("[b]q[/b]", classes="help-key")
                yield Static("Quit Application", classes="help-desc")


class CustomFooter(Horizontal):
    def compose(self) -> ComposeResult:
        with Horizontal(classes="footer-group"):
            yield Static("l", id="key-l", classes="footer-key-chip")
            yield Static("Live Capture", classes="footer-label")
            yield Static("a", id="key-a", classes="footer-key-chip")
            yield Static("Analyze File", classes="footer-label")
            yield Static("r", id="key-r", classes="footer-key-chip")
            yield Static("Reset State", classes="footer-label")
            yield Static("n", id="key-n", classes="footer-key-chip")
            yield Static("Traffic Table", classes="footer-label")
            
        yield Static("", classes="footer-divider")
        
        with Horizontal(classes="footer-group"):
            yield Static("space", id="key-space", classes="footer-key-chip")
            yield Static("Pause/Resume", classes="footer-label")
            
        yield Static("", classes="footer-divider")
        
        with Horizontal(classes="footer-group"):
            yield Static("d", id="key-d", classes="footer-key-chip")
            yield Static("Dashboard", classes="footer-label")
            yield Static("?", id="key-question_mark", classes="footer-key-chip")
            yield Static("Help", classes="footer-label")
            yield Static("q", id="key-q", classes="footer-key-chip")
            yield Static("Quit", classes="footer-label")
            
        yield Static("", classes="footer-spacer")
        
        with Horizontal(classes="footer-group palette-group"):
            yield Static("^p", id="key-ctrl_p", classes="footer-key-chip")
            yield Static("palette", classes="footer-label")

    def flash_key(self, key_id: str):
        try:
            chip = self.query_one(f"#{key_id}")
            chip.add_class("flash-active")
            def remove_flash():
                chip.remove_class("flash-active")
            self.set_timer(0.15, remove_flash)
        except:
            pass


class DashboardScreen(Screen):
    BINDINGS = [
        ("n", "switch_to_capture", "Network Capture"),
        ("a", "switch_to_analyze", "Analyze File"),
        ("space", "toggle_pause", "Pause/Resume"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="stats-bar")
        
        with Horizontal(id="kpi-container"):
            yield Static("Packets/sec\n[bold]0[/]", id="kpi-pps", classes="kpi-card")
            yield Static("Bytes/sec\n[bold]0[/]", id="kpi-bps", classes="kpi-card")
            yield Static("Active Flows\n[bold]0[/]", id="kpi-flows", classes="kpi-card")
            yield Static("Model Status\n[bold yellow]WARMING UP 0/60[/]", id="kpi-model", classes="kpi-card")
            
        with Horizontal(id="main-dashboard"):
            # ── Left column: charts + traffic ──
            with Vertical(classes="dash-col"):
                yield Static("Traffic rate (pkt/s)", classes="panel-header")
                yield PlotextPlot(id="plot-traffic", classes="chart-panel")
                yield Static("Attack probability", classes="panel-header")
                yield PlotextPlot(id="plot-attack", classes="chart-panel")
                yield Static("Live network traffic", classes="panel-header")
                yield DataTable(id="dashboard-packet-table", classes="traffic-table")
                    
            # ── Right column: state + forecast + protocol + drivers ──
            with Vertical(classes="dash-col"):
                yield Static("Current network state", classes="panel-header")
                yield Static("Awaiting model warm-up…", id="state-panel", classes="state-panel")
                yield Static("Forecast timeline", classes="panel-header")
                yield Static("Awaiting model warm-up…", id="forecast-panel", classes="state-panel")
                yield Static("Protocol distribution", classes="panel-header")
                yield Static("Awaiting traffic data…", id="protocol-panel", classes="proto-panel")
                yield Static("Top drivers (explainability)", classes="panel-header")
                yield Static("Awaiting model warm-up…", id="explainability-panel", classes="drivers-panel")
                
        yield CustomFooter()

    def on_mount(self) -> None:
        table = self.query_one("#dashboard-packet-table", DataTable)
        table.add_column("Time", width=10)
        table.add_column("Source", width=18)
        table.add_column("Destination", width=18)
        table.add_column("Proto", width=6)
        table.add_column("Port", width=14)
        table.cursor_type = "row"
        table.zebra_stripes = True

class NetworkCaptureScreen(Screen):
    BINDINGS = [
        ("d", "switch_to_dashboard", "Dashboard"),
        ("f", "focus_filter", "Filter"),
        ("c", "clear_filter", "Clear Filter"),
        ("space", "toggle_pause", "Pause/Resume"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Filter (e.g., tcp, udp, port 443, host 192.168.1.1)", id="filter-input", classes="hidden")
        
        with Horizontal(id="capture-container"):
            yield DataTable(id="packet-table", classes="packet-table")
            yield Tree("Select a packet for deep inspection", id="details-tree", classes="details-tree")
            
        yield CustomFooter()

    def on_mount(self) -> None:
        packet_table = self.query_one("#packet-table", DataTable)
        packet_table.cursor_type = "row"
        packet_table.zebra_stripes = True
        packet_table.add_column("Time")
        packet_table.add_column("Source")
        packet_table.add_column("Destination")
        packet_table.add_column("Protocol")
        packet_table.add_column("Port")
        packet_table.add_column("Size")
        packet_table.add_column("Info")
        self.query_one("#details-tree", Tree).root.expand()


class FileExplorerScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DirectoryTree("/home", id="dir-tree")
        yield CustomFooter()
        
    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(str(event.path))


class AnalyzeFileScreen(Screen):
    BINDINGS = [
        ("d", "switch_to_dashboard", "Dashboard"),
        ("escape", "switch_to_dashboard", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        self.selected_filepath = None
        yield Header()
        with Vertical(id="analyze-container"):
            yield Static("[bold]Analyze Offline CSV/PCAP File[/bold]\n", classes="section-title")
            yield Label("Select a .csv or .pcap file to analyze:")
            with Horizontal(id="file-input-container"):
                yield Button("Browse File Explorer...", id="btn-browse")
                yield Label("No file selected", id="selected-file-label")
            yield Button("Run Analysis", id="btn-analyze", variant="primary")
            
            yield Static("", id="analysis-status", classes="hidden")
            yield ProgressBar(total=100, show_eta=False, id="analysis-progress", classes="hidden")
            
        yield CustomFooter()

class HelpModal(ModalScreen):
    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[bold]Keyboard Shortcuts[/bold]", classes="section-title"),
            Label("?     - Show this help menu\nq     - Quit the application\nd     - Switch to the Main Dashboard\nl     - Resume Live Capture\nn     - Switch to Network Capture (detailed view)\na     - Analyze Offline File (PCAP/CSV)\nr     - Reset internal state/memory\nspace - Pause/Resume the live feed"),
            Button("Close", variant="primary", id="close-help"),
            id="help-dialog"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-help":
            self.app.pop_screen()

class AnalysisResultsScreen(Screen):
    BINDINGS = [
        ("d", "switch_to_dashboard", "Dashboard"),
        ("a", "switch_to_analyze", "New Analysis"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="results-container"):
            yield Static("[bold]Analysis Results[/bold]", id="results-title", classes="section-title")
            yield Static("Summary stats...", id="results-summary", classes="info-panel")
            yield Static("[bold]Attack Timeline[/bold]", classes="section-title")
            yield Sparkline([0], id="results-sparkline", summary_function=max)
            yield Static("[bold]Predictions Over Time[/bold]", classes="section-title")
            yield DataTable(id="results-table")
        yield CustomFooter()

    def on_mount(self):
        table = self.query_one("#results-table", DataTable)
        table.add_columns("Timestamp", "Target", "Current Prediction", "Attack Prob", "MITRE", "+30s Forecast")
        table.cursor_type = "row"


class TrafficMonitorApp(App):
    TITLE = "Temporal Network Threat Forecasting CLI (TNTF-CLI)"
    SUB_TITLE = "Real-time AI Inference Dashboard"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "switch_to_dashboard", "Dashboard"),
        ("l", "resume_live", "Live Capture"),
        ("n", "switch_to_capture", "Network Capture"),
        ("a", "switch_to_analyze", "Analyze File"),
        ("r", "reset_state", "Reset State"),
        ("space", "toggle_pause", "Pause/Resume"),
    ]

    CSS = """
    /* ══════════════════════════════════════════════
       Tokyo Night Theme — Design Tokens
       bg-base:    #1a1b26    (app shell)
       bg-panel:   #1f2335    (panel bodies)
       bg-surface: #24283b    (elevated elements)
       border:     #2a2e3f    (all borders)
       fg:         #c0caf5    (primary text)
       fg-muted:   #565f89    (secondary text)
       accent:     #7aa2f7    (headers, highlights)
       ok:         #9ece6a    (benign / good state)
       alert:      #f7768e    (threat / attack)
       warn:       #e0af68    (warnings)
       chart-1:    #7dcfff    (TCP)
       chart-2:    #e0af68    (UDP)
       chart-3:    #bb9af7    (ARP)
       chart-4:    #f7768e    (Other)
       ══════════════════════════════════════════════ */

    Screen {
        background: #1a1b26;
        color: #c0caf5;
    }
    .hidden {
        display: none;
    }
    
    HelpModal {
        align: center middle;
        background: rgba(26, 27, 38, 0.7);
    }
    #help-dialog {
        padding: 1 2;
        width: 60;
        height: auto;
        background: #1f2335;
        border: solid #7aa2f7;
    }
    #close-help {
        margin-top: 1;
        width: 100%;
    }

    /* ── Top bar ── */
    #stats-bar {
        height: 1;
        background: #1a1b26;
        content-align: center middle;
        color: #565f89;
    }
    #kpi-container {
        height: 5;
        margin: 0 1;
    }
    .kpi-card {
        width: 1fr;
        height: 100%;
        background: #1f2335;
        content-align: center middle;
        margin: 0 1;
        border-top: tall #7aa2f7;
        color: #c0caf5;
    }

    /* ── Dashboard body ── */
    #main-dashboard {
        height: 1fr;
        padding: 0 1;
        margin-top: 1;
    }
    .dash-col {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
    }

    /* ── Panel headers (consistent everywhere) ── */
    .panel-header {
        background: #24283b;
        color: #7aa2f7;
        width: 100%;
        height: 1;
        padding: 0 1;
        margin-top: 1;
        text-style: bold;
    }
    .panel-header:first-child {
        margin-top: 0;
    }

    /* ── Charts ── */
    .chart-panel {
        height: 2fr;
        background: #1f2335;
        border: solid #2a2e3f;
        border-top: none;
        margin-bottom: 0;
    }

    /* ── Fixed-height state panels (never collapse) ── */
    .state-panel {
        background: #1f2335;
        border: solid #2a2e3f;
        border-top: none;
        padding: 1 2;
        height: 9;
        margin-bottom: 0;
        color: #c0caf5;
    }

    /* ── Protocol distribution panel ── */
    .proto-panel {
        background: #1f2335;
        border: solid #2a2e3f;
        border-top: none;
        padding: 1;
        height: 8;
        margin-bottom: 0;
        color: #c0caf5;
    }

    /* ── Drivers panel ── */
    .drivers-panel {
        background: #1f2335;
        border: solid #2a2e3f;
        border-top: none;
        padding: 1;
        height: 1fr;
        color: #c0caf5;
    }

    /* ── Live packet table (fixed height, own scroll) ── */
    .traffic-table {
        height: 1fr;
        min-height: 12;
        max-height: 14;
        background: #1f2335;
        border: solid #2a2e3f;
        border-top: none;
        margin-bottom: 0;
    }

    /* ── Capture screen ── */
    #capture-container {
        height: 1fr;
        padding: 1;
    }
    .packet-table {
        width: 70%;
        height: 1fr;
        border-right: solid #2a2e3f;
        background: #1f2335;
    }
    .details-tree {
        width: 30%;
        height: 1fr;
        padding: 1;
        background: #1f2335;
    }

    /* ── Analyze screen ── */
    #analyze-container {
        align: center middle;
        width: 60%;
        height: auto;
        border: panel #7aa2f7;
        background: #1f2335;
        padding: 2 4;
        margin: 4;
    }
    #file-input-container {
        height: auto;
        margin: 1 0 2 0;
        layout: horizontal;
        align: left middle;
    }
    #btn-browse {
        min-width: 15;
        margin-right: 2;
    }
    #selected-file-label {
        color: #7aa2f7;
        padding-top: 1;
    }
    #btn-analyze {
        width: 100%;
        margin-top: 1;
    }

    /* ── Results screen ── */
    #results-container {
        padding: 2;
        background: #1a1b26;
    }

    /* ── Info panels (results/other screens) ── */
    .info-panel {
        border: panel #2a2e3f;
        background: #1f2335;
        padding: 1;
        height: auto;
        margin-bottom: 1;
    }
    .section-title {
        background: #1f2335;
        color: #7aa2f7;
        width: 100%;
        height: 1;
        padding: 0 1;
        margin: 0;
        text-style: bold;
        border-bottom: solid #2a2e3f;
    }

    /* ── Sparkline (results screen only) ── */
    Sparkline {
        height: 3;
        margin-bottom: 1;
        color: #7aa2f7;
    }

    /* ── Custom Footer / Help Modal ── */
    CustomFooter {
        dock: bottom;
        width: 100%;
        height: 3;
        background: #1a1b26;
        align-vertical: middle;
        padding: 0 1;
    }
    .footer-group {
        height: 3;
        width: auto;
        align-vertical: middle;
    }
    .palette-group {
        dock: right;
    }
    .footer-key-chip {
        width: auto;
        height: auto;
        border: solid #565f89;
        color: #c0caf5;
        background: #1a1b26;
        padding: 0 1;
        margin: 0 1;
        text-style: bold;
    }
    .footer-key-chip.flash-active {
        background: #7aa2f7;
        color: #1a1b26;
        border: solid #7aa2f7;
    }
    .footer-label {
        width: auto;
        height: 1;
        color: #565f89;
        margin: 1 1 1 0;
    }
    .footer-divider {
        width: 1;
        height: 1;
        background: #2a2e3f;
        margin: 1 1;
    }
    .footer-spacer {
        width: 1fr;
        height: 1;
    }
    
    #help-modal-container {
        width: 60%;
        height: 80%;
        background: #1f2335;
        border: panel #7aa2f7;
        align: center top;
        padding: 2 4;
    }
    #help-grid {
        grid-size: 2;
        grid-columns: 10 1fr;
        grid-rows: auto;
        margin-top: 1;
    }
    .help-category {
        color: #7dcfff;
        margin-top: 1;
        border-bottom: solid #2a2e3f;
        padding-bottom: 1;
        column-span: 2;
    }
    .help-key {
        border: solid #565f89;
        color: #c0caf5;
        padding: 0 1;
        margin-right: 2;
        width: 100%;
        text-align: center;
    }
    .help-desc {
        color: #a9b1d6;
        margin-top: 1;
    }
    """

    def __init__(self, interface: str, start_time: str, reset_callback=None, app_context=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.interface = interface if interface else "Auto"
        self.start_time = start_time
        self.is_paused = False
        self.packet_buffer = []
        self.max_packets = 5000
        self.app_context = app_context # Ref to main loop for triggering things
        self.reset_callback = reset_callback
        
        # Chart data buffers
        self.traffic_history = [0] * 50
        self.attack_history = [0.0] * 50
        
        self.filter_text = ""

    def on_mount(self) -> None:
        self.install_screen(DashboardScreen(), name="dashboard")
        self.install_screen(NetworkCaptureScreen(), name="capture")
        self.install_screen(AnalyzeFileScreen(), name="analyze")
        self.install_screen(AnalysisResultsScreen(), name="results")
        self.push_screen("dashboard")

    def on_key(self, event) -> None:
        key = event.key
        key_map = {
            "q": "key-q",
            "l": "key-l",
            "n": "key-n",
            "a": "key-a",
            "space": "key-space",
            "d": "key-d",
            "r": "key-r",
            "question_mark": "key-question_mark",
            "ctrl+p": "key-ctrl_p"
        }
        if key in key_map:
            try:
                footer = self.screen.query_one(CustomFooter)
                footer.flash_key(key_map[key])
            except:
                pass
        
        # Globally push HelpModal when ? is pressed
        if key == "question_mark":
            self.push_screen(HelpModal())

    def action_resume_live(self) -> None:
        if self.app_context and hasattr(self.app_context, 'resume_live_capture'):
            self.app_context.resume_live_capture()
        self.switch_screen("dashboard")

    def action_switch_to_dashboard(self) -> None:
        self.switch_screen("dashboard")

    def action_switch_to_capture(self) -> None:
        self.switch_screen("capture")

    def action_switch_to_analyze(self) -> None:
        self.switch_screen("analyze")

    def action_toggle_pause(self) -> None:
        self.is_paused = not self.is_paused
        self.notify("Display Paused" if self.is_paused else "Display Resumed")

    # ----- Network Capture Handlers -----
    def action_focus_filter(self) -> None:
        try:
            filter_input = self.query_one("#filter-input", Input)
            if filter_input.has_class("hidden"):
                filter_input.remove_class("hidden")
                filter_input.focus()
            else:
                filter_input.add_class("hidden")
                self.query_one("#packet-table", DataTable).focus()
        except:
            pass

    def action_clear_filter(self) -> None:
        self.filter_text = ""
        try:
            inp = self.query_one("#filter-input", Input)
            inp.value = ""
            inp.add_class("hidden")
            self._apply_filter()
            self.query_one("#packet-table", DataTable).focus()
        except:
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter-input":
            self.filter_text = event.value.strip().lower()
            event.input.add_class("hidden")
            self._apply_filter()
            try:
                self.query_one("#packet-table", DataTable).focus()
            except:
                pass

    def _match_filter(self, packet_info: dict) -> bool:
        if not self.filter_text: return True
        ft = self.filter_text
        p = packet_info['packet']
        d = packet_info['decoded_info']
        proto = (d.get('protocol') or "").lower()
        src_ip = p.get('src_ip') or ""
        dst_ip = p.get('dst_ip') or ""
        src_port = str(p.get('src_port') or "")
        dst_port = str(p.get('dst_port') or "")
        
        if ft in ["tcp", "udp", "icmp", "arp", "dns", "http", "tls"]: return ft in proto
        if ft.startswith("port "):
            parts = ft.split(" ")
            if len(parts) > 1: return parts[1] == src_port or parts[1] == dst_port
        if ft.startswith("host "):
            parts = ft.split(" ")
            if len(parts) > 1: return parts[1] == src_ip or parts[1] == dst_ip
        return ft in proto or ft in src_ip or ft in dst_ip

    def _apply_filter(self) -> None:
        try:
            table = self.query_one("#packet-table", DataTable)
            table.clear()
            for packet_info in self.packet_buffer:
                if self._match_filter(packet_info):
                    self._add_packet_to_table(packet_info, table)
        except:
            pass

    def _add_packet_to_table(self, packet_info: dict, table: DataTable) -> None:
        p = packet_info['packet']
        d = packet_info['decoded_info']
        ts = datetime.fromtimestamp(p['timestamp']).strftime('%H:%M:%S.%f')[:-3]
        src = d.get('source', '')
        dst = d.get('destination', '')
        
        sp = p.get('src_port')
        dp = p.get('dst_port')
        port = f"{sp}->{dp}" if (sp is not None and dp is not None) else ""
        
        row_key = str(p['packet_number'])
        if row_key not in table.rows:
            table.add_row(ts, src, dst, d.get('protocol', 'OTHER'), port, str(p.get('packet_length', '')), d.get('info', ''), key=row_key)

    def action_reset_state(self) -> None:
        # Clear chart buffers
        self.traffic_history = [0] * 50
        self.attack_history = [0.0] * 50
        
        # Clear packet buffers
        self.packet_buffer.clear()
        try:
            table = self.screen.query_one("#dashboard-packet-table", DataTable)
            table.clear()
        except:
            pass
            
        try:
            pkt_table = self.screen.query_one("#packet-table", DataTable)
            pkt_table.clear()
        except:
            pass
            
        # Reset KPI visual state
        try:
            self.screen.query_one("#kpi-pps", Static).update("Packets/sec\n[bold]0[/]")
            self.screen.query_one("#kpi-bps", Static).update("Bytes/sec\n[bold]0[/]")
            self.screen.query_one("#kpi-flows", Static).update("Active Flows\n[bold]0[/]")
            self.screen.query_one("#kpi-model", Static).update("Model Status\n[bold yellow]WARMING UP 0/60[/]")
            
            self.screen.query_one("#state-panel", Static).update("Awaiting model warm-up…")
            self.screen.query_one("#forecast-panel", Static).update("Awaiting model warm-up…")
            self.screen.query_one("#protocol-panel", Static).update("Awaiting traffic data…")
            self.screen.query_one("#explainability-panel", Static).update("Awaiting model warm-up…")
            
            plot_attack = self.screen.query_one("#plot-attack", PlotextPlot)
            plot_attack.plt.clear_figure()
            plot_attack.refresh()
            
            plot_traffic = self.screen.query_one("#plot-traffic", PlotextPlot)
            plot_traffic.plt.clear_figure()
            plot_traffic.refresh()
        except:
            pass
            
        # Trigger background state clear
        if self.reset_callback:
            self.reset_callback()

    def on_packet_message(self, message: PacketMessage) -> None:
        packet_info = {
            'packet': message.packet_features, 
            'flow': message.flow_features,
            'decoded_info': message.decoded_info,
            'ml_prediction': message.ml_prediction
        }
        self.packet_buffer.append(packet_info)
        if len(self.packet_buffer) > self.max_packets:
            self.packet_buffer.pop(0)
            
        if self.is_paused: return
        
        # Add to Dashboard Mini-Table
        try:
            d_table = self.screen.query_one("#dashboard-packet-table", DataTable)
            p = packet_info['packet']
            d = packet_info['decoded_info']
            ts = datetime.fromtimestamp(p['timestamp']).strftime('%H:%M:%S')
            src = d.get('source', '')
            dst = d.get('destination', '')
            
            sp = p.get('src_port')
            dp = p.get('dst_port')
            port = f"{sp}->{dp}" if (sp is not None and dp is not None) else ""
            row_key = str(p['packet_number'])
            
            if row_key not in d_table.rows:
                d_table.add_row(ts, src, dst, d.get('protocol', 'OTHER'), port, key=row_key)
                if len(d_table.rows) > 100:
                    first_key = list(d_table.rows.keys())[0]
                    d_table.remove_row(first_key)
                d_table.scroll_end(animate=False)
        except:
            pass
            
        # Add to Network Capture Full Table
        try:
            table = self.screen.query_one("#packet-table", DataTable)
            if self._match_filter(packet_info):
                self._add_packet_to_table(packet_info, table)
                table.scroll_end(animate=False)
        except:
            pass # Not on capture screen

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.control.id in ["packet-table", "dashboard-packet-table"]:
            packet_number = int(event.row_key.value)
            packet_info = next((pi for pi in self.packet_buffer if pi['packet']['packet_number'] == packet_number), None)
            if packet_info:
                if event.control.id == "dashboard-packet-table":
                    self.switch_screen("capture")
                self._render_details(packet_info['packet'], packet_info['flow'], packet_info['decoded_info'], packet_info.get('ml_prediction'))

    def _render_details(self, p: dict, f: dict, d: dict, m: dict = None) -> None:
        try:
            tree = self.screen.query_one("#details-tree", Tree)
            tree.clear()
            tree.root.label = f"[bold]Packet Inspector[/bold]"
            
            for layer in d.get('tree', []):
                layer_node = tree.root.add(f"[bold]{layer['name']}[/bold]", expand=True)
                for k, v in layer['details'].items():
                    layer_node.add_leaf(f"{k}: {v}")
                    
            tree.root.expand()
        except:
            pass

    # ----- Stats & Forecast Handlers -----
    def on_stats_message(self, message: StatsMessage) -> None:
        stats = message.stats
        self.traffic_history.append(stats.get('packet_count', 0))
        if len(self.traffic_history) > 50: self.traffic_history.pop(0)
        
        try:
            self.screen.query_one("#stats-bar", Static).update(f"Interface: {self.interface}  |  Started: {self.start_time}")
            self.screen.query_one("#kpi-pps", Static).update(f"Packets/sec\n[bold #9ece6a]{stats.get('packets_per_sec', 0):.1f}[/]")
            self.screen.query_one("#kpi-bps", Static).update(f"Bytes/sec\n[bold #9ece6a]{stats.get('bytes_per_sec', 0):.1f}[/]")
            self.screen.query_one("#kpi-flows", Static).update(f"Active Flows\n[bold #c0caf5]{stats.get('active_flows_count', 0)}[/]")
            
            # ── Traffic Rate Line Chart ──
            plot_traffic = self.screen.query_one("#plot-traffic", PlotextPlot)
            diffs = [max(0, self.traffic_history[i] - self.traffic_history[i-1]) for i in range(1, len(self.traffic_history))]
            if not diffs: diffs = [0]
            
            plt = plot_traffic.plt
            plt.clear_figure()
            plt.theme('dark')
            plt.plot(diffs, color='blue', marker='braille')
            max_y = max(max(diffs), 1)
            plt.ylim(0, max_y * 1.1)
            plt.xlim(0, len(diffs))
            plt.xticks([i for i in range(0, len(diffs) + 1, 5)])
            plt.grid(True, True)
            plot_traffic.refresh()
            
            # ── Protocol Distribution (Rich text bars) ──
            protos = stats.get('protocols', {})
            proto_panel = self.screen.query_one("#protocol-panel", Static)
            if protos:
                total = sum(protos.values()) + 1e-9
                proto_pct = {k: (v / total) * 100 for k, v in protos.items()}
                sorted_protos = sorted(proto_pct.items(), key=lambda x: x[1], reverse=True)
                
                # Fixed color map (Tokyo Night chart colors)
                color_map = {
                    'TCP': '#7dcfff', 'TLS': '#7dcfff',
                    'UDP': '#e0af68', 'DNS': '#e0af68',
                    'ARP': '#bb9af7',
                    'ICMP': '#9ece6a', 'IPv4': '#9ece6a',
                }
                default_colors = ['#f7768e', '#ff9e64', '#7dcfff', '#bb9af7']
                
                lines = []
                for i, (proto, pct) in enumerate(sorted_protos[:6]):
                    c = color_map.get(proto, default_colors[i % len(default_colors)])
                    bar_len = int(pct / 100 * 30)  # max 30 chars wide
                    bar = "█" * max(bar_len, 1)
                    lines.append(f"[#565f89]{proto[:14]:<14}[/] [{c}]{bar}[/] [{c}]{pct:.0f}%[/]")
                proto_panel.update("\n".join(lines))
            else:
                proto_panel.update("[#565f89]Awaiting traffic data…[/]")
        except:
            pass

    def on_forecast_message(self, message: ForecastMessage) -> None:
        if self.is_paused: return
        f = message.forecast
        
        try:
            kpi_model = self.screen.query_one("#kpi-model", Static)
            
            # ── Attack Timeline Line Chart ──
            is_warming = f.get('is_warming_up', False)
            if is_warming:
                kpi_model.update(f"Model Status\n[bold #e0af68]WARMING UP {f['current_count']}/{f['required_count']}[/]")
            else:
                kpi_model.update("Model Status\n[bold #9ece6a]ACTIVE[/]")
                attack_prob = f.get('attack_probability', 0.0)
                self.attack_history.append(attack_prob)
                if len(self.attack_history) > 50: self.attack_history.pop(0)
            
            plot_attack = self.screen.query_one("#plot-attack", PlotextPlot)
            plt_a = plot_attack.plt
            plt_a.clear_figure()
            plt_a.theme('dark')
            
            history_pct = [x * 100 for x in self.attack_history]
            current_prob_pct = history_pct[-1] if history_pct else 0
            line_color = 'red' if current_prob_pct >= 50.0 else 'blue'
            
            plt_a.plot(history_pct, color=line_color, marker='braille')
            plt_a.ylim(0, 105)
            plt_a.xlim(0, len(history_pct))
            plt_a.yticks([0, 25, 50, 75, 100], ['0%', '25%', '50%', '75%', '100%'])
            plt_a.xticks([i for i in range(0, len(history_pct) + 1, 5)])
            plt_a.grid(True, True)
            plot_attack.refresh()
            
            if is_warming:
                return
            
            # ── Current Network State ──
            pred = f.get('current_prediction', 'Benign')
            if pred == "Benign":
                pred_badge = "[bold white on #9ece6a] BENIGN [/]"
            elif pred == "Suspected":
                pred_badge = "[bold white on #e0af68] SUSPICIOUS [/]"
            else:
                pred_badge = f"[bold white on #f7768e] {pred.upper()} [/]"
            
            state_lines = []
            state_lines.append(f"[#565f89]{'Prediction':<14}[/] {pred_badge}")
            state_lines.append(f"[#565f89]{'Attack prob':<14}[/] [bold #7aa2f7]{attack_prob*100:.1f}%[/]")
            state_lines.append(f"[#565f89]{'Threat Level':<14}[/] [bold #7aa2f7]{f.get('threat_level', 'Normal')}[/]")
            state_lines.append("")
            
            mitre_t = f.get('mitre_tactic', 'N/A')
            mitre_s = f.get('attack_progression', 'N/A')
            if mitre_t != 'N/A':
                state_lines.append(f"[#565f89]{'MITRE Tactic':<14}[/] [bold #7aa2f7]{mitre_t}[/]")
                state_lines.append(f"[#565f89]{'MITRE Stage':<14}[/] [bold #7aa2f7]{mitre_s}[/]")
            else:
                state_lines.append(f"[#565f89]{'MITRE Tactic':<14}[/] [#565f89]None[/]")
                state_lines.append(f"[#565f89]{'MITRE Stage':<14}[/] [#565f89]Normal[/]")
                
            self.screen.query_one("#state-panel", Static).update("\n".join(state_lines))
            
            # ── Forecast Timeline ──
            fc_lines = []
            probs = f.get('probabilities', {})
            prev_prob = attack_prob * 100
            
            fc_lines.append("[bold #7aa2f7]CLASS PROBABILITY:[/]")
            fc_lines.append("")
            
            for horizon in ['future_5s', 'future_10s', 'future_15s', 'future_30s', 'future_60s']:
                if horizon in probs:
                    h_probs = probs[horizon]
                    h_idx = h_probs.argmax()
                    h_class = f['label_map_inverse'].get(h_idx, 'Unknown')
                    h_prob = h_probs[h_idx] * 100
                    h_color = "#9ece6a" if h_class == "Benign" else "#f7768e"
                    
                    trend = "[#565f89]→[/]"
                    if h_prob > prev_prob + 1.0: trend = "[#f7768e]↗[/]"
                    elif h_prob < prev_prob - 1.0: trend = "[#9ece6a]↘[/]"
                    
                    fc_lines.append(f"[#565f89]{horizon:<12}[/] [{h_color}]{h_class:<13}[/] {trend} [{h_color}]{h_prob:>5.1f}%[/]")
                    prev_prob = h_prob
            self.screen.query_one("#forecast-panel", Static).update("\n".join(fc_lines) if len(fc_lines) > 2 else "[#565f89]Awaiting predictions…[/]")
            
            # ── Explainability (Top Drivers) ──
            importance = f.get('feature_importance', {})
            drv_lines = []
            if importance:
                max_score = max(list(importance.values())[:6]) + 1e-9
                # Tokyo Night palette for distinct bar colors
                palette = ['#7dcfff', '#e0af68', '#bb9af7', '#9ece6a', '#f7768e', '#ff9e64', '#0db9d7', '#b4f9f8']
                
                for feat, score in list(importance.items())[:6]:
                    c_idx = sum(ord(c) for c in feat) % len(palette)
                    c = palette[c_idx]
                    
                    bar_len = int((score / max_score) * 30)
                    bar = "█" * max(bar_len, 1)
                    label = (feat[:13] + '…') if len(feat) > 14 else feat
                    drv_lines.append(f"[#565f89]{label:<14}[/] [{c}]{bar}[/] [{c}]{score*100:.1f}%[/]")
            else:
                drv_lines.append("[#565f89]No attack detected.[/]")
            self.screen.query_one("#explainability-panel", Static).update("\n".join(drv_lines))
        except:
            pass
    # ----- File Analyzer -----
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-browse":
            def set_file(path: str | None) -> None:
                if path:
                    self.screen.selected_filepath = path
                    self.screen.query_one("#selected-file-label", Label).update(f"Selected: {path}")
            self.push_screen(FileExplorerScreen(), set_file)
            return

        if event.button.id == "btn-reset":
            self.action_reset_state()
            return

        if event.button.id == "btn-analyze":
            filepath = getattr(self.screen, 'selected_filepath', None)
            if not filepath or not os.path.exists(filepath):
                self.screen.query_one("#analysis-status", Static).update("[red]Please select a valid file from the explorer first![/red]")
                self.screen.query_one("#analysis-status").remove_class("hidden")
                return
                
            if filepath.endswith('.pcap') or filepath.endswith('.pcapng'):
                self.screen.query_one("#analysis-status").update("[yellow]Starting accelerated PCAP replay...[/yellow]")
                self.screen.query_one("#analysis-status").remove_class("hidden")
                if self.app_context and hasattr(self.app_context, 'run_pcap_replay'):
                    self.app_context.run_pcap_replay(filepath)
                    self.action_switch_to_dashboard()
                return

            self.screen.query_one("#analysis-status").update("[yellow]Starting offline CSV analysis...[/yellow]")
            self.screen.query_one("#analysis-status").remove_class("hidden")
            self.screen.query_one("#analysis-progress").remove_class("hidden")
            
            # Trigger background process via main.py callback
            if self.app_context and hasattr(self.app_context, 'run_offline_analysis'):
                threading.Thread(target=self.app_context.run_offline_analysis, args=(filepath,), daemon=True).start()

    def on_file_analysis_progress_message(self, message: FileAnalysisProgressMessage) -> None:
        try:
            self.screen.query_one("#analysis-status", Static).update(f"[cyan]{message.message}[/cyan]")
            prog = self.screen.query_one("#analysis-progress", ProgressBar)
            prog.progress = message.percentage
        except:
            pass

    def on_file_analysis_complete_message(self, message: FileAnalysisCompleteMessage) -> None:
        res = message.results
        if "error" in res:
            try:
                self.screen.query_one("#analysis-status", Static).update(f"[red]Error: {res['error']}[/red]")
            except:
                pass
            return
            
        self.switch_screen("results")
        
        try:
            summary = self.screen.query_one("#results-summary", Static)
            summary.update(f"File Analysis Complete.\nTotal Flows: {res.get('total_flows')}\nTotal ML States (1s): {res.get('total_states')}")
            
            table = self.screen.query_one("#results-table", DataTable)
            table.clear()
            
            timeline_data = []
            
            for p in res.get('predictions', []):
                ts = p['timestamp'].strftime("%H:%M:%S") if hasattr(p['timestamp'], 'strftime') else str(p['timestamp'])
                target = p.get('current_prediction', 'Unknown')
                prob = f"{p.get('attack_probability', 0)*100:.1f}%"
                mitre = p.get('mitre_tactic', 'N/A')
                
                f30 = "N/A"
                if "future_30s" in p.get('probabilities', {}):
                    f30_probs = p['probabilities']['future_30s']
                    f30_idx = f30_probs.argmax()
                    f30 = p['label_map_inverse'].get(f30_idx, 'Unknown')
                    
                table.add_row(ts, target, target, prob, mitre, f30)
                timeline_data.append(p.get('attack_probability', 0.0))
                
            if timeline_data:
                spark = self.screen.query_one("#results-sparkline", Sparkline)
                spark.data = timeline_data
        except:
            pass
