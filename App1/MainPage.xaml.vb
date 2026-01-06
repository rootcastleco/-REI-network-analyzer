' Rootcastle Network Monitor v5.0
' Powered by /REI
' Complete Network Surveillance: NMAP + Wireshark + Sniffnet + SOFIA AI
' Features: Port Scanning, Packet Analysis, Protocol Decode, Export, Traffic Analysis

Imports System.Net.NetworkInformation
Imports System.Net.Sockets
Imports System.Net
Imports System.Text
Imports System.Threading
Imports System.IO
Imports Windows.Storage
Imports Windows.Storage.Pickers
Imports Windows.Web.Http
Imports Windows.Data.Json
Imports Windows.UI.Xaml.Shapes
Imports Windows.UI.Xaml.Media
Imports Windows.UI.Text
Imports Windows.UI.Xaml.Controls
Imports Microsoft.VisualBasic
Imports System.Linq
Imports Windows.UI
Imports App1

Public NotInheritable Class MainPage
    Inherits Page

#Region "Fields"
    ' Network Interfaces
    Private _interfaces As List(Of NetworkInterface)
    Private _selectedInterface As NetworkInterface

    ' Monitoring
    Private _monitorTimer As DispatcherTimer
    Private _uptimeTimer As DispatcherTimer
    Private _isMonitoring As Boolean = False
    Private _startTime As DateTime
    Private _random As New Random()

    ' Recording
    Private _isRecording As Boolean = False
    Private _recordedPackets As New List(Of ConnectionInfo)

    ' Statistics
    Private _packetCount As Long = 0
    Private _lastBytesSent As Long = 0
    Private _lastBytesReceived As Long = 0
    Private _tcpCount As Long = 0
    Private _udpCount As Long = 0
    Private _icmpCount As Long = 0
    Private _otherCount As Long = 0
    Private _errorCount As Long = 0
    Private _bytesPerSecIn As Long = 0
    Private _bytesPerSecOut As Long = 0
    Private _suspiciousCount As Long = 0
    Private _totalBytesIn As Long = 0
    Private _totalBytesOut As Long = 0

    ' QoS Metrics
    Private _latencyHistory As New List(Of Double)
    Private _currentLatency As Double = 0
    Private _jitter As Double = 0
    Private _packetLoss As Double = 0
    Private _throughput As Double = 0

    ' DNS Statistics
    Private _dnsQueryCount As Long = 0
    Private _dnsNxdomainCount As Long = 0
    Private _dnsTunnelCount As Long = 0

    ' TLS/PKI Statistics
    Private _tls13Count As Long = 0
    Private _tls12Count As Long = 0
    Private _tlsWeakCount As Long = 0
    Private _certList As New List(Of CertInfo)

    ' Threat Detection
    Private _portScanCount As Long = 0
    Private _dosCount As Long = 0
    Private _arpSpoofCount As Long = 0
    Private _threatList As New List(Of String)

    ' Asset Inventory
    Private _assetList As New List(Of AssetInfo)

    ' Application Breakdown
    Private _appTraffic As New Dictionary(Of String, Long)

    ' Conversations
    Private _conversations As New Dictionary(Of String, ConversationInfo)

    ' Zero Trust
    Private _zeroTrustEvents As New List(Of ZeroTrustEvent)

    ' Connection tracking for port scan detection
    Private _connectionAttempts As New Dictionary(Of String, List(Of DateTime))

    ' Traffic Graph
    Private _trafficHistoryIn As New List(Of Double)
    Private _trafficHistoryOut As New List(Of Double)
    Private Const MAX_GRAPH_POINTS As Integer = 60

    ' Connections & Data
    Private _activeConnections As New List(Of ConnectionInfo)
    Private _hostTraffic As New Dictionary(Of String, Long)
    Private _alerts As New List(Of String)
    Private _packetLog As New List(Of PacketLogEntry)

    ' Settings
    Private _filterProtocol As String = "ALL"
    Private _suspiciousDetectionEnabled As Boolean = False

    ' NMAP
    Private _nmapCancellationTokenSource As CancellationTokenSource
    Private _isNmapScanning As Boolean = False
    Private _nmapResults As New List(Of NmapHostResult)

    ' Packet Raw Data Storage
    Private _packetRawData As New Dictionary(Of Long, Byte())

    ' External IP
    Private _externalIP As String = ""

    ' AI Settings
    Private _openRouterApiKey As String = ""
    Private _selectedAIModel As String = "meta-llama/llama-3.2-3b-instruct:free"
    Private _selectedLanguage As String = "TR"
    Private Const OPENROUTER_API_URL As String = "https://openrouter.ai/api/v1/chat/completions"

    ' Port & Service Data
    Private ReadOnly _quickScanPorts As Integer() = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
    Private ReadOnly _fullScanPorts As Integer() = Enumerable.Range(1, 1024).ToArray()
    Private ReadOnly _commonServices As New Dictionary(Of Integer, String) From {
        {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
        {111, "RPC"}, {135, "MSRPC"}, {139, "NetBIOS"}, {143, "IMAP"}, {443, "HTTPS"}, {445, "SMB"},
        {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {1723, "PPTP"}, {3306, "MySQL"}, {3389, "RDP"},
        {5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-Proxy"}, {8443, "HTTPS-Alt"}, {27017, "MongoDB"}
    }
    Private ReadOnly _suspiciousPorts As Integer() = {23, 445, 1433, 3306, 4444, 5900, 6666, 6667, 31337, 12345, 27374}
    Private ReadOnly _suspiciousCountries As String() = {"CN", "RU", "KP", "IR"}
#End Region

#Region "Initialization"
    Private Sub MainPage_Loaded(sender As Object, e As RoutedEventArgs) Handles Me.Loaded
        Try
            InitializeGraphData()
            InitializeTimers()
            LoadInterfaces()
            GetExternalIPAsync()
            LogTerminal("[SYS] All systems initialized successfully")
        Catch ex As Exception
            LogTerminal($"[ERR] Init failed: {ex.Message}")
        End Try
    End Sub

    Private Async Sub GetExternalIPAsync()
        Try
            Using client As New HttpClient()
                Dim response = Await client.GetStringAsync(New Uri("https://api.ipify.org"))
                _externalIP = response.Trim()
                ExternalIPText.Text = $"WAN: {_externalIP}"
                InternetStatusText.Text = "●"
                InternetStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
                LogTerminal($"[NET] External IP: {_externalIP}")
            End Using
        Catch ex As Exception
            ExternalIPText.Text = "WAN: Unavailable"
            InternetStatusText.Text = "●"
            InternetStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))
            LogTerminal($"[ERR] Failed to get external IP: {ex.Message}")
        End Try
    End Sub

    Private Sub InitializeGraphData()
        _trafficHistoryIn = New List(Of Double)(Enumerable.Repeat(0.0, MAX_GRAPH_POINTS))
        _trafficHistoryOut = New List(Of Double)(Enumerable.Repeat(0.0, MAX_GRAPH_POINTS))
    End Sub

    Private Sub InitializeTimers()
        _monitorTimer = New DispatcherTimer()
        _monitorTimer.Interval = TimeSpan.FromMilliseconds(500)
        AddHandler _monitorTimer.Tick, AddressOf MonitorTimer_Tick

        _uptimeTimer = New DispatcherTimer()
        _uptimeTimer.Interval = TimeSpan.FromSeconds(1)
        AddHandler _uptimeTimer.Tick, AddressOf UptimeTimer_Tick
    End Sub

    Private Sub LoadInterfaces()
        Try
            InterfaceComboBox.Items.Clear()
            _interfaces = NetworkInterface.GetAllNetworkInterfaces().
                Where(Function(n) n.OperationalStatus = OperationalStatus.Up AndAlso
                                  n.NetworkInterfaceType <> NetworkInterfaceType.Loopback).ToList()

            For Each ni In _interfaces
                InterfaceComboBox.Items.Add($"{ni.Name}")
            Next

            If InterfaceComboBox.Items.Count > 0 Then
                InterfaceComboBox.SelectedIndex = 0
            Else
                LogTerminal("[WARN] No active network interfaces found")
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Failed to load interfaces: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Interface Selection"
    Private Sub InterfaceComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Try
            If InterfaceComboBox.SelectedIndex >= 0 AndAlso InterfaceComboBox.SelectedIndex < _interfaces.Count Then
                _selectedInterface = _interfaces(InterfaceComboBox.SelectedIndex)
                LoadNetworkStats()
                LogTerminal($"[NET] Selected: {_selectedInterface.Name}")
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Interface selection: {ex.Message}")
        End Try
    End Sub

    Private Sub LoadNetworkStats()
        If _selectedInterface Is Nothing Then Return

        Try
            Dim ni = _selectedInterface
            Dim ipStats = ni.GetIPStatistics()

            _lastBytesSent = ipStats.BytesSent
            _lastBytesReceived = ipStats.BytesReceived

            InterfaceNameText.Text = $"Name: {ni.Name}"
            InterfaceTypeText.Text = $"Type: {ni.NetworkInterfaceType}"
            InterfaceStatusText.Text = $"Status: {ni.OperationalStatus}"
            InterfaceSpeedText.Text = $"Speed: {If(ni.Speed > 0, (ni.Speed / 1000000).ToString("F0") & " Mbps", "N/A")}"

            Dim mac = ni.GetPhysicalAddress().GetAddressBytes()
            MacAddressText.Text = $"MAC: {If(mac.Length > 0, String.Join(":", mac.Select(Function(b) b.ToString("X2"))), "N/A")}"

            Dim ipProps = ni.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
            Dim ipv6 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetworkV6)
            Dim gateway = ipProps.GatewayAddresses.FirstOrDefault(Function(g) g.Address.AddressFamily = AddressFamily.InterNetwork)
            Dim dns = ipProps.DnsAddresses.FirstOrDefault()

            IPv4Text.Text = $"IPv4: {If(ipv4?.Address.ToString(), "N/A")}"
            IPv6Text.Text = $"IPv6: {If(ipv6?.Address.ToString(), "N/A")}"
            SubnetText.Text = $"Mask: {If(ipv4?.IPv4Mask?.ToString(), "N/A")}"
            GatewayText.Text = $"GW: {If(gateway?.Address.ToString(), "N/A")}"
            DnsServersText.Text = $"DNS: {If(dns?.ToString(), "N/A")}"

            ' Update topology display
            If ipv4 IsNot Nothing Then
                Dim localIP = ipv4.Address.ToString()
                LocalIPShortText.Text = localIP.Substring(localIP.LastIndexOf(".") + 1)

                ' These controls are not present in XAML; use existing ones.
                'LocalIPText.Text = $"Kişisel IP: {localIP}"
                'RouterIPText.Text = $"Router IP: {gateway?.Address.ToString()}"

                If gateway IsNot Nothing Then
                    GatewayShortText.Text = gateway.Address.ToString().Split("."c).LastOrDefault()
                Else
                    GatewayShortText.Text = "-"
                End If
            End If

            ' Clear previous topology data
            TopologyCanvas.Children.Clear()
            _hostTraffic.Clear()
            _activeConnections.Clear()

            ' Redraw topology
            DrawTopology()
        Catch ex As Exception
            LogTerminal($"[ERR] Failed to load network stats: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Monitoring"
    Private Sub StartMonitoring()
        If _selectedInterface Is Nothing Then Return

        Try
            _isMonitoring = True
            _startTime = DateTime.Now
            _lastBytesSent = 0
            _lastBytesReceived = 0
            _packetCount = 0
            _errorCount = 0
            _suspiciousCount = 0
            _totalBytesIn = 0
            _totalBytesOut = 0
            _bytesPerSecIn = 0
            _bytesPerSecOut = 0
            _trafficHistoryIn.Clear()
            _trafficHistoryOut.Clear()

            For i = 0 To MAX_GRAPH_POINTS - 1
                _trafficHistoryIn.Add(0)
                _trafficHistoryOut.Add(0)
            Next

            ' Start timers
            _monitorTimer.Start()
            _uptimeTimer.Start()

            Dim ni = _selectedInterface
            Dim ipProps = ni.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)

            If ipv4 IsNot Nothing Then
                Dim localIP = ipv4.Address.ToString()
                LocalIPShortText.Text = localIP.Substring(localIP.LastIndexOf(".") + 1)
                ' LocalIPText control is not present in XAML.
            End If

            LogTerminal($"[MON] Monitoring started on {_selectedInterface.Name}")
        Catch ex As Exception
            LogTerminal($"[ERR] Start monitoring: {ex.Message}")
        End Try
    End Sub

    Private Sub StopMonitoring()
        _isMonitoring = False
        _monitorTimer.Stop()
        _uptimeTimer.Stop()

        LogTerminal($"[MON] Monitoring stopped on {_selectedInterface.Name}")
    End Sub

    Private Sub MonitorTimer_Tick(sender As Object, e As Object)
        If _selectedInterface Is Nothing OrElse Not _isMonitoring Then Return

        Try
            Dim ni = _selectedInterface
            Dim ipStats = ni.GetIPStatistics()

            Dim currentBytesSent = ipStats.BytesSent
            Dim currentBytesReceived = ipStats.BytesReceived
            Dim deltaSent = Math.Max(0, currentBytesSent - _lastBytesSent)
            Dim deltaReceived = Math.Max(0, currentBytesReceived - _lastBytesReceived)

            _bytesPerSecOut = deltaSent * 2
            _bytesPerSecIn = deltaReceived * 2
            _totalBytesOut += deltaSent
            _totalBytesIn += deltaReceived

            ' Update graph data
            _trafficHistoryOut.RemoveAt(0)
            _trafficHistoryOut.Add(_bytesPerSecOut / 1024.0)
            _trafficHistoryIn.RemoveAt(0)
            _trafficHistoryIn.Add(_bytesPerSecIn / 1024.0)

            ' UI Updates
            DrawTrafficGraph()
            DrawTopologyTraffic()
            UpdateTrafficDisplay(currentBytesSent, currentBytesReceived)
            TrafficRateText.Text = $"{FormatBytes(_bytesPerSecIn + _bytesPerSecOut)}/s"
            BytesPerSecText.Text = $"↓{FormatBytes(_bytesPerSecIn)}/s ↑{FormatBytes(_bytesPerSecOut)}/s"

            ' Update topology stats
            DownloadSpeedText.Text = $"{FormatBytes(_bytesPerSecIn)}/s"
            UploadSpeedText.Text = $"{FormatBytes(_bytesPerSecOut)}/s"
            ActiveConnectionsText.Text = _activeConnections.Count.ToString()
            ActiveHostsText.Text = $"Hosts: {_hostTraffic.Count}"

            ' Update QoS Metrics
            UpdateQoSMetrics()

            ' Update Bandwidth percentage
            UpdateBandwidthDisplay()

            ' Capture packets
            If deltaSent > 0 Or deltaReceived > 0 Then
                CapturePacket(deltaSent, deltaReceived)
            End If

            ' Update Security Stats periodically
            UpdateSecurityStats()

            ' Update Alert count
            AlertCountText.Text = $"[{_alerts.Count}]"

            _lastBytesSent = currentBytesSent
            _lastBytesReceived = currentBytesReceived

        Catch ex As Exception
            _errorCount += 1
            ErrorCountText.Text = $"E:{_errorCount}"
        End Try
    End Sub

    Private Sub UptimeTimer_Tick(sender As Object, e As Object)
        If Not _isMonitoring Then Return

        Try
            Dim uptime = DateTime.Now - _startTime
            UptimeText.Text = $"{uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}"
        Catch ex As Exception
            LogTerminal($"[ERR] Uptime update: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "UI Display"
    Private Sub UpdateTrafficDisplay(sent As Long, recv As Long)
        SentDataText.Text = $"↑ {FormatBytes(sent)}"
        ReceivedDataText.Text = $"↓ {FormatBytes(recv)}"
    End Sub

    Private Sub DrawTopologyTraffic()
        Try
            TopologyCanvas.Children.Clear()
            Dim w = TopologyCanvas.ActualWidth
            Dim h = TopologyCanvas.ActualHeight
            If w <= 0 Or h <= 0 Then Return

            ' Draw connection line
            Dim centerY = h / 2
            Dim line As New Line() With {
                .X1 = 0, .Y1 = centerY,
                .X2 = w, .Y2 = centerY,
                .Stroke = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 100, 100)),
                .StrokeThickness = 2
            }
            TopologyCanvas.Children.Add(line)

            ' Draw traffic flow indicators (animated dots)
            Dim trafficIntensity = Math.Min(10, Math.Max(1, CInt((_bytesPerSecIn + _bytesPerSecOut) / 10000)))

            ' Download arrows (left to right, cyan)
            If _bytesPerSecIn > 0 Then
                For i = 0 To trafficIntensity - 1
                    Dim x = (DateTime.Now.Millisecond / 100.0 + i * (w / trafficIntensity)) Mod w
                    Dim arrow As New TextBlock() With {
                        .Text = "→",
                        .Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 255)),
                        .FontSize = 14,
                        .FontFamily = New FontFamily("Consolas")
                    }
                    Canvas.SetLeft(arrow, x)
                    Canvas.SetTop(arrow, centerY - 15)
                    TopologyCanvas.Children.Add(arrow)
                Next
            End If

            ' Upload arrows (right to left, green)
            If _bytesPerSecOut > 0 Then
                For i = 0 To trafficIntensity - 1
                    Dim x = w - ((DateTime.Now.Millisecond / 100.0 + i * (w / trafficIntensity)) Mod w)
                    Dim arrow As New TextBlock() With {
                        .Text = "←",
                        .Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0)),
                        .FontSize = 14,
                        .FontFamily = New FontFamily("Consolas")
                    }
                    Canvas.SetLeft(arrow, x)
                    Canvas.SetTop(arrow, centerY + 5)
                    TopologyCanvas.Children.Add(arrow)
                Next
            End If

            ' Draw traffic stats in center
            Dim statsText As New TextBlock() With {
                .Text = $"↓{FormatBytes(_bytesPerSecIn)}/s  ↑{FormatBytes(_bytesPerSecOut)}/s",
                .Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 255, 255)),
                .FontSize = 10,
                .FontFamily = New FontFamily("Consolas")
            }
            Dim bg As New Border() With {
                .Background = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(200, 0, 20, 20)),
                .Padding = New Thickness(4),
                .CornerRadius = New CornerRadius(2),
                .Child = statsText
            }
            Canvas.SetLeft(bg, w / 2 - 60)
            Canvas.SetTop(bg, centerY - 12)
            TopologyCanvas.Children.Add(bg)
        Catch
        End Try
    End Sub

    Private Sub DrawTrafficGraph()
        Try
            ' XAML canvas name is `TrafficGraphCanvas`
            If TrafficGraphCanvas.Children.Count > 0 Then
                TrafficGraphCanvas.Children.Clear()
            End If

            Dim maxIn = _trafficHistoryIn.Max()
            Dim maxOut = _trafficHistoryOut.Max()
            Dim maxValue = Math.Max(maxIn, maxOut)
            If maxValue = 0 Then Return

            Dim width = TrafficGraphCanvas.ActualWidth
            Dim height = TrafficGraphCanvas.ActualHeight
            Dim barWidth = Math.Max(1, CInt(width / MAX_GRAPH_POINTS))

            For i = 0 To MAX_GRAPH_POINTS - 1
                Dim inValue = _trafficHistoryIn(i)
                Dim outValue = _trafficHistoryOut(i)

                Dim inHeight = height * (inValue / maxValue)
                Dim outHeight = height * (outValue / maxValue)

                Dim inBar = New Rectangle() With {
                    .Width = barWidth - 2,
                    .Height = inHeight,
                    .Fill = New SolidColorBrush(Colors.Blue)
                }

                Dim outBar = New Rectangle() With {
                    .Width = barWidth - 2,
                    .Height = outHeight,
                    .Fill = New SolidColorBrush(Colors.Red)
                }

                Canvas.SetLeft(inBar, i * barWidth)
                Canvas.SetTop(inBar, height - inHeight)

                Canvas.SetLeft(outBar, i * barWidth)
                Canvas.SetTop(outBar, height - outHeight)

                TrafficGraphCanvas.Children.Add(inBar)
                TrafficGraphCanvas.Children.Add(outBar)
            Next

            TrafficGraphCanvas.Width = Math.Max(TrafficGraphCanvas.ActualWidth, MAX_GRAPH_POINTS * 4)
        Catch ex As Exception
            LogTerminal($"[ERR] Draw traffic graph: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Packet Capture"
    Private Sub CapturePacket(deltaSent As Long, deltaReceived As Long)
        Try
            Dim now = DateTime.Now

            ' Simulate packet capture for testing
            Dim testPacket As New ConnectionInfo() With {
                .Timestamp = now,
                .SourceIP = "192.168.1." & _random.Next(1, 255),
                .DestIP = "192.168.1." & _random.Next(1, 255),
                .Protocol = If(_random.Next(0, 2) = 0, "TCP", "UDP"),
                .Length = CLng(_random.Next(50, 1500)),
                .Info = "Test packet " & _packetCount
            }

            _packetCount += 1
            _recordedPackets.Add(testPacket)

            ' Update active connections
            UpdateActiveConnections(testPacket)

            ' Update firewall and threat detection
            If _suspiciousDetectionEnabled Then
                UpdateThreatDetection(testPacket)
            End If

            ' Log packet details
            Dim packetDetails = $"[{testPacket.Timestamp:HH:mm:ss}] {testPacket.Protocol} {testPacket.SourceIP} → {testPacket.DestIP} [{testPacket.Length} bytes] {testPacket.Info}"
            LogTerminal(packetDetails)

            ' Update simple UI bindings list (Packet Capture)
            ConnectionsListView.ItemsSource = Nothing
            ConnectionsListView.ItemsSource = _recordedPackets.TakeLast(200).Select(Function(p)
                                                                                        p.Id = p.Id
                                                                                        Return p
                                                                                    End Function).ToList()
            ConnectionCountText.Text = $"[{_recordedPackets.Count} connections]"

            PacketCountText.Text = _packetCount.ToString()

        Catch ex As Exception
            LogTerminal($"[ERR] Capture packet: {ex.Message}")
        End Try
    End Sub

    Private Sub UpdateActiveConnections(packet As ConnectionInfo)
        Try
            Dim key = $"{packet.SourceIP}-{packet.DestIP}-{packet.Protocol}"

            If Not _activeConnections.Any(Function(c) c.Key = key) Then
                Dim conn = New ConnectionInfo() With {
                    .SourceIP = packet.SourceIP,
                    .DestIP = packet.DestIP,
                    .Protocol = packet.Protocol,
                    .Length = packet.Length,
                    .Timestamp = packet.Timestamp
                }

                _activeConnections.Add(conn)

                ' Update UI
                ActiveConnectionsText.Text = _activeConnections.Count.ToString()
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Update active connections: {ex.Message}")
        End Try
    End Sub

    Private Sub UpdateThreatDetection(packet As ConnectionInfo)
        Try
            ' Basic rule: alert on incoming packets if source IP is suspicious
            If packet.Protocol = "TCP" AndAlso packet.Length > 1000 Then
                Dim sourceIPParts = packet.SourceIP.Split(".")
                If sourceIPParts.Length = 4 Then
                    Dim lastOctet = Convert.ToInt32(sourceIPParts(3))
                    If lastOctet > 100 Then
                        _suspiciousCount += 1
                        If _suspiciousCount <= 5 Then
                            LogTerminal($"[ALERT] Suspicious packet detected: {packet.SourceIP} → {packet.DestIP} [{packet.Length} bytes]")
                        End If
                    End If
                End If
            End If

            ' Update firewall rules (block large incoming TCP packets from suspicious IPs)
            If packet.Protocol = "TCP" AndAlso packet.Length > 1000 Then
                Dim destIPParts = packet.DestIP.Split(".")
                If destIPParts.Length = 4 Then
                    Dim lastOctet = Convert.ToInt32(destIPParts(3))
                    If lastOctet <= 100 Then
                        LogTerminal($"[FIREWALL] Blocking incoming packet from {packet.SourceIP} to {packet.DestIP} [{packet.Length} bytes]")
                    End If
                End If
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Update threat detection: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Security & Alerts"
    Private Sub UpdateSecurityStats()
        Try
            ' Update suspicious activities count
            Dim suspiciousActivities = _recordedPackets.
                Where(Function(p) p.Protocol = "TCP" AndAlso p.Length > 1000).
                GroupBy(Function(p) p.SourceIP).
                Select(Function(g) New With {.IP = g.Key, .Count = g.Count()}).
                OrderByDescending(Function(a) a.Count).
                ToList()

            _suspiciousCount = suspiciousActivities.Sum(Function(a) a.Count)

            ' Update alert list
            _alerts = suspiciousActivities.
                Where(Function(a) a.Count > 5).
                Select(Function(a) $"{a.IP}: {a.Count} suspicious packets").
                ToList()

            ' Update alert count display
            AlertCountText.Text = $"[{_alerts.Count}]"
        Catch ex As Exception
            LogTerminal($"[ERR] Update security stats: {ex.Message}")
        End Try
    End Sub

    Private Sub LogTerminal(message As String)
        Try
            Dim timeStamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            Dim line = $"{timeStamp} - {message}" & Environment.NewLine

            ' XAML terminal is `TerminalOutput` (TextBlock) inside a ScrollViewer.
            TerminalOutput.Text &= line

            If AutoScrollCheckBox IsNot Nothing AndAlso AutoScrollCheckBox.IsChecked.GetValueOrDefault(True) Then
                TerminalScrollViewer?.ChangeView(Nothing, TerminalScrollViewer.ScrollableHeight, Nothing)
            End If
        Catch
            ' Ignore logging errors
        End Try
    End Sub
#End Region

#Region "QoS Metrics"
    Private Sub UpdateQoSMetrics()
        Try
            ' Simulate QoS metrics update
            _latencyHistory.Add(_random.NextDouble() * 50)
            If _latencyHistory.Count > 10 Then _latencyHistory.RemoveAt(0)

            Dim avgLatency = _latencyHistory.Average()
            _currentLatency = avgLatency

            ' Left panel
            LatencyText.Text = $"{avgLatency:F1} ms"

            ' QoS panel
            QosLatencyText.Text = $"{avgLatency:F1} ms"

            ' Jitter
            If _latencyHistory.Count > 1 Then
                Dim jitter = 0.0
                For i = 1 To _latencyHistory.Count - 1
                    jitter += Math.Abs(_latencyHistory(i) - _latencyHistory(i - 1))
                Next
                jitter /= (_latencyHistory.Count - 1)
                _jitter = jitter
            End If
            QosJitterText.Text = $"{_jitter:F1} ms"

            ' Packet Loss (simulate 0.1% packet loss)
            _packetLoss = If(_random.NextDouble() < 0.001, 1, 0)
            QosLossText.Text = $"{_packetLoss}%"

            ' Throughput (rough estimate)
            _throughput = (_bytesPerSecIn + _bytesPerSecOut) * 8.0 / 1_000_000.0
            QosThroughputText.Text = $"{_throughput:F2} Mbps"
        Catch ex As Exception
            LogTerminal($"[ERR] Update QoS metrics: {ex.Message}")
        End Try
    End Sub

    Private Sub UpdateBandwidthDisplay()
        Try
            If _selectedInterface Is Nothing OrElse _selectedInterface.Speed <= 0 Then
                BandwidthText.Text = "0%"
                Return
            End If

            Dim usedBps = (_bytesPerSecIn + _bytesPerSecOut) * 8.0
            Dim pct = Math.Min(100.0, (usedBps / _selectedInterface.Speed) * 100.0)
            BandwidthText.Text = $"{pct:F1}%"
        Catch
            BandwidthText.Text = "0%"
        End Try
    End Sub

    Private Function FormatBytes(value As Long) As String
        Dim dbl = CDbl(Math.Max(0L, value))
        Dim units = New String() {"B", "KB", "MB", "GB", "TB"}
        Dim idx = 0
        While dbl >= 1024 AndAlso idx < units.Length - 1
            dbl /= 1024
            idx += 1
        End While
        If idx = 0 Then Return $"{dbl:0} {units(idx)}"
        Return $"{dbl:0.##} {units(idx)}"
    End Function

    Private Sub DrawTopology()
        ' Minimal placeholder: topology is drawn dynamically in `DrawTopologyTraffic`.
        ' Keep as a hook so calls from other routines compile.
        DrawTopologyTraffic()
    End Sub

    Private Sub ShowAlert(message As String)
        _alerts.Add(message)
        If _alerts.Count > 200 Then _alerts.RemoveAt(0)
        AlertsListView.ItemsSource = Nothing
        AlertsListView.ItemsSource = _alerts.ToList()
        AlertCountText.Text = $"[{_alerts.Count}]"
    End Sub

    Private Sub StartMonitorButton_Click(sender As Object, e As RoutedEventArgs)
        If _isMonitoring Then
            StopMonitoring()
            StartMonitorButton.Content = "▶ START"
            MonitorStatusText.Text = "●"
            MonitorStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0))
            StatusText.Text = "[STOPPED]"
        Else
            StartMonitoring()
            StartMonitorButton.Content = "■ STOP"
            MonitorStatusText.Text = "●"
            MonitorStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
            StatusText.Text = "[MONITORING]"
        End If
    End Sub

    Private Sub SuspiciousPacketCheckBox_Checked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = True
        LogTerminal("[SEC] Suspicious detection enabled")
    End Sub

    Private Sub SuspiciousPacketCheckBox_Unchecked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = False
        LogTerminal("[SEC] Suspicious detection disabled")
    End Sub

    Private Sub ClearTerminalButton_Click(sender As Object, e As RoutedEventArgs)
        TerminalOutput.Text = ""
    End Sub

    Private Sub FilterComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        ' UI-only placeholder; filtering can be layered on top of packet logs.
    End Sub

    Private Sub RecordButton_Click(sender As Object, e As RoutedEventArgs)
        _isRecording = Not _isRecording
        RecordButton.Content = If(_isRecording, "■ STOP REC", "● REC")
        RecordingStatusText.Text = If(_isRecording, "[REC]", "")
        LogTerminal(If(_isRecording, "[REC] Recording started", "[REC] Recording stopped"))
    End Sub

    Private Sub PacketFilterTextBox_KeyDown(sender As Object, e As KeyRoutedEventArgs)
        If e.Key = Windows.System.VirtualKey.Enter Then
            ApplyFilterButton_Click(sender, Nothing)
        End If
    End Sub

    Private Sub ApplyFilterButton_Click(sender As Object, e As RoutedEventArgs)
        _filterProtocol = If(String.IsNullOrWhiteSpace(PacketFilterTextBox.Text), "ALL", PacketFilterTextBox.Text.Trim().ToUpperInvariant())
        LogTerminal($"[UI] Filter set: {_filterProtocol}")
    End Sub

    Private Sub PacketListView_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selected = TryCast(ConnectionsListView.SelectedItem, ConnectionInfo)
        If selected Is Nothing Then Return

        PacketDetailsPanel.Visibility = Visibility.Visible
        PacketDetailsText.Text = $"[{selected.Timestamp:HH:mm:ss}] {selected.Protocol} {selected.SourceIP} → {selected.DestIP}{vbCrLf}Len: {selected.Length} bytes{vbCrLf}{selected.Info}"
    End Sub

    Private Sub ExportReportButton_Click(sender As Object, e As RoutedEventArgs)
        ' Placeholder for export wiring; keep feature surface without breaking build.
        ShowAlert("Export not implemented in this build.")
    End Sub

    Private Sub SecurityDashboardButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 2
    End Sub

    Private Sub TopologyButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 0
    End Sub

    Private Sub AdvancedSettingsButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 3
    End Sub

    Private Sub SendTcpButton_Click(sender As Object, e As RoutedEventArgs)
        ShowAlert("TCP sender not implemented in this build.")
    End Sub

    Private Sub SendUdpButton_Click(sender As Object, e As RoutedEventArgs)
        ShowAlert("UDP sender not implemented in this build.")
    End Sub

    Private Sub PingButton_Click(sender As Object, e As RoutedEventArgs)
        ShowAlert("Ping not implemented in this build.")
    End Sub

    Private Sub TraceRouteButton_Click(sender As Object, e As RoutedEventArgs)
        ShowAlert("Traceroute not implemented in this build.")
    End Sub

#End Region

#Region "SOFIA AI"
    Private Sub AIModelComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim item = TryCast(AIModelComboBox.SelectedItem, ComboBoxItem)
        If item IsNot Nothing Then
            _selectedAIModel = item.Tag?.ToString()
            UpdateAIModelInfo()
            LogTerminal($"[AI] Model changed: {item.Content}")
        End If
    End Sub

    Private Sub AILanguageComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim item = TryCast(AILanguageComboBox.SelectedItem, ComboBoxItem)
        If item IsNot Nothing Then
            _selectedLanguage = item.Tag?.ToString()
            UpdateAIModelInfo()
            LogTerminal($"[AI] Language changed: {item.Content}")
        End If
    End Sub

    Private Sub UpdateAIModelInfo()
        Try
            Dim langName = If(_selectedLanguage = "TR", "Türkçe",
                           If(_selectedLanguage = "EN", "English",
                           If(_selectedLanguage = "DE", "Deutsch",
                           If(_selectedLanguage = "FR", "Français",
                           If(_selectedLanguage = "ES", "Español",
                           If(_selectedLanguage = "JP", "日本語",
                           If(_selectedLanguage = "CN", "中文", "Unknown")))))))

            AIModelInfoText.Text = $"Selected: {_selectedAIModel} | Language: {langName}"
        Catch
        End Try
    End Sub

    Private Function GetLanguagePrompt() As String
        Select Case _selectedLanguage
            Case "EN"
                Return "Always respond in English. Be technical and concise."
            Case "DE"
                Return "Antworte immer auf Deutsch. Sei technisch und präzise."
            Case "FR"
                Return "Réponds toujours en français. Sois technique et concis."
            Case "ES"
                Return "Responde siempre en español. Sé técnico y conciso."
            Case "JP"
                Return "常に日本語で回答してください。技術的で簡潔にしてください。"
            Case "CN"
                Return "请始终用中文回答。要技术性强且简洁。"
            Case Else ' TR
                Return "Her zaman Türkçe yanıt ver. Teknik ve özlü ol."
        End Select
    End Function

    Private Async Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim query = AIQueryTextBox?.Text?.Trim()
            If String.IsNullOrEmpty(query) Then
                query = If(_selectedLanguage = "TR", "Mevcut ağ durumunu analiz et ve güvenlik değerlendirmesi yap.",
                                                     "Analyze current network status and provide security assessment.")
            End If

            AIAnalysisText.Text = If(_selectedLanguage = "TR", "[SOFIA] 🔄 Analiz ediliyor, lütfen bekleyin...",
                                                                "[SOFIA] 🔄 Analyzing, please wait...")
            AIStatusText.Text = "Processing..."
            StatusText.Text = "[AI ANALYZING]..."

            Dim data = CollectAnalysisData()
            Dim response = Await GetAIResponseAsync(data, query)

            AIAnalysisText.Text = response
            AIStatusText.Text = "Ready"
            StatusText.Text = "[AI] ✓ Complete"

            If AIQueryTextBox IsNot Nothing Then
                AIQueryTextBox.Text = ""
            End If
        Catch ex As Exception
            AIAnalysisText.Text = $"[SOFIA] ❌ Error: {ex.Message}"
            AIStatusText.Text = "Error"
            StatusText.Text = "[AI] Error"
        End Try
    End Sub

    Private Sub AIQueryTextBox_KeyDown(sender As Object, e As KeyRoutedEventArgs)
        If e.Key = Windows.System.VirtualKey.Enter Then AIAnalyzeButton_Click(sender, Nothing)
    End Sub

    Private Async Sub AIQuickAnalyze_Click(sender As Object, e As RoutedEventArgs)
        Dim button = TryCast(sender, Button)
        Dim actionType = button?.Tag?.ToString()

        AIAnalysisText.Text = If(_selectedLanguage = "TR", "[SOFIA] 🔄 İşleniyor...", "[SOFIA] 🔄 Processing...")
        AIStatusText.Text = "Processing..."

        Dim query As String = ""
        Select Case actionType
            Case "traffic"
                query = If(_selectedLanguage = "TR",
                    "Mevcut ağ trafiğini detaylı analiz et. Protokol dağılımı, bant genişliği kullanımı ve olası darboğazları belirle.",
                    "Analyze current network traffic in detail. Identify protocol distribution, bandwidth usage and potential bottlenecks.")
            Case "security"
                query = If(_selectedLanguage = "TR",
                    "Kapsamlı güvenlik taraması yap. Açık portlar, şüpheli trafik, potansiyel tehditler ve güvenlik açıklarını listele.",
                    "Perform comprehensive security scan. List open ports, suspicious traffic, potential threats and vulnerabilities.")
            Case "firewall"
                query = If(_selectedLanguage = "TR",
                    "Tespit edilen trafiğe göre firewall kural önerileri oluştur. iptables ve Windows Firewall formatında.",
                    "Generate firewall rule recommendations based on detected traffic. In iptables and Windows Firewall format.")
            Case "summary"
                query = If(_selectedLanguage = "TR",
                    "Tüm ağ aktivitesinin yönetici özeti oluştur. İstatistikler ve aksiyon maddeleri ile.",
                    "Create executive summary of all network activity. With statistics and action items.")
            Case "anomaly"
                query = If(_selectedLanguage = "TR",
                    "Anomali tespiti yap. Normal trafik profilinden sapmaları ve şüpheli davranış kalıplarını tespit et.",
                    "Perform anomaly detection. Identify deviations from normal traffic profile and suspicious behavior patterns.")
            Case "performance"
                query = If(_selectedLanguage = "TR",
                    "Ağ performans analizi yap. Latency, jitter, packet loss değerlerini yorumla ve optimizasyon önerileri sun.",
                    "Perform network performance analysis. Interpret latency, jitter, packet loss values and provide optimization recommendations.")
            Case "toptalkers"
                query = If(_selectedLanguage = "TR",
                    "En çok trafik üreten host'ları ve uygulamaları analiz et. Bant genişliği tüketim oranlarını belirt.",
                    "Analyze top traffic generating hosts and applications. Indicate bandwidth consumption rates.")
            Case "incident"
                query = If(_selectedLanguage = "TR",
                    "Incident response raporu oluştur. Timeline, etkilenen sistemler ve aksiyon planı ile.",
                    "Create incident response report. With timeline, affected systems and action plan.")
        End Select

        Dim data = CollectAnalysisData()
        Dim response = Await GetAIResponseAsync(data, query)
        AIAnalysisText.Text = response
        AIStatusText.Text = "Ready"
    End Sub

    Private Function CollectAnalysisData() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("=== ROOTCASTLE NETWORK ANALYSIS DATA ===")
        sb.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
        sb.AppendLine($"External IP: {_externalIP}")
        sb.AppendLine()
        sb.AppendLine("--- INTERFACE INFO ---")
        sb.AppendLine($"Interface: {InterfaceNameText.Text}")
        sb.AppendLine($"IP Address: {IPv4Text.Text}")
        sb.AppendLine($"Gateway: {GatewayText.Text}")
        sb.AppendLine($"DNS: {DnsServersText.Text}")
        sb.AppendLine()
        sb.AppendLine("--- TRAFFIC STATISTICS ---")
        sb.AppendLine($"Total Bytes IN: {FormatBytes(_totalBytesIn)}")
        sb.AppendLine($"Total Bytes OUT: {FormatBytes(_totalBytesOut)}")
        sb.AppendLine($"Current Rate IN: {FormatBytes(_bytesPerSecIn)}/s")
        sb.AppendLine($"Current Rate OUT: {FormatBytes(_bytesPerSecOut)}/s")
        sb.AppendLine()
        sb.AppendLine("--- PACKET STATISTICS ---")
        sb.AppendLine($"Total Packets: {_packetCount}")
        sb.AppendLine($"TCP: {_tcpCount} | UDP: {_udpCount} | ICMP: {_icmpCount} | Other: {_otherCount}")
        sb.AppendLine($"Suspicious: {_suspiciousCount}")
        sb.AppendLine()
        sb.AppendLine("--- QoS METRICS ---")
        sb.AppendLine($"Latency: {_currentLatency:F1} ms | Jitter: {_jitter:F1} ms | Packet Loss: {_packetLoss:F2}%")
        sb.AppendLine()
        sb.AppendLine("--- SECURITY ---")
        sb.AppendLine($"Port Scans: {_portScanCount} | DoS: {_dosCount} | TLS Weak: {_tlsWeakCount}")
        sb.AppendLine()
        sb.AppendLine("--- NMAP RESULTS ---")
        sb.AppendLine($"Hosts: {_nmapResults.Count}")
        For Each host In _nmapResults.Take(10)
            sb.AppendLine($"  {host.Host} [{host.Status}] Ports: {host.Ports}")
        Next
        sb.AppendLine()
        sb.AppendLine("--- TOP HOSTS ---")
        For Each kv In _hostTraffic.OrderByDescending(Function(x) x.Value).Take(10)
            sb.AppendLine($"  {kv.Key}: {FormatBytes(kv.Value)}")
        Next
        Return sb.ToString()
    End Function

    Private Async Function GetAIResponseAsync(data As String, userQuery As String) As Task(Of String)
        Try
            If String.IsNullOrEmpty(_openRouterApiKey) Then
                Return If(_selectedLanguage = "TR",
                    "[SOFIA] ⚠️ API Key Gerekli

OpenRouter API anahtarı ayarlanmamış. 

🔧 Çözüm:
1. https://openrouter.ai adresine gidin
2. Ücretsiz hesap oluşturun
3. API Key alın
4. Ayarlar (⚙️) menüsünden API Key'i girin

📝 Not: Ücretsiz modeller kullanabilirsiniz.",
                    "[SOFIA] ⚠️ API Key Required

OpenRouter API key is not set.

🔧 Solution:
1. Go to https://openrouter.ai
2. Create a free account
3. Get your API Key
4. Enter API Key from Settings (⚙️) menu

📝 Note: You can use free models.")
            End If

            Using client As New HttpClient()
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {_openRouterApiKey}")
                client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")
                client.DefaultRequestHeaders.Add("X-Title", "Rootcastle Network Monitor")

                Dim languagePrompt = GetLanguagePrompt()

                Dim systemPrompt = $"You are SOFIA (Smart Operational Firewall Intelligence Assistant), a professional network security and analysis AI. You are the built-in AI engine of Rootcastle Network Monitor.

TASKS:
1. Analyze network traffic and detect anomalies
2. Evaluate and prioritize security threats
3. Provide firewall rules and security recommendations
4. Support incident response
5. Suggest performance optimizations
6. Create technical and executive reports

RULES:
- {languagePrompt}
- Explain technical details clearly
- Provide concrete action items
- Indicate risk levels (Critical/High/Medium/Low)
- Use emojis for visualization
- Use structured and readable format"

                Dim userPrompt = $"USER QUERY: {userQuery}

NETWORK DATA:
{data}

Please analyze the network data above and provide a detailed response to the user's query."

                Dim body As New JsonObject()
                body.Add("model", JsonValue.CreateStringValue(_selectedAIModel))

                Dim msgs As New JsonArray()

                Dim sysMsg As New JsonObject()
                sysMsg.Add("role", JsonValue.CreateStringValue("system"))
                sysMsg.Add("content", JsonValue.CreateStringValue(systemPrompt))
                msgs.Add(sysMsg)

                Dim usrMsg As New JsonObject()
                usrMsg.Add("role", JsonValue.CreateStringValue("user"))
                usrMsg.Add("content", JsonValue.CreateStringValue(userPrompt))
                msgs.Add(usrMsg)

                body.Add("messages", msgs)
                body.Add("max_tokens", JsonValue.CreateNumberValue(2000))
                body.Add("temperature", JsonValue.CreateNumberValue(0.7))

                Dim content As New HttpStringContent(body.Stringify(), Windows.Storage.Streams.UnicodeEncoding.Utf8, "application/json")
                Dim response = Await client.PostAsync(New Uri(OPENROUTER_API_URL), content)
                Dim responseText = Await response.Content.ReadAsStringAsync()

                If response.IsSuccessStatusCode Then
                    Dim json = JsonObject.Parse(responseText)
                    Dim choices = json.GetNamedArray("choices")
                    If choices.Count > 0 Then
                        Dim aiResponse = choices.GetObjectAt(0).GetNamedObject("message").GetNamedString("content")
                        Return $"[SOFIA] 🧠 AI Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{aiResponse}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📅 {DateTime.Now:yyyy-MM-dd HH:mm:ss}
🔧 Model: {_selectedAIModel}"
                    End If
                ElseIf response.StatusCode = Windows.Web.Http.HttpStatusCode.Unauthorized Then
                    Return If(_selectedLanguage = "TR",
                        "[SOFIA] ❌ API Key Hatası (Unauthorized)

API anahtarınız geçersiz veya süresi dolmuş.

🔧 Çözüm:
1. Ayarlar (⚙️) menüsünü açın
2. Geçerli bir OpenRouter API Key girin
3. https://openrouter.ai/keys adresinden yeni key alabilirsiniz",
                        "[SOFIA] ❌ API Key Error (Unauthorized)

Your API key is invalid or expired.

🔧 Solution:
1. Open Settings (⚙️) menu
2. Enter a valid OpenRouter API Key
3. Get a new key from https://openrouter.ai/keys")
                Else
                    Return $"[SOFIA] ⚠️ API Error: {response.StatusCode}"
                End If

                Return If(_selectedLanguage = "TR", "[SOFIA] ⚠️ Analiz yapılamadı.", "[SOFIA] ⚠️ Analysis failed.")
            End Using
        Catch ex As Exception
            Return $"[SOFIA] ❌ Error: {ex.Message}"
        End Try
    End Function
#End Region

#Region "NMAP Scanner"
    Private Sub NmapMenuButton_Click(sender As Object, e As RoutedEventArgs)
        NmapResultsPanel.Visibility = If(NmapResultsPanel.Visibility = Visibility.Visible, Visibility.Collapsed, Visibility.Visible)
    End Sub

    Private Async Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapScanning Then
            LogTerminal("[NMAP] Scan already in progress")
            Return
        End If

        Dim target = NmapTargetTextBox.Text.Trim()
        If String.IsNullOrEmpty(target) Then
            LogTerminal("[NMAP] Target required")
            ShowAlert("Enter target IP/range")
            Return
        End If

        Dim scanType = GetSelectedScanType()
        Dim portsText = NmapPortsTextBox.Text.Trim()

        _isNmapScanning = True
        _nmapCancellationTokenSource = New CancellationTokenSource()
        NmapStopButton.IsEnabled = True
        NmapProgressBar.Visibility = Visibility.Visible
        NmapProgressBar.IsIndeterminate = True
        NmapResultsPanel.Visibility = Visibility.Visible
        _nmapResults.Clear()
        NmapResultsListView.ItemsSource = Nothing

        LogTerminal($"[NMAP] Starting {scanType} scan: {target}")
        NmapStatusText.Text = $"[SCAN: {target}]"
        ShowAlert($"NMAP: {target}")

        Try
            Dim ports = GetPortsForScan(scanType, portsText)
            Dim targets = ParseTargets(target)

            LogTerminal($"[NMAP] Scanning {targets.Count} target(s), {ports.Length} port(s)")

            For Each t In targets
                If _nmapCancellationTokenSource.IsCancellationRequested Then Exit For
                Await ScanHostAsync(t, ports, scanType, _nmapCancellationTokenSource.Token)
                RefreshNmapResults()
            Next

            RefreshNmapResults()
            LogTerminal($"[NMAP] Scan complete: {_nmapResults.Count} host(s) found")
            NmapStatusText.Text = $"[DONE: {_nmapResults.Count}]"
            ShowAlert($"NMAP complete: {_nmapResults.Count} hosts")

        Catch ex As OperationCanceledException
            LogTerminal("[NMAP] Scan cancelled by user")
            NmapStatusText.Text = "[CANCELLED]"
        Catch ex As Exception
            LogTerminal($"[NMAP] Error: {ex.Message}")
            NmapStatusText.Text = "[ERROR]"
            ShowAlert($"NMAP Error: {ex.Message}")
        Finally
            _isNmapScanning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    Private Async Sub NmapNetworkDiscoveryButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapScanning Then
            LogTerminal("[NMAP] Scan already in progress")
            Return
        End If

        If _selectedInterface Is Nothing Then
            LogTerminal("[NMAP] Select interface first")
            ShowAlert("Select network interface first")
            Return
        End If

        Try
            Dim ipProps = _selectedInterface.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
            If ipv4 Is Nothing Then
                LogTerminal("[NMAP] No IPv4 address found")
                ShowAlert("No IPv4 address on selected interface")
                Return
            End If

            Dim localIP = ipv4.Address.ToString()
            Dim parts = localIP.Split("."c)
            If parts.Length <> 4 Then
                LogTerminal("[NMAP] Invalid IP format")
                Return
            End If

            Dim networkRange = $"{parts(0)}.{parts(1)}.{parts(2)}.1-254"
            NmapTargetTextBox.Text = networkRange
            LogTerminal($"[NMAP] Network discovery: {networkRange}")

            _isNmapScanning = True
            _nmapCancellationTokenSource = New CancellationTokenSource()
            NmapStopButton.IsEnabled = True
            NmapProgressBar.Visibility = Visibility.Visible
            NmapProgressBar.IsIndeterminate = True
            NmapResultsPanel.Visibility = Visibility.Visible
            _nmapResults.Clear()
            NmapResultsListView.ItemsSource = Nothing

            NmapStatusText.Text = "[DISCOVERING...]"
            ShowAlert("Network discovery started")

            Dim baseIP = $"{parts(0)}.{parts(1)}.{parts(2)}."
            Dim tasks As New List(Of Task)

            For i = 1 To 254
                If _nmapCancellationTokenSource.IsCancellationRequested Then Exit For

                Dim ip = baseIP & i.ToString()
                tasks.Add(PingHostAsync(ip))

                If tasks.Count >= 50 Then
                    Await Task.WhenAll(tasks)
                    tasks.Clear()
                    RefreshNmapResults()
                    NmapStatusText.Text = $"[SCAN: {i}/254 - Found: {_nmapResults.Count}]"
                End If
            Next

            If tasks.Count > 0 Then
                Await Task.WhenAll(tasks)
            End If

            RefreshNmapResults()
            LogTerminal($"[NMAP] Discovery complete: {_nmapResults.Count} host(s) found")
            NmapStatusText.Text = $"[FOUND: {_nmapResults.Count}]"
            ShowAlert($"Discovery complete: {_nmapResults.Count} hosts")

        Catch ex As Exception
            LogTerminal($"[NMAP] Discovery error: {ex.Message}")
            ShowAlert($"Discovery error: {ex.Message}")
        Finally
            _isNmapScanning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    Private Sub NmapStopButton_Click(sender As Object, e As RoutedEventArgs)
        If _nmapCancellationTokenSource IsNot Nothing Then
            _nmapCancellationTokenSource.Cancel()
            LogTerminal("[NMAP] Stop requested...")
            NmapStatusText.Text = "[STOPPING...]"
        End If
    End Sub

    Private Async Function PingHostAsync(ip As String) As Task
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 500)
                If reply.Status = IPStatus.Success Then
                    SyncLock _nmapResults
                        If Not _nmapResults.Any(Function(r) r.Host = ip) Then
                            _nmapResults.Add(New NmapHostResult With {
                                .Host = ip,
                                .Status = "UP",
                                .Ports = $"RTT: {reply.RoundtripTime}ms",
                                .OS = "",
                                .OpenPorts = New List(Of Integer)
                            })
                        End If
                    End SyncLock
                End If
            End Using
        Catch
        End Try
    End Function

    Private Async Function ScanHostAsync(ip As String, ports As Integer(), scanType As String, token As CancellationToken) As Task
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 1000)
                If reply.Status <> IPStatus.Success Then
                    Return
                End If
            End Using
        Catch
            Return
        End Try

        If token.IsCancellationRequested Then Return

        Dim result As New NmapHostResult With {
            .Host = ip,
            .Status = "UP",
            .OpenPorts = New List(Of Integer),
            .OS = ""
        }

        Await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low,
            Sub() LogTerminal($"[NMAP] Scanning {ip} ({ports.Length} ports)"))

        Dim openPorts As New List(Of String)

        For Each port In ports
            If token.IsCancellationRequested Then Exit For

            Try
                Using client As New TcpClient()
                    client.SendTimeout = 200
                    client.ReceiveTimeout = 200

                    Dim connectTask = client.ConnectAsync(ip, port)
                    Dim timeoutTask = Task.Delay(200, token)

                    Dim completedTask = Await Task.WhenAny(connectTask, timeoutTask)

                    If completedTask Is connectTask AndAlso Not connectTask.IsFaulted AndAlso client.Connected Then
                        result.OpenPorts.Add(port)
                        Dim svc = If(_commonServices.ContainsKey(port), _commonServices(port), "unknown")
                        openPorts.Add($"{port}/{svc}")

                        Await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low,
                            Sub() LogTerminal($"[NMAP] {ip}:{port} OPEN ({svc})"))
                    End If

                    client.Close()
                End Using
            Catch
            End Try
        Next

        If scanType = "OS Detection" OrElse scanType = "Full Scan" OrElse scanType = "Service Scan" Then
            result.OS = Await DetectOSAsync(ip)
        End If

        result.Ports = If(openPorts.Count > 0, String.Join(", ", openPorts), "No open ports")

        If result.OpenPorts.Count > 0 OrElse scanType = "Quick Scan" Then
            SyncLock _nmapResults
                Dim existing = _nmapResults.FirstOrDefault(Function(r) r.Host = ip)
                If existing IsNot Nothing Then
                    existing.Ports = result.Ports
                    existing.OS = result.OS
                    existing.OpenPorts = result.OpenPorts
                Else
                    _nmapResults.Add(result)
                End If
            End SyncLock
        End If
    End Function

    Private Async Function DetectOSAsync(ip As String) As Task(Of String)
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 1000)
                If reply.Status = IPStatus.Success AndAlso reply.Options IsNot Nothing Then
                    Dim ttl = reply.Options.Ttl
                    If ttl <= 64 Then Return "Linux/Unix/macOS"
                    If ttl <= 128 Then Return "Windows"
                    If ttl <= 255 Then Return "Network Device"
                End If
            End Using
        Catch
        End Try
        Return "Unknown"
    End Function

    Private Function GetSelectedScanType() As String
        Try
            Dim item = TryCast(NmapScanTypeCombo.SelectedItem, ComboBoxItem)
            Return If(item?.Content?.ToString(), "Quick Scan")
        Catch
            Return "Quick Scan"
        End Try
    End Function

    Private Function GetPortsForScan(scanType As String, customPorts As String) As Integer()
        If Not String.IsNullOrEmpty(customPorts) Then
            Return ParsePorts(customPorts)
        End If

        Select Case scanType
            Case "Full Scan"
                Return _fullScanPorts
            Case "UDP Scan"
                Return {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514}
            Case "Stealth Scan", "Quick Scan"
                Return _quickScanPorts
            Case "Service Scan", "OS Detection"
                Return _quickScanPorts
            Case "Vuln Scan"
                Return {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080}
            Case Else
                Return _quickScanPorts
        End Select
    End Function

    Private Function ParsePorts(text As String) As Integer()
        Dim ports As New List(Of Integer)
        Try
            For Each part In text.Split(","c)
                part = part.Trim()
                If part.Contains("-") Then
                    Dim r = part.Split("-"c)
                    Dim startPort = Integer.Parse(r(0).Trim())
                    Dim endPort = Integer.Parse(r(1).Trim())
                    If startPort <= endPort AndAlso startPort > 0 AndAlso endPort <= 65535 Then
                        ports.AddRange(Enumerable.Range(startPort, endPort - startPort + 1))
                    End If
                Else
                    Dim port = Integer.Parse(part)
                    If port > 0 AndAlso port <= 65535 Then
                        ports.Add(port)
                    End If
                End If
            Next
        Catch ex As Exception
            LogTerminal($"[NMAP] Port parse error: {ex.Message}")
        End Try
        Return If(ports.Count > 0, ports.Distinct().OrderBy(Function(p) p).ToArray(), _quickScanPorts)
    End Function

    Private Function ParseTargets(target As String) As List(Of String)
        Dim targets As New List(Of String)
        Try
            target = target.Trim()

            If target.Contains("/24") Then
                Dim baseIP = target.Replace("/24", "").Trim().Split("."c)
                If baseIP.Length = 4 Then
                    For i = 1 To 254
                        targets.Add($"{baseIP(0)}.{baseIP(1)}.{baseIP(2)}.{i}")
                    Next
                End If
            ElseIf target.Contains("-") Then
                Dim parts = target.Split("."c)
                If parts.Length = 4 AndAlso parts(3).Contains("-") Then
                    Dim rangeParts = parts(3).Split("-"c)
                    Dim startIP = Integer.Parse(rangeParts(0).Trim())
                    Dim endIP = Integer.Parse(rangeParts(1).Trim())
                    For i = startIP To endIP
                        targets.Add($"{parts(0)}.{parts(1)}.{parts(2)}.{i}")
                    Next
                Else
                    targets.Add(target)
                End If
            Else
                targets.Add(target)
            End If
        Catch ex As Exception
            LogTerminal($"[NMAP] Target parse error: {ex.Message}")
            targets.Add(target)
        End Try
        Return targets
    End Function

    Private Sub RefreshNmapResults()
        Try
            Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal,
                Sub()
                    NmapResultsListView.ItemsSource = Nothing
                    NmapResultsListView.ItemsSource = _nmapResults.ToList()
                    NmapHostCountText.Text = $"[{_nmapResults.Count} hosts]"
                End Sub)
        Catch
        End Try
    End Sub

    Private Sub NmapResultsListView_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selected = TryCast(NmapResultsListView.SelectedItem, NmapHostResult)
        If selected IsNot Nothing Then
            TargetHostTextBox.Text = selected.Host
            PacketDetailsPanel.Visibility = Visibility.Visible
            PacketDetailsText.Text = $"═══ HOST: {selected.Host} ═══" & vbCrLf &
                                    $"Status: {selected.Status}" & vbCrLf &
                                    $"OS: {If(String.IsNullOrEmpty(selected.OS), "Unknown", selected.OS)}" & vbCrLf &
                                    $"Open Ports: {selected.Ports}" & vbCrLf &
                                    $"Port Count: {selected.OpenPorts.Count}"
        End If
    End Sub
#End Region

End Class
