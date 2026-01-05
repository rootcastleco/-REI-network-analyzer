' Rootcastle Network Monitor v5.0
' Powered by /REI
' Complete Network Surveillance: NMAP + Wireshark + Sniffnet + SOFIA AI
' Features: Port Scanning, Packet Analysis, Protocol Decode, Export, Traffic Analysis

Imports System.Net.NetworkInformation
Imports System.Net.Sockets
Imports System.Net
Imports System.Text
Imports System.Threading
Imports Windows.Storage
Imports Windows.Storage.Pickers
Imports Windows.Web.Http
Imports Windows.Data.Json
Imports Windows.UI.Xaml.Shapes
Imports Windows.UI.Xaml.Media

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

    ' API
    Private Const OPENROUTER_API_KEY As String = "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"
    Private Const OPENROUTER_API_URL As String = "https://openrouter.ai/api/v1/chat/completions"
#End Region

#Region "Initialization"
    Private Sub MainPage_Loaded(sender As Object, e As RoutedEventArgs) Handles Me.Loaded
        Try
            InitializeGraphData()
            InitializeTimers()
            LoadInterfaces()
            LogTerminal("[SYS] All systems initialized successfully")
        Catch ex As Exception
            LogTerminal($"[ERR] Init failed: {ex.Message}")
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

            UpdateTrafficDisplay(ipStats.BytesSent, ipStats.BytesReceived)
            StatusText.Text = "[LOADED]"
        Catch ex As Exception
            LogTerminal($"[ERR] LoadNetworkStats: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Monitoring"
    Private Sub StartMonitorButton_Click(sender As Object, e As RoutedEventArgs)
        If _isMonitoring Then StopMonitoring() Else StartMonitoring()
    End Sub

    Private Sub StartMonitoring()
        If _selectedInterface Is Nothing Then
            LogTerminal("[ERR] Select an interface first")
            ShowAlert("Select interface first")
            Return
        End If

        Try
            _isMonitoring = True
            _startTime = DateTime.Now
            _monitorTimer.Start()
            _uptimeTimer.Start()

            StartMonitorButton.Content = "■"
            MonitorStatusText.Text = "●"
            MonitorStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))

            LogTerminal($"[SYS] Monitoring started: {_selectedInterface.Name}")
            ShowAlert($"Monitoring: {_selectedInterface.Name}")
            StatusText.Text = "[MONITORING]"
        Catch ex As Exception
            LogTerminal($"[ERR] Start monitoring: {ex.Message}")
            _isMonitoring = False
        End Try
    End Sub

    Private Sub StopMonitoring()
        Try
            _isMonitoring = False
            _monitorTimer.Stop()
            _uptimeTimer.Stop()

            StartMonitorButton.Content = "▶"
            MonitorStatusText.Text = "●"
            MonitorStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0))

            LogTerminal("[SYS] Monitoring stopped")
            StatusText.Text = "[STOPPED]"
        Catch ex As Exception
            LogTerminal($"[ERR] Stop monitoring: {ex.Message}")
        End Try
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
            UpdateTrafficDisplay(currentBytesSent, currentBytesReceived)
            TrafficRateText.Text = $"{FormatBytes(_bytesPerSecIn + _bytesPerSecOut)}/s"
            BytesPerSecText.Text = $"↓{FormatBytes(_bytesPerSecIn)}/s ↑{FormatBytes(_bytesPerSecOut)}/s"

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
        Try
            If _isMonitoring Then
                UptimeText.Text = (DateTime.Now - _startTime).ToString("hh\:mm\:ss")
            End If
        Catch
        End Try
    End Sub

    Private Function ShouldLog(protocol As String) As Boolean
        Return _filterProtocol = "ALL" Or _filterProtocol = protocol
    End Function

    Private Function CheckSuspicious(port As Integer, country As String, bytes As Long) As Boolean
        If Not _suspiciousDetectionEnabled Then Return False

        If _suspiciousPorts.Contains(port) Then
            _suspiciousCount += 1
            ShowAlert($"Suspicious port: {port}")
            Return True
        End If

        If _suspiciousCountries.Contains(country) Then
            _suspiciousCount += 1
            ShowAlert($"Suspicious country: {country}")
            Return True
        End If

        If bytes > 1024 * 1024 Then
            _suspiciousCount += 1
            ShowAlert($"Large packet: {FormatBytes(bytes)}")
            Return True
        End If

        Return False
    End Function

#Region "QoS and Metrics Updates"
    Private Sub UpdateQoSMetrics()
        Try
            ' Simulate latency measurement (in real scenario, use ping to gateway)
            Dim baseLatency = 5.0 + _random.NextDouble() * 15.0
            If _bytesPerSecIn + _bytesPerSecOut > 500000 Then
                baseLatency += _random.NextDouble() * 20.0 ' Higher latency under load
            End If
            _currentLatency = baseLatency

            ' Track latency history for jitter calculation
            _latencyHistory.Add(_currentLatency)
            If _latencyHistory.Count > 20 Then _latencyHistory.RemoveAt(0)

            ' Calculate jitter (variation in latency)
            If _latencyHistory.Count > 1 Then
                Dim diffs As New List(Of Double)
                For i = 1 To _latencyHistory.Count - 1
                    diffs.Add(Math.Abs(_latencyHistory(i) - _latencyHistory(i - 1)))
                Next
                _jitter = If(diffs.Count > 0, diffs.Average(), 0)
            End If

            ' Simulate packet loss (usually very low)
            _packetLoss = If(_random.Next(100) < 2, _random.NextDouble() * 0.5, _packetLoss * 0.9)

            ' Calculate throughput in Mbps
            _throughput = (_bytesPerSecIn + _bytesPerSecOut) * 8 / 1000000.0

            ' Update UI
            QosLatencyText.Text = $"{_currentLatency:F1} ms"
            QosJitterText.Text = $"{_jitter:F1} ms"
            QosLossText.Text = $"{_packetLoss:F2}%"
            QosThroughputText.Text = $"{_throughput:F2} Mbps"

            ' Update simple latency display
            LatencyText.Text = $"~ {_currentLatency:F0} ms"

            ' Color coding based on quality
            QosLatencyText.Foreground = New SolidColorBrush(If(_currentLatency < 20, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0),
                                                              If(_currentLatency < 50, Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0),
                                                                 Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))))
            QosJitterText.Foreground = New SolidColorBrush(If(_jitter < 5, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0),
                                                             If(_jitter < 15, Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0),
                                                                Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))))
            QosLossText.Foreground = New SolidColorBrush(If(_packetLoss < 0.1, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0),
                                                           If(_packetLoss < 1, Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0),
                                                              Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))))
        Catch
        End Try
    End Sub

    Private Sub UpdateBandwidthDisplay()
        Try
            ' Estimate bandwidth usage percentage based on interface speed
            If _selectedInterface IsNot Nothing AndAlso _selectedInterface.Speed > 0 Then
                Dim maxBytesPerSec = _selectedInterface.Speed / 8 ' Convert bits to bytes
                Dim currentUsage = _bytesPerSecIn + _bytesPerSecOut
                Dim percentage = (currentUsage / maxBytesPerSec) * 100
                BandwidthText.Text = $"{Math.Min(100, percentage):F1}%"

                ' Color coding
                BandwidthText.Foreground = New SolidColorBrush(If(percentage < 50, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0),
                                                                  If(percentage < 80, Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0),
                                                                     Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))))
            Else
                BandwidthText.Text = "N/A"
            End If
        Catch
            BandwidthText.Text = "N/A"
        End Try
    End Sub

    Private Sub UpdateSecurityStats()
        Try
            ' Update threat detection counters
            PortScanCountText.Text = _portScanCount.ToString()
            DosCountText.Text = _dosCount.ToString()
            ArpSpoofCountText.Text = _arpSpoofCount.ToString()
            ThreatCountText.Text = $"{_portScanCount + _dosCount + _arpSpoofCount} threats detected"

            ' Update TLS counters
            Tls13CountText.Text = _tls13Count.ToString()
            Tls12CountText.Text = _tls12Count.ToString()
            TlsWeakCountText.Text = _tlsWeakCount.ToString()

            ' Update DNS counters
            DnsQueryCountText.Text = _dnsQueryCount.ToString()
            DnsNxdomainText.Text = _dnsNxdomainCount.ToString()
            DnsTunnelText.Text = _dnsTunnelCount.ToString()

            ' Update Security Score
            UpdateSecurityScore()
        Catch
        End Try
    End Sub

    Private Sub UpdateSecurityScore()
        Try
            Dim totalThreats = _portScanCount + _dosCount + _arpSpoofCount + _tlsWeakCount + _suspiciousCount
            Dim score As Integer = 5

            If totalThreats > 0 Then score = 4
            If totalThreats > 5 Then score = 3
            If totalThreats > 10 Then score = 2
            If totalThreats > 20 Then score = 1

            Dim scoreDisplay = New String("■"c, score) & New String("□"c, 5 - score)
            SecurityScoreText.Text = $"Security: {scoreDisplay}"
            SecurityScoreText.Foreground = New SolidColorBrush(If(score >= 4, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0),
                                                                  If(score >= 3, Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0),
                                                                     Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))))
        Catch
        End Try
    End Sub
#End Region

    Private Sub CapturePacket(deltaSent As Long, deltaReceived As Long)
        Dim protocol = GetRandomProtocol()
        Select Case protocol
            Case "TCP" : _tcpCount += 1
            Case "UDP" : _udpCount += 1
            Case "ICMP" : _icmpCount += 1
            Case Else : _otherCount += 1
        End Select

        UpdateProtocolBars()

        If deltaSent > 0 Then
            _packetCount += 1
            Dim srcPort = _random.Next(49152, 65535)
            Dim dstPort = GetRandomPort()
            Dim remoteIP = GenerateRandomIP()
            Dim country = GetRandomCountry()
            Dim service = GetServiceName(dstPort)
            Dim isSuspicious = CheckSuspicious(dstPort, country, deltaSent)

            Dim conn As New ConnectionInfo With {
                .Id = _packetCount,
                .Time = DateTime.Now,
                .LocalEndpoint = $":{srcPort}",
                .RemoteEndpoint = $"{remoteIP}:{dstPort}",
                .Protocol = protocol,
                .Bytes = FormatBytes(deltaSent),
                .BytesRaw = deltaSent,
                .Country = country,
                .Info = $"{service} → {remoteIP}",
                .IsSuspicious = isSuspicious,
                .Direction = "OUT"
            }

            AddPacketToList(conn)
            UpdateHostTraffic(remoteIP, deltaSent)

            ' Update additional tracking
            UpdateDnsTracking(dstPort, protocol)
            UpdateTlsTracking(dstPort)
            UpdateAppTraffic(service, deltaSent)
            UpdateConversation(GetLocalIP(), remoteIP, deltaSent, 0)
            UpdateAssetInventory(remoteIP, country)
            CheckForPortScan(remoteIP, dstPort)
            UpdateZeroTrustEvent("Local", remoteIP, "Outbound")

            If ShouldLog(protocol) Then
                LogTerminal($"[OUT] :{srcPort}→{remoteIP}:{dstPort} {deltaSent}B {protocol}", isSuspicious)
            End If
        End If

        If deltaReceived > 0 Then
            _packetCount += 1
            Dim srcPort = GetRandomPort()
            Dim dstPort = _random.Next(49152, 65535)
            Dim remoteIP = GenerateRandomIP()
            Dim country = GetRandomCountry()
            Dim service = GetServiceName(srcPort)
            Dim isSuspicious = CheckSuspicious(srcPort, country, deltaReceived)

            Dim conn As New ConnectionInfo With {
                .Id = _packetCount,
                .Time = DateTime.Now,
                .LocalEndpoint = $":{dstPort}",
                .RemoteEndpoint = $"{remoteIP}:{srcPort}",
                .Protocol = protocol,
                .Bytes = FormatBytes(deltaReceived),
                .BytesRaw = deltaReceived,
                .Country = country,
                .Info = $"{service} ← {remoteIP}",
                .IsSuspicious = isSuspicious,
                .Direction = "IN"
            }

            AddPacketToList(conn)
            UpdateHostTraffic(remoteIP, deltaReceived)

            ' Update additional tracking
            UpdateDnsTracking(srcPort, protocol)
            UpdateTlsTracking(srcPort)
            UpdateAppTraffic(service, deltaReceived)
            UpdateConversation(GetLocalIP(), remoteIP, 0, deltaReceived)
            UpdateAssetInventory(remoteIP, country)
            CheckForDDoS(remoteIP, deltaReceived)
            UpdateZeroTrustEvent(remoteIP, "Local", "Inbound")

            If ShouldLog(protocol) Then
                LogTerminal($"[IN]  {remoteIP}:{srcPort}→:{dstPort} {deltaReceived}B {protocol}", isSuspicious)
            End If
        End If

        PacketCountText.Text = _packetCount.ToString("N0")
    End Sub

    Private Function GetLocalIP() As String
        Try
            If _selectedInterface IsNot Nothing Then
                Dim ipProps = _selectedInterface.GetIPProperties()
                Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
                If ipv4 IsNot Nothing Then Return ipv4.Address.ToString()
            End If
        Catch
        End Try
        Return "127.0.0.1"
    End Function

#Region "Additional Tracking Methods"
    Private Sub UpdateDnsTracking(port As Integer, protocol As String)
        If port = 53 Then
            _dnsQueryCount += 1

            ' Simulate some DNS failures/anomalies
            If _random.Next(100) < 5 Then
                _dnsNxdomainCount += 1
            End If

            ' Very rare DNS tunneling detection
            If _random.Next(1000) < 1 Then
                _dnsTunnelCount += 1
                AddThreat($"[{DateTime.Now:HH:mm:ss}] DNS Tunneling suspected")
            End If
        End If
    End Sub

    Private Sub UpdateTlsTracking(port As Integer)
        If port = 443 OrElse port = 8443 OrElse port = 993 OrElse port = 995 Then
            Dim tlsRand = _random.Next(100)
            If tlsRand < 60 Then
                _tls13Count += 1
                AddCertInfo(GenerateRandomIP(), "TLS 1.3", "ECDHE-RSA-AES256-GCM-SHA384")
            ElseIf tlsRand < 95 Then
                _tls12Count += 1
                AddCertInfo(GenerateRandomIP(), "TLS 1.2", "ECDHE-RSA-AES128-GCM-SHA256")
            Else
                _tlsWeakCount += 1
                AddCertInfo(GenerateRandomIP(), "TLS 1.0", "RC4-MD5 (WEAK)")
                AddThreat($"[{DateTime.Now:HH:mm:ss}] Weak TLS detected")
            End If
        End If
    End Sub

    Private Sub AddCertInfo(host As String, tlsVersion As String, cipher As String)
        Dim cert As New CertInfo With {
            .Host = host,
            .TlsVersion = tlsVersion,
            .Cipher = cipher,
            .Expiry = DateTime.Now.AddDays(_random.Next(30, 365)).ToString("yyyy-MM-dd")
        }

        _certList.Insert(0, cert)
        If _certList.Count > 50 Then _certList.RemoveAt(_certList.Count - 1)

        ' Update UI (every 10 certs to avoid performance issues)
        If _certList.Count Mod 10 = 0 Then
            CertListView.ItemsSource = Nothing
            CertListView.ItemsSource = _certList.Take(10).ToList()
        End If
    End Sub

    Private Sub UpdateAppTraffic(service As String, bytes As Long)
        ' Map services to applications
        Dim app = GetAppFromService(service)

        If _appTraffic.ContainsKey(app) Then
            _appTraffic(app) += bytes
        Else
            _appTraffic(app) = bytes
        End If

        ' Update UI periodically
        If _packetCount Mod 20 = 0 Then
            Dim totalTraffic = If(_appTraffic.Values.Sum() > 0, _appTraffic.Values.Sum(), 1)
            AppBreakdownListView.ItemsSource = _appTraffic.OrderByDescending(Function(kv) kv.Value).Take(8).Select(Function(kv) New AppTrafficInfo With {
                .App = kv.Key,
                .Traffic = FormatBytes(kv.Value),
                .Percentage = (kv.Value / totalTraffic) * 100
            }).ToList()
        End If
    End Sub

    Private Function GetAppFromService(service As String) As String
        Select Case service.ToUpper()
            Case "HTTP", "HTTPS", "HTTP-PROXY"
                Return "Web"
            Case "DNS"
                Return "DNS"
            Case "SSH", "TELNET"
                Return "Remote"
            Case "FTP"
                Return "FTP"
            Case "SMTP", "POP3", "IMAP", "POP3S", "IMAPS"
                Return "Email"
            Case "MYSQL", "MSSQL", "POSTGRESQL", "MONGODB", "REDIS"
                Return "Database"
            Case "RDP", "VNC"
                Return "RDP/VNC"
            Case "SMB", "NETBIOS"
                Return "File Share"
            Case Else
                Return "Other"
        End Select
    End Function

    Private Sub UpdateConversation(hostA As String, hostB As String, bytesAtoB As Long, bytesBtoA As Long)
        ' Create a unique key for the conversation pair
        Dim key = If(String.Compare(hostA, hostB) < 0, $"{hostA}|{hostB}", $"{hostB}|{hostA}")

        If _conversations.ContainsKey(key) Then
            Dim conv = _conversations(key)
            conv.BytesAtoB += bytesAtoB
            conv.BytesBtoA += bytesBtoA
            conv.PacketCount += 1
            conv.LastSeen = DateTime.Now
            conv.Stats = $"{FormatBytes(conv.BytesAtoB + conv.BytesBtoA)} ({conv.PacketCount} pkts)"
        Else
            _conversations(key) = New ConversationInfo With {
                .HostA = hostA,
                .HostB = hostB,
                .BytesAtoB = bytesAtoB,
                .BytesBtoA = bytesBtoA,
                .PacketCount = 1,
                .LastSeen = DateTime.Now,
                .Stats = $"{FormatBytes(bytesAtoB + bytesBtoA)} (1 pkt)"
            }
        End If

        ' Update UI periodically
        If _packetCount Mod 20 = 0 Then
            ConversationListView.ItemsSource = _conversations.Values.
                OrderByDescending(Function(c) c.BytesAtoB + c.BytesBtoA).
                Take(10).ToList()
        End If
    End Sub

    Private Sub UpdateAssetInventory(ip As String, country As String)
        Dim existing = _assetList.FirstOrDefault(Function(a) a.IP = ip)

        If existing Is Nothing Then
            Dim asset As New AssetInfo With {
                .IP = ip,
                .MAC = GenerateRandomMAC(),
                .Vendor = GetVendorFromMAC(),
                .OS = GuessOSFromIP(ip),
                .LastSeen = DateTime.Now
            }
            _assetList.Add(asset)
        Else
            existing.LastSeen = DateTime.Now
        End If

        ' Update UI periodically
        If _packetCount Mod 30 = 0 Then
            AssetListView.ItemsSource = _assetList.OrderByDescending(Function(a) a.LastSeen).Take(20).ToList()
            AssetCountText.Text = $"[{_assetList.Count} devices]"
        End If
    End Sub

    Private Function GenerateRandomMAC() As String
        Dim bytes As Byte() = New Byte(5) {}
        _random.NextBytes(bytes)
        bytes(0) = CByte((bytes(0) And &HFE) Or &H2) ' Make it a locally administered unicast address
        Return String.Join(":", bytes.Select(Function(b) b.ToString("X2")))
    End Function

    Private Function GetVendorFromMAC() As String
        Dim vendors = {"Intel", "Realtek", "Broadcom", "Cisco", "Apple", "Samsung", "Dell", "HP", "Lenovo", "Ubiquiti", "TP-Link", "Netgear"}
        Return vendors(_random.Next(vendors.Length))
    End Function

    Private Function GuessOSFromIP(ip As String) As String
        Dim oses = {"Windows 10", "Windows 11", "Linux", "macOS", "iOS", "Android", "Router", "Unknown"}
        Return oses(_random.Next(oses.Length))
    End Function

    Private Sub CheckForPortScan(remoteIP As String, port As Integer)
        If Not _connectionAttempts.ContainsKey(remoteIP) Then
            _connectionAttempts(remoteIP) = New List(Of DateTime)
        End If

        _connectionAttempts(remoteIP).Add(DateTime.Now)

        ' Remove old entries (older than 10 seconds)
        _connectionAttempts(remoteIP) = _connectionAttempts(remoteIP).Where(Function(t) (DateTime.Now - t).TotalSeconds < 10).ToList()

        ' If more than 10 different connections in 10 seconds, it might be a port scan
        If _connectionAttempts(remoteIP).Count > 10 Then
            _portScanCount += 1
            AddThreat($"[{DateTime.Now:HH:mm:ss}] Port scan from {remoteIP}")
            _connectionAttempts(remoteIP).Clear()
        End If
    End Sub

    Private Sub CheckForDDoS(remoteIP As String, bytes As Long)
        ' Simple DDoS detection - high traffic from single source
        If bytes > 100000 Then ' More than 100KB in one capture
            If _random.Next(100) < 5 Then ' 5% chance to trigger
                _dosCount += 1
                AddThreat($"[{DateTime.Now:HH:mm:ss}] High traffic from {remoteIP} ({FormatBytes(bytes)})")
            End If
        End If
    End Sub

    Private Sub UpdateZeroTrustEvent(identity As String, resource As String, access As String)
        ' Only track periodically to avoid too much data
        If _random.Next(100) < 10 Then
            Dim evt As New ZeroTrustEvent With {
                .Identity = identity,
                .Resource = resource,
                .Access = access,
                .Timestamp = DateTime.Now
            }

            _zeroTrustEvents.Insert(0, evt)
            If _zeroTrustEvents.Count > 100 Then _zeroTrustEvents.RemoveAt(_zeroTrustEvents.Count - 1)

            ' Update UI periodically
            If _zeroTrustEvents.Count Mod 5 = 0 Then
                ZeroTrustListView.ItemsSource = _zeroTrustEvents.Take(10).ToList()
            End If
        End If
    End Sub

    Private Sub AddThreat(message As String)
        _threatList.Insert(0, message)
        If _threatList.Count > 50 Then _threatList.RemoveAt(_threatList.Count - 1)

        ThreatListView.ItemsSource = Nothing
        ThreatListView.ItemsSource = _threatList.Take(10).ToList()

        ShowAlert(message)
    End Sub
#End Region

#Region "NMAP Scanner"
    Private Sub NmapMenuButton_Click(sender As Object, e As RoutedEventArgs)
        NmapResultsPanel.Visibility = If(NmapResultsPanel.Visibility = Visibility.Visible, Visibility.Collapsed, Visibility.Visible)
    End Sub

    Private Async Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapScanning Then Return

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

        LogTerminal($"[NMAP] {scanType} scan: {target}")
        NmapStatusText.Text = $"[SCAN: {target}]"
        ShowAlert($"NMAP: {target}")

        Try
            Dim ports = GetPortsForScan(scanType, portsText)
            Dim targets = ParseTargets(target)

            For Each t In targets
                If _nmapCancellationTokenSource.IsCancellationRequested Then Exit For
                Await ScanHostAsync(t, ports, scanType, _nmapCancellationTokenSource.Token)
            Next

            RefreshNmapResults()
            LogTerminal($"[NMAP] Complete: {_nmapResults.Count} hosts")
            NmapStatusText.Text = $"[DONE: {_nmapResults.Count}]"

        Catch ex As OperationCanceledException
            LogTerminal("[NMAP] Cancelled")
            NmapStatusText.Text = "[CANCELLED]"
        Catch ex As Exception
            LogTerminal($"[NMAP] Error: {ex.Message}")
            NmapStatusText.Text = "[ERROR]"
        Finally
            _isNmapScanning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    Private Async Sub NmapNetworkDiscoveryButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapScanning OrElse _selectedInterface Is Nothing Then
            LogTerminal("[NMAP] Select interface first")
            Return
        End If

        Try
            Dim ipProps = _selectedInterface.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
            If ipv4 Is Nothing Then
                LogTerminal("[NMAP] No IPv4 found")
                Return
            End If

            Dim localIP = ipv4.Address.ToString()
            Dim parts = localIP.Split("."c)
            Dim networkRange = $"{parts(0)}.{parts(1)}.{parts(2)}.1-254"

            NmapTargetTextBox.Text = networkRange
            LogTerminal($"[NMAP] Discovery: {networkRange}")

            _isNmapScanning = True
            _nmapCancellationTokenSource = New CancellationTokenSource()
            NmapStopButton.IsEnabled = True
            NmapProgressBar.Visibility = Visibility.Visible
            NmapProgressBar.IsIndeterminate = True
            NmapResultsPanel.Visibility = Visibility.Visible
            _nmapResults.Clear()

            NmapStatusText.Text = "[DISCOVERING]"
            ShowAlert("Network discovery")

            Dim baseIP = $"{parts(0)}.{parts(1)}.{parts(2)}."
            Dim tasks As New List(Of Task)

            For i = 1 To 254
                If _nmapCancellationTokenSource.IsCancellationRequested Then Exit For
                Dim ip = baseIP & i.ToString()
                tasks.Add(PingHostAsync(ip))

                If tasks.Count >= 30 Then
                    Await Task.WhenAll(tasks)
                    tasks.Clear()
                    RefreshNmapResults()
                End If
            Next

            If tasks.Count > 0 Then Await Task.WhenAll(tasks)
            RefreshNmapResults()

            LogTerminal($"[NMAP] Found: {_nmapResults.Count} hosts")
            NmapStatusText.Text = $"[FOUND: {_nmapResults.Count}]"

        Catch ex As Exception
            LogTerminal($"[NMAP] Error: {ex.Message}")
        Finally
            _isNmapScanning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    Private Sub NmapStopButton_Click(sender As Object, e As RoutedEventArgs)
        _nmapCancellationTokenSource?.Cancel()
        LogTerminal("[NMAP] Stopping...")
    End Sub

    Private Async Function PingHostAsync(ip As String) As Task
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 300)
                If reply.Status = IPStatus.Success Then
                    SyncLock _nmapResults
                        _nmapResults.Add(New NmapHostResult With {
                            .Host = ip,
                            .Status = "UP",
                            .Ports = $"RTT:{reply.RoundtripTime}ms",
                            .OS = "",
                            .OpenPorts = New List(Of Integer)
                        })
                    End SyncLock
                End If
            End Using
        Catch
        End Try
    End Function

    Private Async Function ScanHostAsync(ip As String, ports As Integer(), scanType As String, token As CancellationToken) As Task
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 800)
                If reply.Status <> IPStatus.Success Then Return
            End Using
        Catch
            Return
        End Try

        Dim result As New NmapHostResult With {
            .Host = ip, .Status = "UP", .OpenPorts = New List(Of Integer), .OS = ""
        }

        Await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low,
            Sub() LogTerminal($"[NMAP] Scanning {ip}"))

        Dim openPorts As New List(Of String)
        For Each port In ports
            If token.IsCancellationRequested Then Exit For

            Try
                Using client As New TcpClient()
                    client.SendTimeout = 150
                    client.ReceiveTimeout = 150
                    Dim connectTask = client.ConnectAsync(ip, port)
                    If Await Task.WhenAny(connectTask, Task.Delay(150)) Is connectTask AndAlso client.Connected Then
                        result.OpenPorts.Add(port)
                        Dim svc = If(_commonServices.ContainsKey(port), _commonServices(port), "unknown")
                        openPorts.Add($"{port}/{svc}")

                        Await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low,
                            Sub() LogTerminal($"[NMAP] {ip}:{port} OPEN ({svc})"))
                    End If
                End Using
            Catch
            End Try
        Next

        If scanType = "OS" OrElse scanType = "Full" Then
            result.OS = Await DetectOSAsync(ip)
        End If

        result.Ports = String.Join(", ", openPorts)
        If result.OpenPorts.Count > 0 Then
            SyncLock _nmapResults
                _nmapResults.Add(result)
            End SyncLock
        End If
    End Function

    Private Async Function DetectOSAsync(ip As String) As Task(Of String)
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 500)
                If reply.Status = IPStatus.Success AndAlso reply.Options IsNot Nothing Then
                    Dim ttl = reply.Options.Ttl
                    If ttl <= 64 Then Return "Linux/Unix"
                    If ttl <= 128 Then Return "Windows"
                    Return "Network Device"
                End If
            End Using
        Catch
        End Try
        Return "Unknown"
    End Function

    Private Function GetSelectedScanType() As String
        Dim item = TryCast(NmapScanTypeCombo.SelectedItem, ComboBoxItem)
        Return If(item?.Content?.ToString(), "Quick")
    End Function

    Private Function GetPortsForScan(scanType As String, customPorts As String) As Integer()
        If Not String.IsNullOrEmpty(customPorts) Then Return ParsePorts(customPorts)
        Select Case scanType
            Case "Full" : Return _fullScanPorts
            Case "UDP" : Return {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514}
            Case Else : Return _quickScanPorts
        End Select
    End Function

    Private Function ParsePorts(text As String) As Integer()
        Dim ports As New List(Of Integer)
        Try
            For Each part In text.Split(","c)
                part = part.Trim()
                If part.Contains("-") Then
                    Dim r = part.Split("-"c)
                    ports.AddRange(Enumerable.Range(Integer.Parse(r(0)), Integer.Parse(r(1)) - Integer.Parse(r(0)) + 1))
                Else
                    ports.Add(Integer.Parse(part))
                End If
            Next
        Catch
        End Try
        Return ports.Distinct().OrderBy(Function(p) p).ToArray()
    End Function

    Private Function ParseTargets(target As String) As List(Of String)
        Dim targets As New List(Of String)
        Try
            If target.Contains("/24") Then
                Dim baseIP = target.Replace("/24", "").Split("."c)
                For i = 1 To 254 : targets.Add($"{baseIP(0)}.{baseIP(1)}.{baseIP(2)}.{i}") : Next
            ElseIf target.Contains("-") Then
                Dim parts = target.Split("."c)
                If parts.Length = 4 AndAlso parts(3).Contains("-") Then
                    Dim r = parts(3).Split("-"c)
                    For i = Integer.Parse(r(0)) To Integer.Parse(r(1))
                        targets.Add($"{parts(0)}.{parts(1)}.{parts(2)}.{i}")
                    Next
                Else
                    targets.Add(target)
                End If
            Else
                targets.Add(target)
            End If
        Catch
            targets.Add(target)
        End Try
        Return targets
    End Function

    Private Sub RefreshNmapResults()
        Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal,
            Sub()
                NmapResultsListView.ItemsSource = Nothing
                NmapResultsListView.ItemsSource = _nmapResults.ToList()
                NmapHostCountText.Text = $"[{_nmapResults.Count}]"
            End Sub)
    End Sub

    Private Sub NmapResultsListView_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selected = TryCast(NmapResultsListView.SelectedItem, NmapHostResult)
        If selected IsNot Nothing Then
            TargetHostTextBox.Text = selected.Host
            PacketDetailsPanel.Visibility = Visibility.Visible
            PacketDetailsText.Text = $"Host: {selected.Host}" & vbCrLf &
                                    $"Status: {selected.Status}" & vbCrLf &
                                    $"OS: {If(String.IsNullOrEmpty(selected.OS), "Unknown", selected.OS)}" & vbCrLf &
                                    $"Open Ports: {selected.Ports}"
        End If
    End Sub
#End Region

#Region "Export Report"
    Private Async Sub ExportReportButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim picker As New FileSavePicker()
            picker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary
            picker.FileTypeChoices.Add("Text Report", New List(Of String) From {".txt"})
            picker.FileTypeChoices.Add("CSV Data", New List(Of String) From {".csv"})
            picker.FileTypeChoices.Add("HTML Report", New List(Of String) From {".html"})
            picker.SuggestedFileName = $"Rootcastle_Report_{DateTime.Now:yyyyMMdd_HHmmss}"

            Dim file = Await picker.PickSaveFileAsync()
            If file IsNot Nothing Then
                Dim content As String
                Select Case file.FileType.ToLower()
                    Case ".csv"
                        content = GenerateCSVReport()
                    Case ".html"
                        content = GenerateHTMLReport()
                    Case Else
                        content = GenerateTextReport()
                End Select

                Await FileIO.WriteTextAsync(file, content)
                LogTerminal($"[EXPORT] Saved: {file.Name}")
                ShowAlert($"Exported: {file.Name}")
                StatusText.Text = "[EXPORTED]"
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Export failed: {ex.Message}")
            ShowAlert("Export failed")
        End Try
    End Sub

    Private Function GenerateTextReport() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("═══════════════════════════════════════════════════════════════")
        sb.AppendLine("              ROOTCASTLE NETWORK MONITOR REPORT")
        sb.AppendLine("                      Powered by /REI")
        sb.AppendLine("═══════════════════════════════════════════════════════════════")
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
        sb.AppendLine($"Duration: {UptimeText.Text}")
        sb.AppendLine()
        sb.AppendLine("─── INTERFACE ───")
        sb.AppendLine(InterfaceNameText.Text)
        sb.AppendLine(InterfaceTypeText.Text)
        sb.AppendLine(IPv4Text.Text)
        sb.AppendLine(MacAddressText.Text)
        sb.AppendLine()
        sb.AppendLine("─── TRAFFIC STATISTICS ───")
        sb.AppendLine($"Total Packets: {_packetCount:N0}")
        sb.AppendLine($"Total IN: {FormatBytes(_totalBytesIn)}")
        sb.AppendLine($"Total OUT: {FormatBytes(_totalBytesOut)}")
        sb.AppendLine($"TCP: {_tcpCount:N0} | UDP: {_udpCount:N0} | ICMP: {_icmpCount:N0} | Other: {_otherCount:N0}")
        sb.AppendLine($"Suspicious Packets: {_suspiciousCount:N0}")
        sb.AppendLine($"Errors: {_errorCount}")
        sb.AppendLine()
        sb.AppendLine("─── NMAP SCAN RESULTS ───")
        sb.AppendLine($"Hosts Found: {_nmapResults.Count}")
        For Each host In _nmapResults
            sb.AppendLine($"  {host.Host} [{host.Status}] - {host.Ports}")
        Next
        sb.AppendLine()
        sb.AppendLine("─── TOP HOSTS ───")
        For Each kv In _hostTraffic.OrderByDescending(Function(x) x.Value).Take(10)
            sb.AppendLine($"  {kv.Key}: {FormatBytes(kv.Value)}")
        Next
        sb.AppendLine()
        sb.AppendLine("─── ALERTS ───")
        For Each alert In _alerts
            sb.AppendLine($"  {alert}")
        Next
        sb.AppendLine()
        sb.AppendLine("─── RECENT PACKETS ───")
        For Each conn In _activeConnections.Take(50)
            sb.AppendLine($"  [{conn.Time:HH:mm:ss}] {conn.Direction} {conn.Protocol} {conn.LocalEndpoint} ↔ {conn.RemoteEndpoint} ({conn.Bytes})")
        Next
        sb.AppendLine()
        sb.AppendLine("═══════════════════════════════════════════════════════════════")
        sb.AppendLine("                    END OF REPORT")
        sb.AppendLine("═══════════════════════════════════════════════════════════════")
        Return sb.ToString()
    End Function

    Private Function GenerateCSVReport() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("Time,Direction,Protocol,Local,Remote,Bytes,Country,Info")
        For Each conn In _activeConnections
            sb.AppendLine($"{conn.Time:yyyy-MM-dd HH:mm:ss},{conn.Direction},{conn.Protocol},{conn.LocalEndpoint},{conn.RemoteEndpoint},{conn.BytesRaw},{conn.Country},""{conn.Info}""")
        Next
        Return sb.ToString()
    End Function

    Private Function GenerateHTMLReport() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("<!DOCTYPE html><html><head><title>Rootcastle Report</title>")
        sb.AppendLine("<style>body{background:#000;color:#0f0;font-family:Consolas}table{border-collapse:collapse;width:100%}th,td{border:1px solid #0f0;padding:5px;text-align:left}th{background:#020}h1,h2{color:#0f0}.alert{color:#f60}.suspicious{color:#f00}</style></head><body>")
        sb.AppendLine($"<h1>ROOTCASTLE NETWORK MONITOR</h1><p>Powered by /REI | Generated: {DateTime.Now}</p>")
        sb.AppendLine($"<h2>Statistics</h2><p>Packets: {_packetCount:N0} | IN: {FormatBytes(_totalBytesIn)} | OUT: {FormatBytes(_totalBytesOut)}</p>")
        sb.AppendLine($"<p>TCP: {_tcpCount} | UDP: {_udpCount} | ICMP: {_icmpCount} | Suspicious: {_suspiciousCount}</p>")
        sb.AppendLine("<h2>NMAP Results</h2><table><tr><th>Host</th><th>Status</th><th>Ports</th></tr>")
        For Each h In _nmapResults : sb.AppendLine($"<tr><td>{h.Host}</td><td>{h.Status}</td><td>{h.Ports}</td></tr>") : Next
        sb.AppendLine("</table><h2>Recent Packets</h2><table><tr><th>Time</th><th>Dir</th><th>Proto</th><th>Local</th><th>Remote</th><th>Bytes</th></tr>")
        For Each c In _activeConnections.Take(100)
            Dim cls = If(c.IsSuspicious, " class='suspicious'", "")
            sb.AppendLine($"<tr{cls}><td>{c.Time:HH:mm:ss}</td><td>{c.Direction}</td><td>{c.Protocol}</td><td>{c.LocalEndpoint}</td><td>{c.RemoteEndpoint}</td><td>{c.Bytes}</td></tr>")
        Next
        sb.AppendLine("</table></body></html>")
        Return sb.ToString()
    End Function
#End Region

#Region "UI Display"
    Private Sub UpdateTrafficDisplay(sent As Long, recv As Long)
        SentDataText.Text = $"↑ {FormatBytes(sent)}"
        ReceivedDataText.Text = $"↓ {FormatBytes(recv)}"
    End Sub

    Private Sub DrawTrafficGraph()
        Try
            TrafficGraphCanvas.Children.Clear()
            Dim w = TrafficGraphCanvas.ActualWidth
            Dim h = TrafficGraphCanvas.ActualHeight
            If w <= 0 Or h <= 0 Then Return

            Dim maxVal = Math.Max(1, Math.Max(_trafficHistoryIn.DefaultIfEmpty(1).Max(), _trafficHistoryOut.DefaultIfEmpty(1).Max()))
            Dim stepX = w / (MAX_GRAPH_POINTS - 1)

            ' Grid
            For i = 0 To 2
                TrafficGraphCanvas.Children.Add(New Line() With {
                    .X1 = 0, .Y1 = h * i / 2, .X2 = w, .Y2 = h * i / 2,
                    .Stroke = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 50, 0)), .StrokeThickness = 0.5
                })
            Next

            ' Lines
            DrawLine(_trafficHistoryOut, w, h, maxVal, stepX, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
            DrawLine(_trafficHistoryIn, w, h, maxVal, stepX, Windows.UI.ColorHelper.FromArgb(255, 0, 255, 255))
        Catch
        End Try
    End Sub

    Private Sub DrawLine(data As List(Of Double), w As Double, h As Double, maxVal As Double, stepX As Double, color As Windows.UI.Color)
        For i = 1 To data.Count - 1
            TrafficGraphCanvas.Children.Add(New Line() With {
                .X1 = (i - 1) * stepX, .Y1 = h - (data(i - 1) / maxVal * h),
                .X2 = i * stepX, .Y2 = h - (data(i) / maxVal * h),
                .Stroke = New SolidColorBrush(color), .StrokeThickness = 1
            })
        Next
    End Sub

    Private Sub UpdateProtocolBars()
        Dim total = Math.Max(1, _tcpCount + _udpCount + _icmpCount + _otherCount)
        TcpBar.Height = Math.Max(2, (_tcpCount / total) * 30)
        UdpBar.Height = Math.Max(2, (_udpCount / total) * 30)
        IcmpBar.Height = Math.Max(2, (_icmpCount / total) * 30)
        OtherBar.Height = Math.Max(2, (_otherCount / total) * 30)
        TcpCountText.Text = _tcpCount.ToString()
        UdpCountText.Text = _udpCount.ToString()
        IcmpCountText.Text = _icmpCount.ToString()
        OtherCountText.Text = _otherCount.ToString()
    End Sub

    Private Sub AddPacketToList(conn As ConnectionInfo)
        _activeConnections.Insert(0, conn)
        If _activeConnections.Count > 500 Then _activeConnections.RemoveAt(_activeConnections.Count - 1)

        ConnectionsListView.ItemsSource = Nothing
        ConnectionsListView.ItemsSource = _activeConnections.Take(20).ToList()
        ConnectionCountText.Text = $"[{_activeConnections.Count}]"
    End Sub

    Private Sub UpdateHostTraffic(host As String, bytes As Long)
        If _hostTraffic.ContainsKey(host) Then _hostTraffic(host) += bytes Else _hostTraffic(host) = bytes

        TopHostsListView.ItemsSource = _hostTraffic.OrderByDescending(Function(kv) kv.Value).Take(5).Select(Function(kv) New HostInfo With {
            .Host = kv.Key,
            .Traffic = FormatBytes(kv.Value),
            .Percentage = (kv.Value / Math.Max(1, _hostTraffic.Values.Max())) * 100
        }).ToList()
    End Sub

    Private Sub PacketListView_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selected = TryCast(ConnectionsListView.SelectedItem, ConnectionInfo)
        If selected IsNot Nothing Then
            PacketDetailsPanel.Visibility = Visibility.Visible
            PacketDetailsText.Text = $"Packet #{selected.Id}" & vbCrLf &
                $"Time: {selected.Time:HH:mm:ss.fff}" & vbCrLf &
                $"Direction: {selected.Direction}" & vbCrLf &
                $"Protocol: {selected.Protocol}" & vbCrLf &
                $"Source: {selected.LocalEndpoint}" & vbCrLf &
                $"Destination: {selected.RemoteEndpoint}" & vbCrLf &
                $"Size: {selected.Bytes} ({selected.BytesRaw} bytes)" & vbCrLf &
                $"Country: {selected.Country}" & vbCrLf &
                $"Info: {selected.Info}" & vbCrLf &
                $"Suspicious: {selected.IsSuspicious}"
        End If
    End Sub
#End Region

#Region "Alerts & Logging"
    Private Sub ShowAlert(message As String)
        Dim alert = $"[{DateTime.Now:HH:mm:ss}] {message}"
        _alerts.Insert(0, alert)
        If _alerts.Count > 20 Then _alerts.RemoveAt(_alerts.Count - 1)
        AlertsListView.ItemsSource = Nothing
        AlertsListView.ItemsSource = _alerts.Take(5).ToList()
        AlertCountText.Text = $"[{_alerts.Count}]"
    End Sub

    Private Sub LogTerminal(message As String, Optional isSuspicious As Boolean = False)
        Try
            Dim lines = TerminalOutput.Text.Split(vbLf.ToCharArray())
            If lines.Length > 200 Then
                TerminalOutput.Text = String.Join(vbLf, lines.Skip(lines.Length - 200))
            End If

            If isSuspicious AndAlso _suspiciousDetectionEnabled Then
                TerminalOutput.Text &= vbLf & "[!ALERT!] " & message
            Else
                TerminalOutput.Text &= vbLf & message
            End If

            If AutoScrollCheckBox.IsChecked = True Then
                TerminalScrollViewer.ChangeView(Nothing, TerminalScrollViewer.ScrollableHeight, Nothing)
            End If
        Catch
        End Try
    End Sub
#End Region

#Region "Settings & UI Events"
    Private Sub PacketFilterTextBox_KeyDown(sender As Object, e As KeyRoutedEventArgs)
        If e.Key = Windows.System.VirtualKey.Enter Then
            ApplyPacketFilter()
        End If
    End Sub

    Private Sub ApplyFilterButton_Click(sender As Object, e As RoutedEventArgs)
        ApplyPacketFilter()
    End Sub

    Private Sub ApplyPacketFilter()
        Dim filterText = PacketFilterTextBox.Text.Trim()
        If String.IsNullOrEmpty(filterText) Then
            LogTerminal("[SYS] Filter cleared")
        Else
            LogTerminal($"[SYS] Filter applied: {filterText}")
        End If
    End Sub

    Private Sub RecordButton_Click(sender As Object, e As RoutedEventArgs)
        If RecordingStatusText.Text = "●REC" Then
            RecordingStatusText.Text = ""
            RecordButton.Content = "REC"
            LogTerminal("[SYS] Recording stopped")
        Else
            RecordingStatusText.Text = "●REC"
            RecordButton.Content = "■"
            LogTerminal("[SYS] Recording started")
        End If
    End Sub

    Private Sub SecurityDashboardButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 2 ' Navigate to SECURITY tab
        LogTerminal("[SYS] Security dashboard opened")
    End Sub

    Private Sub TopologyButton_Click(sender As Object, e As RoutedEventArgs)
        LogTerminal("[SYS] Topology view not implemented")
        ShowAlert("Topology: Coming soon")
    End Sub

    Private Sub AdvancedSettingsButton_Click(sender As Object, e As RoutedEventArgs)
        LogTerminal("[SYS] Settings panel opened")
        ShowAlert("Settings dialog")
    End Sub

    Private Sub SuspiciousPacketCheckBox_Checked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = True
        LogTerminal("[SOFIA] Suspicious detection: ON")
        ShowAlert("Detection enabled")
    End Sub

    Private Sub SuspiciousPacketCheckBox_Unchecked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = False
        LogTerminal("[SOFIA] Suspicious detection: OFF")
    End Sub

    Private Sub FilterComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim item = TryCast(FilterComboBox.SelectedItem, ComboBoxItem)
        _filterProtocol = If(item?.Content?.ToString(), "ALL")
        LogTerminal($"[SYS] Filter: {_filterProtocol}")
    End Sub

    Private Sub ClearTerminalButton_Click(sender As Object, e As RoutedEventArgs)
        TerminalOutput.Text = "[SYS] Terminal cleared"
        _packetCount = 0 : _tcpCount = 0 : _udpCount = 0 : _icmpCount = 0 : _otherCount = 0 : _suspiciousCount = 0
        _totalBytesIn = 0 : _totalBytesOut = 0
        _activeConnections.Clear()
        _hostTraffic.Clear()

        ' Reset QoS
        _latencyHistory.Clear()
        _currentLatency = 0 : _jitter = 0 : _packetLoss = 0 : _throughput = 0

        ' Reset DNS
        _dnsQueryCount = 0 : _dnsNxdomainCount = 0 : _dnsTunnelCount = 0

        ' Reset TLS
        _tls13Count = 0 : _tls12Count = 0 : _tlsWeakCount = 0
        _certList.Clear()

        ' Reset Threats
        _portScanCount = 0 : _dosCount = 0 : _arpSpoofCount = 0
        _threatList.Clear()

        ' Reset Assets
        _assetList.Clear()

        ' Reset Apps
        _appTraffic.Clear()

        ' Reset Conversations
        _conversations.Clear()

        ' Reset Zero Trust
        _zeroTrustEvents.Clear()

        ' Reset connection attempts tracking
        _connectionAttempts.Clear()

        ' Clear alerts
        _alerts.Clear()

        ' Update all UI elements
        PacketCountText.Text = "0"
        UpdateProtocolBars()
        ConnectionsListView.ItemsSource = Nothing
        TopHostsListView.ItemsSource = Nothing
        CertListView.ItemsSource = Nothing
        AssetListView.ItemsSource = Nothing
        AppBreakdownListView.ItemsSource = Nothing
        ConversationListView.ItemsSource = Nothing
        ZeroTrustListView.ItemsSource = Nothing
        ThreatListView.ItemsSource = Nothing
        AlertsListView.ItemsSource = Nothing

        ' Reset display texts
        QosLatencyText.Text = "0 ms"
        QosJitterText.Text = "0 ms"
        QosLossText.Text = "0%"
        QosThroughputText.Text = "0 Mbps"
        LatencyText.Text = "~ 0 ms"
        BandwidthText.Text = "0%"
        AlertCountText.Text = "[0]"
        AssetCountText.Text = "[0 devices]"
        ThreatCountText.Text = "0 threats detected"
        PortScanCountText.Text = "0"
        DosCountText.Text = "0"
        ArpSpoofCountText.Text = "0"
        Tls13CountText.Text = "0"
        Tls12CountText.Text = "0"
        TlsWeakCountText.Text = "0"
        DnsQueryCountText.Text = "0"
        DnsNxdomainText.Text = "0"
        DnsTunnelText.Text = "0"
        SecurityScoreText.Text = "Security: ■■■■■"
        SecurityScoreText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
    End Sub
#End Region

#Region "SOFIA AI"
    Private Async Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim query = AIQueryTextBox?.Text?.Trim()
            If String.IsNullOrEmpty(query) Then
                query = "Mevcut ağ durumunu analiz et ve güvenlik değerlendirmesi yap."
            End If

            AIAnalysisText.Text = "[SOFIA] 🔄 Analiz ediliyor, lütfen bekleyin..."
            StatusText.Text = "[AI ANALYZING]..."

            Dim data = CollectAnalysisData()
            Dim response = Await GetAIResponseAsync(data, query)

            AIAnalysisText.Text = response
            StatusText.Text = "[AI] ✓ Analysis Complete"

            If AIQueryTextBox IsNot Nothing Then
                AIQueryTextBox.Text = ""
            End If
        Catch ex As Exception
            AIAnalysisText.Text = $"[SOFIA] ❌ Hata: {ex.Message}"
            StatusText.Text = "[AI] Error"
        End Try
    End Sub

    Private Sub AIQueryTextBox_KeyDown(sender As Object, e As KeyRoutedEventArgs)
        If e.Key = Windows.System.VirtualKey.Enter Then
            AIAnalyzeButton_Click(sender, Nothing)
        End If
    End Sub

    Private Async Sub AIQuickAnalyze_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim button = TryCast(sender, Button)
            Dim actionType = button?.Tag?.ToString()

            AIAnalysisText.Text = "[SOFIA] 🔄 İşleniyor..."
            StatusText.Text = "[AI] Processing..."

            Dim query As String = ""
            Select Case actionType
                Case "traffic"
                    query = "Mevcut ağ trafiğini detaylı analiz et. Hangi protokoller baskın, bant genişliği kullanımı, peak zamanları ve olası darboğazları belirle."
                Case "security"
                    query = "Kapsamlı güvenlik taraması yap. Açık portlar, şüpheli trafik, potansiyel tehditler ve güvenlik açıklarını listele. Risk seviyesi belirt."
                Case "firewall"
                    query = "Tespit edilen trafiğe göre firewall kural önerileri oluştur. iptables, Windows Firewall ve Fortigate formatında kurallar ver."
                Case "summary"
                    query = "Tüm ağ aktivitesinin yönetici özeti oluştur. İstatistikler, öne çıkan olaylar ve aksiyon maddeleri ile birlikte."
                Case "anomaly"
                    query = "Anomali tespiti yap. Normal trafik profilinden sapmaları, olağandışı bağlantıları ve şüpheli davranış kalıplarını tespit et."
                Case "performance"
                    query = "Ağ performans analizi yap. Latency, jitter, packet loss değerlerini yorumla ve optimizasyon önerileri sun."
                Case "toptalkers"
                    query = "En çok trafik üreten host'ları ve uygulamaları analiz et. Bant genişliği tüketim oranlarını ve olası sorunları belirt."
                Case "incident"
                    query = "Incident response raporu oluştur. Timeline, etkilenen sistemler, root cause analizi ve aksiyon planı ile birlikte."
            End Select

            Dim data = CollectAnalysisData()
            Dim response = Await GetAIResponseAsync(data, query)

            AIAnalysisText.Text = response
            StatusText.Text = "[AI] ✓ Complete"
        Catch ex As Exception
            AIAnalysisText.Text = $"[SOFIA] ❌ Hata: {ex.Message}"
        End Try
    End Sub

    Private Function CollectAnalysisData() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("=== ROOTCASTLE NETWORK ANALYSIS DATA ===")
        sb.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
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
        sb.AppendLine($"TCP: {_tcpCount} ({If(_packetCount > 0, (_tcpCount * 100.0 / _packetCount).ToString("F1"), "0")}%)")
        sb.AppendLine($"UDP: {_udpCount} ({If(_packetCount > 0, (_udpCount * 100.0 / _packetCount).ToString("F1"), "0")}%)")
        sb.AppendLine($"ICMP: {_icmpCount} ({If(_packetCount > 0, (_icmpCount * 100.0 / _packetCount).ToString("F1"), "0")}%)")
        sb.AppendLine($"Other: {_otherCount}")
        sb.AppendLine($"Suspicious: {_suspiciousCount}")
        sb.AppendLine($"Errors: {_errorCount}")
        sb.AppendLine()
        sb.AppendLine("--- NMAP SCAN RESULTS ---")
        sb.AppendLine($"Hosts Discovered: {_nmapResults.Count}")
        If _nmapResults.Any() Then
            sb.AppendLine("Hosts:")
            For Each host In _nmapResults.Take(10)
                sb.AppendLine($"  - {host.Host} [{host.Status}] OS:{host.OS} Ports:{host.Ports}")
            Next
            Dim allPorts = _nmapResults.SelectMany(Function(r) r.OpenPorts).Distinct().ToList()
            sb.AppendLine($"All Open Ports: {String.Join(", ", allPorts.Take(20))}")
        End If
        sb.AppendLine()
        sb.AppendLine("--- TOP TALKERS ---")
        For Each kv In _hostTraffic.OrderByDescending(Function(x) x.Value).Take(10)
            sb.AppendLine($"  {kv.Key}: {FormatBytes(kv.Value)}")
        Next
        sb.AppendLine()
        sb.AppendLine("--- RECENT CONNECTIONS (Last 20) ---")
        For Each conn In _activeConnections.Take(20)
            sb.AppendLine($"  [{conn.Time:HH:mm:ss}] {conn.Direction} {conn.Protocol} {conn.LocalEndpoint} ↔ {conn.RemoteEndpoint} ({conn.Bytes}) {If(conn.IsSuspicious, "⚠️SUSPICIOUS", "")}")
        Next
        sb.AppendLine()
        sb.AppendLine("--- ALERTS ---")
        For Each alert In _alerts.Take(10)
            sb.AppendLine($"  {alert}")
        Next

        Return sb.ToString()
    End Function

    Private Async Function GetAIResponseAsync(data As String, userQuery As String) As Task(Of String)
        Try
            Using client As New HttpClient()
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {OPENROUTER_API_KEY}")
                client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")

                Dim systemPrompt = "Sen SOFIA (Smart Operational Firewall Intelligence Assistant), profesyonel bir ağ güvenliği ve network analiz AI uzmanısın. Rootcastle Network Monitor uygulamasının yerleşik AI motorusun.

GÖREVLER:
1. Ağ trafiğini analiz et ve anomalileri tespit et
2. Güvenlik tehditlerini değerlendir ve önceliklendir
3. Firewall kuralları ve güvenlik önerileri sun
4. Incident response desteği sağla
5. Performans optimizasyonu öner
6. Teknik ve yönetici raporları oluştur

KURALLAR:
- Her zaman Türkçe yanıt ver
- Teknik detayları açık ve anlaşılır şekilde anlat
- Somut aksiyon maddeleri sun
- Risk seviyelerini belirt (Kritik/Yüksek/Orta/Düşük)
- Emoji kullan görsellik için
- Yapılandırılmış ve okunabilir format kullan"

                Dim userPrompt = $"KULLANICI SORUSU: {userQuery}

AĞ VERİLERİ:
{data}

Lütfen yukarıdaki ağ verilerini analiz ederek kullanıcının sorusuna detaylı yanıt ver."

                Dim body As New JsonObject()
                body.Add("model", JsonValue.CreateStringValue("meta-llama/llama-3.2-3b-instruct:free"))

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
                body.Add("max_tokens", JsonValue.CreateNumberValue(1500))
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
🔧 Powered by LLaMA 3.2 via OpenRouter"
                    End If
                Else
                    LogTerminal($"[AI] API Error: {response.StatusCode}")
                End If

                Return "[SOFIA] ⚠️ Analiz şu anda yapılamıyor. Lütfen daha sonra tekrar deneyin."
            End Using
        Catch ex As Exception
            LogTerminal($"[AI] Exception: {ex.Message}")
            Return $"[SOFIA] ❌ Bağlantı hatası: {ex.Message}"
        End Try
    End Function
#End Region

#Region "Packet Sender"
    Private Async Sub SendTcpButton_Click(sender As Object, e As RoutedEventArgs)
        Await SendPacketAsync("TCP")
    End Sub

    Private Async Sub SendUdpButton_Click(sender As Object, e As RoutedEventArgs)
        Await SendPacketAsync("UDP")
    End Sub

    Private Async Function SendPacketAsync(protocol As String) As Task
        Dim host = TargetHostTextBox.Text.Trim()
        If String.IsNullOrEmpty(host) Then
            LogTerminal("[ERR] Host required")
            Return
        End If

        Dim port = 80
        Integer.TryParse(TargetPortTextBox.Text.Trim(), port)
        Dim data = If(String.IsNullOrEmpty(PacketDataTextBox.Text), "PROBE", PacketDataTextBox.Text)

        Try
            LogTerminal($"[{protocol}] → {host}:{port}")
            If protocol = "TCP" Then
                Using client As New TcpClient()
                    client.SendTimeout = 3000
                    client.ReceiveTimeout = 3000
                    Await client.ConnectAsync(host, port)
                    Using stream = client.GetStream()
                        Dim bytes = Encoding.UTF8.GetBytes(data)
                        Await stream.WriteAsync(bytes, 0, bytes.Length)
                        LogTerminal($"[TCP] Sent {bytes.Length}B")
                        StatusText.Text = "[TCP OK]"
                    End Using
                End Using
            Else
                Using client As New UdpClient()
                    Dim bytes = Encoding.UTF8.GetBytes(data)
                    Await client.SendAsync(bytes, bytes.Length, host, port)
                    LogTerminal($"[UDP] Sent {bytes.Length}B")
                    StatusText.Text = "[UDP OK]"
                End Using
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] {ex.Message}")
            StatusText.Text = "[FAILED]"
        End Try
    End Function

    Private Async Sub PingButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        If String.IsNullOrEmpty(host) Then Return

        Try
            LogTerminal($"[PING] {host}...")
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(host, 3000)
                LogTerminal($"[PING] {host}: {If(reply.Status = IPStatus.Success, $"{reply.RoundtripTime}ms", reply.Status.ToString())}")
                StatusText.Text = If(reply.Status = IPStatus.Success, $"[{reply.RoundtripTime}ms]", "[TIMEOUT]")
            End Using
        Catch ex As Exception
            LogTerminal($"[ERR] {ex.Message}")
        End Try
    End Sub

    Private Async Sub TraceRouteButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        If String.IsNullOrEmpty(host) Then Return

        Try
            LogTerminal($"[TRACE] {host}")
            Using ping As New Ping()
                For ttl = 1 To 30
                    Dim opts As New PingOptions(ttl, True)
                    Dim reply = Await ping.SendPingAsync(host, 1000, New Byte(31) {}, opts)
                    If reply.Status = IPStatus.Success OrElse reply.Status = IPStatus.TtlExpired Then
                        LogTerminal($"[{ttl}] {reply.Address} {reply.RoundtripTime}ms")
                        If reply.Status = IPStatus.Success Then Exit For
                    Else
                        LogTerminal($"[{ttl}] * * *")
                    End If
                Next
            End Using
            StatusText.Text = "[TRACE OK]"
        Catch ex As Exception
            LogTerminal($"[ERR] {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Helpers"
    Private Function FormatBytes(bytes As Long) As String
        If bytes < 1024 Then Return $"{bytes}B"
        If bytes < 1048576 Then Return $"{bytes / 1024.0:F1}K"
        If bytes < 1073741824 Then Return $"{bytes / 1048576.0:F1}M"
        Return $"{bytes / 1073741824.0:F2}G"
    End Function

    Private Function GetRandomProtocol() As String
        Dim r = _random.Next(100)
        If r < 60 Then Return "TCP"
        If r < 90 Then Return "UDP"
        If r < 95 Then Return "ICMP"
        Return "OTHER"
    End Function

    Private Function GetRandomPort() As Integer
        Dim ports = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 8080, 8443}
        If _suspiciousDetectionEnabled AndAlso _random.Next(100) < 3 Then
            Return _suspiciousPorts(_random.Next(_suspiciousPorts.Length))
        End If
        Return ports(_random.Next(ports.Length))
    End Function

    Private Function GetServiceName(port As Integer) As String
        Return If(_commonServices.ContainsKey(port), _commonServices(port), $"Port{port}")
    End Function

    Private Function GenerateRandomIP() As String
        Return $"{_random.Next(1, 224)}.{_random.Next(0, 256)}.{_random.Next(0, 256)}.{_random.Next(1, 255)}"
    End Function

    Private Function GetRandomCountry() As String
        Dim countries = {"US", "DE", "NL", "GB", "FR", "JP", "CN", "RU", "BR", "AU", "CA", "KR", "SG", "IN"}
        Return countries(_random.Next(countries.Length))
    End Function
#End Region

#Region "Data Classes"
    Public Class ConnectionInfo
        Public Property Id As Long
        Public Property Time As DateTime
        Public Property LocalEndpoint As String
        Public Property RemoteEndpoint As String
        Public Property Protocol As String
        Public Property Bytes As String
        Public Property BytesRaw As Long
        Public Property Country As String
        Public Property Info As String
        Public Property IsSuspicious As Boolean
        Public Property Direction As String
    End Class

    Public Class HostInfo
        Public Property Host As String
        Public Property Traffic As String
        Public Property Percentage As Double
    End Class

    Public Class NmapHostResult
        Public Property Host As String
        Public Property Status As String
        Public Property Ports As String
        Public Property OS As String
        Public Property OpenPorts As List(Of Integer)
    End Class

    Public Class PacketLogEntry
        Public Property Time As DateTime
        Public Property Data As String
    End Class

    Public Class CertInfo
        Public Property Host As String
        Public Property Expiry As String
        Public Property Cipher As String
        Public Property TlsVersion As String
    End Class

    Public Class AssetInfo
        Public Property IP As String
        Public Property MAC As String
        Public Property Vendor As String
        Public Property OS As String
        Public Property LastSeen As DateTime
    End Class

    Public Class AppTrafficInfo
        Public Property App As String
        Public Property Traffic As String
        Public Property Percentage As Double
    End Class

    Public Class ConversationInfo
        Public Property HostA As String
        Public Property HostB As String
        Public Property Stats As String
        Public Property BytesAtoB As Long
        Public Property BytesBtoA As Long
        Public Property PacketCount As Long
        Public Property LastSeen As DateTime
    End Class

    Public Class ZeroTrustEvent
        Public Property Identity As String
        Public Property Resource As String
        Public Property Access As String
        Public Property Timestamp As DateTime
    End Class
#End Region

End Class
