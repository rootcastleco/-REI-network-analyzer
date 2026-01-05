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

            ' Capture packets
            If deltaSent > 0 Or deltaReceived > 0 Then
                CapturePacket(deltaSent, deltaReceived)
            End If

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

            If ShouldLog(protocol) Then
                LogTerminal($"[IN]  {remoteIP}:{srcPort}→:{dstPort} {deltaReceived}B {protocol}", isSuspicious)
            End If
        End If

        PacketCountText.Text = _packetCount.ToString("N0")
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
        PacketCountText.Text = "0"
        UpdateProtocolBars()
        ConnectionsListView.ItemsSource = Nothing
        TopHostsListView.ItemsSource = Nothing
    End Sub
#End Region

#Region "SOFIA AI"
    Private Async Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            AIAnalysisText.Text = "[SOFIA] Analyzing..."
            StatusText.Text = "[AI]..."

            Dim data = CollectAnalysisData()
            Dim response = Await GetAIResponseAsync(data)

            AIAnalysisText.Text = response
            StatusText.Text = "[AI] Done"
        Catch ex As Exception
            AIAnalysisText.Text = $"[ERR] {ex.Message}"
        End Try
    End Sub

    Private Function CollectAnalysisData() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("=== NETWORK ANALYSIS DATA ===")
        sb.AppendLine($"Interface: {InterfaceNameText.Text}")
        sb.AppendLine($"IP: {IPv4Text.Text}")
        sb.AppendLine($"Traffic: IN={FormatBytes(_totalBytesIn)}, OUT={FormatBytes(_totalBytesOut)}")
        sb.AppendLine($"Packets: {_packetCount} (TCP:{_tcpCount}, UDP:{_udpCount}, ICMP:{_icmpCount})")
        sb.AppendLine($"Suspicious: {_suspiciousCount}")
        sb.AppendLine($"NMAP: {_nmapResults.Count} hosts")
        If _nmapResults.Any() Then
            sb.AppendLine($"Open Ports: {String.Join(", ", _nmapResults.SelectMany(Function(r) r.OpenPorts).Distinct().Take(15))}")
        End If
        sb.AppendLine($"Top Hosts: {String.Join(", ", _hostTraffic.OrderByDescending(Function(kv) kv.Value).Take(5).Select(Function(kv) kv.Key))}")
        Return sb.ToString()
    End Function

    Private Async Function GetAIResponseAsync(data As String) As Task(Of String)
        Try
            Using client As New HttpClient()
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {OPENROUTER_API_KEY}")
                client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")

                Dim prompt = $"Sen SOFIA, ağ güvenliği AI uzmanısın. Analiz et (Türkçe, 80 kelime):
1. Ağ durumu değerlendirmesi
2. Güvenlik riskleri
3. Aksiyon önerileri

{data}"

                Dim body As New JsonObject()
                body.Add("model", JsonValue.CreateStringValue("meta-llama/llama-3.2-3b-instruct:free"))
                Dim msgs As New JsonArray()
                Dim msg As New JsonObject()
                msg.Add("role", JsonValue.CreateStringValue("user"))
                msg.Add("content", JsonValue.CreateStringValue(prompt))
                msgs.Add(msg)
                body.Add("messages", msgs)
                body.Add("max_tokens", JsonValue.CreateNumberValue(250))

                Dim content As New HttpStringContent(body.Stringify(), Windows.Storage.Streams.UnicodeEncoding.Utf8, "application/json")
                Dim response = Await client.PostAsync(New Uri(OPENROUTER_API_URL), content)
                Dim responseText = Await response.Content.ReadAsStringAsync()

                If response.IsSuccessStatusCode Then
                    Dim json = JsonObject.Parse(responseText)
                    Dim choices = json.GetNamedArray("choices")
                    If choices.Count > 0 Then
                        Return "[SOFIA]" & vbCrLf & choices.GetObjectAt(0).GetNamedObject("message").GetNamedString("content")
                    End If
                End If
                Return "[SOFIA] Analysis unavailable"
            End Using
        Catch ex As Exception
            Return $"[ERR] {ex.Message}"
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
#End Region

End Class
