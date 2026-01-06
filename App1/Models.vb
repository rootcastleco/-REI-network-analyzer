Option Strict On
Option Explicit On

Imports System

' Shared / simple models used by `MainPage.xaml.vb`.

Public Class ConnectionInfo
    Public Property Id As Long
    Public Property Timestamp As DateTime
    Public Property SourceIP As String
    Public Property DestIP As String
    Public Property Protocol As String
    Public Property Length As Long
    Public Property Info As String

    ' Convenience properties for UI bindings
    Public ReadOnly Property Key As String
        Get
            Return $"{SourceIP}-{DestIP}-{Protocol}"
        End Get
    End Property

    Public ReadOnly Property LocalEndpoint As String
        Get
            Return SourceIP
        End Get
    End Property

    Public ReadOnly Property RemoteEndpoint As String
        Get
            Return DestIP
        End Get
    End Property

    Public ReadOnly Property Bytes As String
        Get
            Return Length.ToString()
        End Get
    End Property
End Class

Public Class PacketLogEntry
    Public Property Id As Long
    Public Property Timestamp As DateTime
    Public Property Message As String
    Public Property Level As String
End Class

Public Class CertInfo
    Public Property Host As String
    Public Property Expiry As String
    Public Property Cipher As String
End Class

Public Class AssetInfo
    Public Property IP As String
    Public Property MAC As String
    Public Property Vendor As String
    Public Property OS As String
End Class

Public Class ConversationInfo
    Public Property HostA As String
    Public Property HostB As String
    Public Property Stats As String
End Class

Public Class ZeroTrustEvent
    Public Property Identity As String
    Public Property Resource As String
    Public Property Access As String
End Class

Public Class NmapHostResult
    Public Property Host As String
    Public Property Status As String
    Public Property Ports As String
    Public Property OS As String
    Public Property OpenPorts As List(Of Integer)
End Class
