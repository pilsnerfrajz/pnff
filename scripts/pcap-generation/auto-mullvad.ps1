#Requires -RunAsAdministrator

param (
    [string]$NetworkInterface,
    [string]$OutputFile
)

function Invoke-LocalMullvadCapture {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("lwo", "shadowsocks", "off")]
        [string]$Mode
    )

    Start-Service -Name "MullvadVPN" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    mullvad relay set location se > $null
    mullvad anti-censorship set mode $Mode > $null

    if ($Mode -eq "off") {
        $Mode = "vanilla"
    }

    for ($i = 1; $i -le 473; $i++) {
        Start-Sleep -Seconds 3

        $CurrentFile = "${OutputFile}_${Mode}_${i}.pcap"
        echo "Starting capture iteration $i. Output file: $CurrentFile"

        # Start tshark in the background and save the process to a variable
        $tsharkArgs = "-i $Interface -w $CurrentFile"
        $captureProcess = Start-Process -FilePath "C:\Program Files\Wireshark\tshark.exe" -ArgumentList $tsharkArgs -PassThru -WindowStyle Hidden

        Start-Service -Name "MullvadVPN" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        mullvad connect -w > $null

        echo "Mullvad status: $(mullvad status)"
        $status = mullvad status
        if ($status -match "Blocked") {
            $captureProcess | Stop-Process -Force
            return 1
        }

        # Simulate browsing, although a simple ping is probably enough
        # We just need the handshake to be completed
        # This keeps the connection consistent with previous tests
        curl.exe -s "https://svtplay.se" > $null
        curl.exe -s "https://svtplay.se/program" > $null
        curl.exe -s "https://svtplay.se/program/historia" > $null

        # Stop the local capture process
        $captureProcess | Stop-Process -Force

        mullvad disconnect -w > $null
        mullvad status
        Stop-Service -Name "MullvadVPN" -Force
    }
}

Invoke-LocalMullvadCapture -Mode "off"
Invoke-LocalMullvadCapture -Mode "lwo"
Invoke-LocalMullvadCapture -Mode "shadowsocks"
