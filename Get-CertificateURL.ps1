function Get-CertificateURL {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]
        $Certs
    )

    BEGIN
    {

$Signature = @"
[StructLayoutAttribute(LayoutKind.Sequential)]
public struct CRYPT_URL_ARRAY {
    public uint cUrl;
    public IntPtr rgwszUrl;
}

[DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern bool CryptGetObjectUrl(
    int pszUrlOid,
    IntPtr pvPara,
    int dwFlags,
    IntPtr pUrlArray,
    ref int pcbUrlArray,
    IntPtr pUrlInfo,
    ref int pcbUrlInfo,
    int pvReserved
);
"@;

        if (-not ([System.Management.Automation.PSTypeName][PKI.CryptNet]).Type) {
            Add-Type -MemberDefinition $Signature -Namespace PKI -Name CryptNet;
        }

        [int] $CRYPT_GET_URL_FROM_EXTENSION = 2;

        [int] $URL_OID_CERTIFICATE_ISSUER = 1;
        [int] $URL_OID_CERTIFICATE_CRL_DIST_POINT = 2;
        [int] $URL_OID_CERTIFICATE_ONLY_OCSP = 13;

        [System.IntPtr] $pvPara = [System.IntPtr]::Zero;
        [int] $dwFlags = $CRYPT_GET_URL_FROM_EXTENSION;
        [System.IntPtr] $pUrlArray = [System.IntPtr]::Zero;
        [int] $pcbUrlArray = 0;
        [System.IntPtr] $pUrlInfo = [System.IntPtr]::Zero;
        [int] $pcbUrlInfo = 0;

        [PKI.CryptNet+CRYPT_URL_ARRAY] $CryptUrlArray = New-Object -TypeName PKI.CryptNet+CRYPT_URL_ARRAY;
        [System.IntPtr] $StrArrPtr = [System.IntPtr]::Zero;
        [System.IntPtr] $StrPtr = [System.IntPtr]::Zero;
        [string] $Url = [string]::Empty;

        [psobject] $URLs = $null;

        $URLs = New-Object psobject -Property @{
            CDP = @();
            AIA = @();
            OCSP = @();
        }

    }

    PROCESS
    {

        $pvPara = $Cert.Handle;

        if ($pvPara.Equals([System.IntPtr]::Zero))
        {
            return;
        }

        foreach ($pszUrlOid in $URL_OID_CERTIFICATE_ISSUER, $URL_OID_CERTIFICATE_CRL_DIST_POINT, $URL_OID_CERTIFICATE_ONLY_OCSP)
        {

            $pUrlArray = [System.IntPtr]::Zero;
            $pcbUrlArray = 0;
            $pUrlInfo = [System.IntPtr]::Zero;
            $pcbUrlInfo = 0;

            if ([PKI.CryptNet]::CryptGetObjectUrl($pszUrlOid, $pvPara, $dwFlags, $pUrlArray, [ref]$pcbUrlArray, $pUrlInfo, [ref]$pcbUrlInfo, $null) -eq $true)
            {

                $pUrlArray = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pcbUrlArray);
                $pUrlInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pcbUrlInfo);

                [void][PKI.Cryptnet]::CryptGetObjectUrl($pszUrlOid, $pvPara, $dwFlags, $pUrlArray, [ref]$pcbUrlArray, $pUrlInfo, [ref]$pcbUrlInfo, $null)

                $CryptUrlArray = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pUrlArray, [System.Type][PKI.CryptNet+CRYPT_URL_ARRAY]);           
                for ([int] $i = 0; $i -lt $CryptUrlArray.cUrl; $i++)
                {
                    $StrArrPtr = [IntPtr]($CryptUrlArray.rgwszUrl.ToInt64() + ([IntPtr]::Size * $i));
                    $StrPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($StrArrPtr);
                    $Url = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($StrPtr);
                    switch ($pszUrlOid)
                    {
                        $URL_OID_CERTIFICATE_ISSUER         { $URLs.AIA  += $Url; }
                        $URL_OID_CERTIFICATE_CRL_DIST_POINT { $URLs.CDP  += $Url; }
                        $URL_OID_CERTIFICATE_ONLY_OCSP      { $URLs.OCSP += $Url; }
                    }
                }

                [void][Runtime.InteropServices.Marshal]::FreeHGlobal($pUrlArray);
                [void][Runtime.InteropServices.Marshal]::FreeHGlobal($pUrlInfo);

            }
        }
    }

    END
    {
        Write-Output -InputObject $URLs;
    }
}
