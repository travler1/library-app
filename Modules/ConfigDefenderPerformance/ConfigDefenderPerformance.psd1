@{
    GUID = 'A51E6D9E-BC14-41A7-98A8-888195641250'
    Author="Microsoft Corporation"
    CompanyName="Microsoft Corporation"
    Copyright="Copyright (C) Microsoft Corporation. All rights reserved."
    ModuleVersion = '1.0'
    NestedModules = @('MSFT_MpPerformanceRecording.psm1')

    FormatsToProcess = @('MSFT_MpPerformanceReport.Format.ps1xml')

    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @( 'New-MpPerformanceRecording',
                           'Get-MpPerformanceReport'
                           )
    HelpInfoUri="https://aka.ms/winsvr-2022-pshelp"
    PowerShellVersion = '5.1'
}

# SIG # Begin signature block
# MIIllwYJKoZIhvcNAQcCoIIliDCCJYQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALMtnQG5KhaVi8
# /j7ONkfb/EMugE0iBrx7n8hqD9uLdaCCC1MwggTgMIIDyKADAgECAhMzAAAK7CQL
# sju2bxocAAAAAArsMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMTAxOTE5MTgwM1oXDTI0MTAxNjE5MTgwM1owcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDxlYs7SirE
# 2DMWmJDHmyPDmkzh+fLl2bNdYJFYVIxEDXmuYo7qVT/TlzRyHZNjfnCpNIN5BGy+
# tL1DHfbYMyeZ64rRBk5ZDyfxpC0PjuOKeo8l1Yp0DYH8o/tovvyg/7t7RBqawaFi
# 8mo9wrD5ISkTwSSMv2itkTg00L+gE8awFU17AUmplCQ9mZ91C/9wLp9wH9bIBGm5
# LnsMVzGxaxLbcqzuyi0CUj0ANTuQNZUFNTvLWj/k3W3j7iiNZRDaniVqF2i7UEpU
# Twl0A2/ET31/zrvHBzhJKaUtC31IicLI8HqTuUA96FAxGfczxleoZI6jXS2sWSYI
# wU6YnckWSSAhAgMBAAGjggFoMIIBZDAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUK97sk9qa9IVpYVlzmmULjVzY6akwRQYDVR0RBD4w
# PKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMN
# MjMwMDI4KzUwMTcwMjAfBgNVHSMEGDAWgBTRT6mKBwjO9CQYmOUA//PWeR03vDBT
# BgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5jcmwwVwYIKwYBBQUHAQEE
# SzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4IBAQArGdljm580qkATgRqYVsgvfdFUkL/7TpOb8yh1h5vk2SEL
# El5Bfz46bs3+ywayV/mXd8Y43M3yku5Dp7dMwRXkze6j4LJLpLQ4CMPN4fvtlPkb
# w+fQmXkHjogsb4bcJo/aUKfLy4hGUbw+uqKBLx0RRIEj6Vj2m5W7lB+rdBl8hhtr
# v5F4HYoy9lvXQhGGDwSsph+0uaZvCXSP7DOM3wOaYUQSNX6hYF5EHZsPrd334YGd
# dTWIPRHrOWqg9FplGJumgZLgdlwY+WNZbXGCZwEQN3P88LTgrH/gmlSD0fHbZDyM
# YZ77M6PFlz4eXvC6I7J3VemS8OoU4DzYgxSahDXFMIIGazCCBFOgAwIBAgIKYQxq
# GQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIzWhcNMjUwNzA2MjA1MDIz
# WjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQD
# ExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+DZ0U5LGfwciUsDh8H9Az
# VfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdScFosHZSrGb+vlX2vZqFv
# m2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/OEbmisdzaXZVaZZM5Njw
# NOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMUpUwIoIPXIx/zX99vLM/a
# FtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jAvguTHijgc23SVOkoTL9r
# XZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEAAaOCAeMwggHfMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQYmOUA//PWeR03vDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEE
# AYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Q
# S0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcA
# YQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZI
# hvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnClHDDZJTD2FamkI7+5Jr0
# bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz/Q2QJCTj+dyWyvy4rL/0
# wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0bjPMAYkG6SHSHgv1QyfSH
# KcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9TUj3bkFHUhy7G8JXOqiZ
# VpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b3CLVFCNqQX/QQqbb7yV7
# BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9pE/oGw5rduS4j7DC6v11
# 9yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6MjugagwI7RiE+TIPJwX9hr
# cqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpolVf1Ayq1kEOgx+RJUeRry
# DtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ239Q+J9iguymghZ8Zrzs
# mbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcNGw186/RayZXPhxIKXezF
# ApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w3gI/h+5WoezrtUyFMYIZ
# mjCCGZYCAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENBIDIwMTACEzMAAArsJAuy
# O7ZvGhwAAAAACuwwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIBhT7C0VQ9IYyvNiupSGOc577LyiUPub5f/VTSflWIz9MEIGCisGAQQB
# gjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEABnd+pUQ4k5yl5TYH2YYljaLO
# QqZkt831g916A4Fg/2dZRv7x7s/CjT8pIgDof5Os6he6myd8yvjOgT5zP4lIBwcH
# KPBKs82WWDV+2DA9klZWXtNTinEQ9ReWdHsrssOJnN+b1NqOE42L/MQ6tgGv6BRh
# HGhbsEICgPEspM1yje8AO+Q+fVZRa2W7ELRGsppiqK0rcJQRFJnnaHfkFoVOg216
# eKFzRAwl2KDkTGqz9ZC4Ib6asXzAEgOxKHNiFeePYbuFBDa+NCRuCqDCa9MVov6L
# GHUDSBaJsCVd6pTP/6v6g8LvDIGlCxfXHLDOccZk4SaSeRTFqKm3EN7+NYSQhqGC
# FykwghclBgorBgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCArC/flbu72ERc3T9Rswp/f
# NlBI8mMLmSRKQplEOsjrYgIGZbqiLmhdGBMyMDI0MDIyMTA3MzQxOC43MDVaMASA
# AgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg2REYtNEJCQy05MzM1MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQIC
# EzMAAAHdXVcdldStqhsAAQAAAd0wDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwHhcNMjMxMDEyMTkwNzA5WhcNMjUwMTEwMTkwNzA5
# WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAKhOA5RE6i53nHURH4lnfKLp+9JvipuTtctairCxMUSrPSy5CWK2Dtri
# QP+T52HXbN2g7AktQ1pQZbTDGFzK6d03vYYNrCPuJK+PRsP2FPVDjBXy5mrLRFzI
# HHLaiAaobE5vFJuoxZ0ZWdKMCs8acjhHUmfaY+79/CR7uN+B4+xjJqwvdpU/mp0m
# Aq3earyH+AKmv6lkrQN8zgrcbCgHwsqvvqT6lEFqYpi7uKn7MAYbSeLe0pMdatV5
# EW6NVnXMYOTRKuGPfyfBKdShualLo88kG7qa2mbA5l77+X06JAesMkoyYr4/9CgD
# FjHUpcHSODujlFBKMi168zRdLerdpW0bBX9EDux2zBMMaEK8NyxawCEuAq7++7kt
# FAbl3hUKtuzYC1FUZuUl2Bq6U17S4CKsqR3itLT9qNcb2pAJ4jrIDdll5Tgoqef5
# gpv+YcvBM834bXFNwytd3ujDD24P9Dd8xfVJvumjsBQQkK5T/qy3HrQJ8ud1nHSv
# tFVi5Sa/ubGuYEpS8gF6GDWN5/KbveFkdsoTVIPo8pkWhjPs0Q7nA5+uBxQB4zlj
# EjKz5WW7BA4wpmFm24fhBmRjV4Nbp+n78cgAjvDSfTlA6DYBcv2kx1JH2dIhaRnS
# eOXePT6hMF0Il598LMu0rw35ViUWcAQkUNUTxRnqGFxz5w+ZusMDAgMBAAGjggFJ
# MIIBRTAdBgNVHQ4EFgQUbqL1toyPUdpFyyHSDKWj0I4lw/EwHwYDVR0jBBgwFoAU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcw
# AoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3Nv
# ZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZI
# hvcNAQELBQADggIBAC5U2bINLgXIHWbMcqVuf9jkUT/K8zyLBvu5h8JrqYR2z/ea
# O2yo1Ooc9Shyvxbe9GZDu7kkUzxSyJ1IZksZZw6FDq6yZNT3PEjAEnREpRBL8S+m
# bXg+O4VLS0LSmb8XIZiLsaqZ0fDEcv3HeA+/y/qKnCQWkXghpaEMwGMQzRkhGwcG
# dXr1zGpQ7HTxvfu57xFxZX1MkKnWFENJ6urd+4teUgXj0ngIOx//l3XMK3Ht8T2+
# zvGJNAF+5/5qBk7nr079zICbFXvxtidNN5eoXdW+9rAIkS+UGD19AZdBrtt6dZ+O
# dAquBiDkYQ5kVfUMKS31yHQOGgmFxuCOzTpWHalrqpdIllsy8KNsj5U9sONiWAd9
# PNlyEHHbQZDmi9/BNlOYyTt0YehLbDovmZUNazk79Od/A917mqCdTqrExwBGUPbM
# P+/vdYUqaJspupBnUtjOf/76DAhVy8e/e6zR98PkplmliO2brL3Q3rD6+ZCVdrGM
# 9Rm6hUDBBkvYh+YjmGdcQ5HB6WT9Rec8+qDHmbhLhX4Zdaard5/OXeLbgx2f7L4Q
# QQj3KgqjqDOWInVhNE1gYtTWLHe4882d/k7Lui0K1g8EZrKD7maOrsJLKPKlegce
# J9FCqY1sDUKUhRa0EHUW+ZkKLlohKrS7FwjdrINWkPBgbQznCjdE2m47QjTbMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIB
# AKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEt
# MCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUANiNH
# GWXbNaDPxnyiDbEOciSjFhCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOl/fZEwIhgPMjAyNDAyMjEwMzM1NDVa
# GA8yMDI0MDIyMjAzMzU0NVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6X99kQIB
# ADAHAgEAAgIJiDAHAgEAAgISADAKAgUA6YDPEQIBADA2BgorBgEEAYRZCgQCMSgw
# JjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3
# DQEBBQUAA4GBADaVfTFSm9aWH5RP0cNCAQJYSb33KUMlUsZ13ygKk8F/3FcTZh7i
# Zk3qST9j7ySt74M2UjzC1YE165Os4560jAm50p5k1I6mBxa3SwsrA6wR5p4ydtqu
# FpxH36kWTP6Cxzq/FkkPEU6Z4RsvfRET8tcJ+9ffJkL9vEJaBRIJBXb9MYIEDTCC
# BAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHdXVcd
# ldStqhsAAQAAAd0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgt9BqCClTPTPK+ouhhaCnw76D31SM
# CBwjF7Ycs/aOk5owgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBh/w4tmmWs
# T3iZnHtH0Vk37UCN02lRxY+RiON6wDFjZjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAAB3V1XHZXUraobAAEAAAHdMCIEIIR+l+R9DbAQ
# K2oAzTLfAfHuYAruBtWHPClS7n6qVwNxMA0GCSqGSIb3DQEBCwUABIICAH4qDhbg
# qDCImbsntVtYR5GVzNYO0ewW/1RKagh4vZaa4+OOTre/EXiPEFQPb2dylfnu0Zfy
# +Ln7K9dAE+0bXPuLYlskaptRXfn9oc5+jHhIQcLEIT6TSYHl7lc5usKXqKY6NkMT
# zG4a1VHagKMNEaNibLkcyrXcTXGuLeURM+KOLmjs+ZjFPnfXK0JGyTYygXeD1SaR
# NCjMWpbfxiueUhYp+GiTmazCiFkAEVojeFkgiteHW5jygvA7tA9Q0Eh/5Jq7Ewsu
# lH1CJZ2HuOYwvCrKeeScMRB9sqbtxWGvuiI4GnUE3V9vYEcC5eocTW385fa6rRPH
# KvZSbIsyvpkKJ/Amt2paeDQBBNbiJr2Dex4Zlw+Z0gIeMLMqX8SMTPOBz2TE0/ZD
# y9YeFe7VowbbseGLwWeG9DCTBnF71d1/mdscFV6+jswnwmaGOJU9UwxNY+ozkZy1
# /mCKsD7zcCAk6cH46RhLcQ58Nix06eRyD5XliO+pY9hdnupl4BArIdMH0WIQhaMy
# 7th8EuV14L+vfzmmfABCX9crKEclhCdrUPWlxG8CztDytO661890aWr6YJV4QcWX
# 8kIzbxmMuDsLUTyDA44uof9KDO8ynjRy/jxec7MGt2u0dDcvnTYAlrL74gsI5+pD
# X5nzfVqxD4y0nGYp3djtjRSR9ExK6HlwP8it
# SIG # End signature block
