# https://stackoverflow.com/questions/28701561/midl-cannot-find-c-preprocessor-cl-exe
function Invoke-CmdScript {
  param(
    [String] $scriptName
  )
  $cmdLine = """$scriptName"" $args & set"
  & $Env:SystemRoot\system32\cmd.exe /c $cmdLine |
  select-string '^([^=]*)=(.*)$' | foreach-object {
    $varName = $_.Matches[0].Groups[1].Value
    $varValue = $_.Matches[0].Groups[2].Value
    set-item Env:$varName $varValue
  }
}

$idl_source="../MS-IDL/"
$idl_out="./idl/"
mkdir ${idl_out} | Out-Null

Invoke-CmdScript "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\midl.exe" /I ${idl_source} /out ${idl_out} ${idl_source}/ms-dtyp.idl /win32 /error all

Get-ChildItem -Path .\${idl_source} -Filter *.idl -Recurse -File -Name | ForEach-Object {
    & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\midl.exe" /I ${idl_source} /out ${idl_out} $_
}
