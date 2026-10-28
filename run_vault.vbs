' run_vault.vbs
' Double-click this to launch Vault with no terminal window.
' Make a desktop shortcut to this file once, and you'll never need
' Command Prompt again - just double-click the shortcut.

Set objShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
objShell.CurrentDirectory = fso.GetParentFolderName(WScript.ScriptFullName)
objShell.Run "python app.py", 0, False
