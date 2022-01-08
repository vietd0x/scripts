@echo off
cd "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
(
	@echo off
	echo start www.example.com
) > opweb.cmd
