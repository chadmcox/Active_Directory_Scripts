For /f %i IN ('dsquery server -o rdn') do @echo %i && @dfsrdiag.exe DumpAdCfg /member:"%i" >> %temp%\sysvolcfgdump.txt
@echo "Results found here %temp%\sysvolcfgdump.txt"
