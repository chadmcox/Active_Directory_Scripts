For /f %i IN ('dsquery server -o rdn') do @echo %i && @Repadmin /syncall "%i" /AEP
