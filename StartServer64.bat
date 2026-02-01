@setlocal enableextensions
@cd /d "%~dp0"
SET PZ_CLASSPATH=java/;java/projectzomboid.jar
".\jre64\bin\java.exe" -Djava.awt.headless=true -Dzomboid.steam=1 -Dzomboid.znetlog=0 -XX:+UseZGC -XX:-CreateCoredumpOnCrash -XX:-OmitStackTraceInFastThrow -Xms24g -Xmx24g -Duser.home="C:\PZServerBuild42\hh_saves" -Djava.library.path=natives/;natives/win64/;. -cp %PZ_CLASSPATH% zombie.network.GameServer %1 %2

