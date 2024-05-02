cd tool
# PATH=$PATH:/home/li/LibScan/tool/module/dex2jar \
# python /home/li/LibScan/tool/LibScan.py detect_all \
#     -o /home/li/LibScan/result/phunter\
#     -af /data/phunter/issta23-artifact/dataset/apps_all_option/origin\
#     -lf /home/li/LibScan/data/vulnerability_libs\
#     -ld /home/li/LibScan/data/vulnerability_libs_dex.mybuild\

# PATH=$PATH:/home/li/LibScan/tool/module/dex2jar \
# python /home/li/LibScan/tool/LibScan.py detect_all \
#     -o /home/li/LibScan/result/reproduce-ground-truth.mybuild\
#     -af /home/li/LibScan/data/ground_truth_apks\
#     -lf /home/li/LibScan/data/ground_truth_libs\
#     -ld /home/li/LibScan/data/ground_truth_libs_dex.mybuild
# PATH=$PATH:/home/li/LibScan/tool/module/dex2jar \
# python /home/li/LibScan/tool/LibScan.py detect_all \
#     -o /home/li/LibScan/result/vuln.mybuild\
#     -af /home/li/LibScan/data/ground_truth_apks\
#     -lf /home/li/LibScan/data/vulnerability_libs\
#     -ld /home/li/LibScan/data/vulnerability_libs_dex.mybuild

# rm /home/li/LibScan/result/debugger/*
# PATH=$PATH:/home/li/LibScan/tool/module/dex2jar \
# python /home/li/LibScan/tool/LibScan.py detect_all \
#     -o /home/li/LibScan/result/debugger\
#     -af /home/li/LibScan/tmp/apk\
#     -lf /home/li/LibScan/data/phunter.adapt.test\
#     -ld /home/li/LibScan/data/phunter.adapt.test.dex\


python /home/li/LibScan/tool/LibScan.py detect_all \
    -o /home/li/LibScan/result/phunter\
    -af /data/phunter/issta23-artifact/dataset/apps_all_option/origin\
    -lf /home/li/LibScan/data/phunter.adapt\
    -ld /home/li/LibScan/data/phunter.adapt.dex