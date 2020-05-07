echo "-----" >> memory.log
echo "start:" >> memory.log
date "+%H:%M:%S   %d/%m/%y" >> memory.log
while true; do free >> memory.log; sleep 1; done
date "+%H:%M:%S   %d/%m/%y" >> memory.log
echo "-----" >> memory.log
echo "" >> memory.log