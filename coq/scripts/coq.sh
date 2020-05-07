echo "-----" >> coq.log
echo "start:" >> coq.log
date "+%H:%M:%S   %d/%m/%y" >> coq.log
coqc ../signal.v
date "+%H:%M:%S   %d/%m/%y" >> coq.log
echo "-----" >> coq.log
echo "" >> coq.log