git pull origin coq
git checkout coq
sudo bash memory.sh &
sudo bash coq.sh
git add memory.log coq.log
git commit -m "Auto: Coq Job"
git push origin coq
sudo poweroff