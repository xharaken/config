ln -fs ~/config/bash_profile.sh ~/.bash_profile
#mkdir -p ~/.config/Terminal
#ln -fs ~/config/terminalrc ~/.config/Terminal/terminalrc
ln -fs ~/.bash_profile ~/.bashrc
ln -fs ~/config/dot.emacs ~/.emacs
ln -fs ~/config/dot.screenrc ~/.screenrc
chmod 0755 ~/config
source ~/.bash_profile
source ~/.bashrc
