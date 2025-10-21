#!/bin/bash
[[ $(screen -list| grep -c 'bot_teste') == '0' ]] && {
    clear
    echo -e "\E[44;1;37m     ATIVACÃO BOT SSH TESTE     \E[0m"
    echo ""
    echo -ne "\n\033[1;32mINFORME O TOKEN\033[1;37m: "
    read token
    clear
    echo "-----------MODELO-----------"
    echo "=×=×=×=×=×=×=×=×=×=×=×=×=×="
    echo "   MENSAGEM DE BOAS VINDAS   "
    echo "=×=×=×=×=×=×=×=×=×=×=×=×=×="
    echo "        MENSAGEM FINAL         "
    echo ""
    echo -ne "\033[1;32mMENSAGEM DE BOAS VINDAS:\033[1;37m "
    read bvindo
    echo -ne "\033[1;32mMENSAGEM FINAL:\033[1;37m "
    read mfinal
    clear
    echo -ne "\033[1;32mNOME DO BOTÃO 1(GERADOR SSH):\033[1;37m "
    read bt1
    clear
    echo -ne "\033[1;32mNOME DO BOTÃO 2(PERSONALIZADO):\033[1;37m "
    read bt2
    echo -ne "\033[1;32mLINK DO BOTÃO 2 (Ex: www.google.com): \033[1;37m "
    read link2
    clear
    echo -ne "\033[1;32mNOME DO BOTÃO 3(PERSONALIZADO):\033[1;37m "
    read bt3
    echo -ne "\033[1;32mLINK DO BOTÃO 3 (Ex: www.google.com):\033[1;37m "
    read link3
    clear
    echo -ne "\033[1;32mDURAÇÃO DO TESTE(EM HORAS):\033[1;37m "
    read dtempo
    clear
    echo ""
    echo -e "\033[1;32mINICIANDO BOT TESTE \033[0m\n"
    cd $HOME/BOT
    rm -rf $HOME/BOT/botssh
    wget https://www.dropbox.com/s/a7i10qa2j1dzri0/botssh >/dev/null 2>&1
    chmod 777 botssh
    echo ""
    sleep 1
    sed -i "s/BEM_VINDO/$bvindo/g" $HOME/BOT/botssh >/dev/null 2>&1
    sed -i "s/MSG_FINAL/$mfinal/g" $HOME/BOT/botssh >/dev/null 2>&1
    sed -i "s/BT_INF01/$bt1/g" $HOME/BOT/botssh >/dev/null 2>&1
    sed -i "s/INF02_BT/$bt2/g" $HOME/BOT/botssh >/dev/null 2>&1
    sed -i "s/LINK_BT02/$link2/g" $HOME/BOT/botssh >/dev/null 2>&1
    sed -i "s/BNT03_BT/$bt3/g" $HOME/BOT/botssh >/dev/null 2>&1
    sed -i "s/LK_BT03/$link3/g" $HOME/BOT/botssh >/dev/null 2>&1
        sed -i "s/TEMPO_TESTE/$dtempo/g" $HOME/BOT/botssh >/dev/null 2>&1
    sleep 1
    screen -dmS bot_teste ./botssh $token> /dev/null 2>&1
    clear
    echo "BOT ATIVADO"
    menu
} || {
    screen -r -S "bot_teste" -X quit
    clear
    echo "BOT DESATIVADO"
    menu
}
