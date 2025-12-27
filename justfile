set_file := "src/main.c"
output := "main"

program:
    @echo "Join Grup Biar Bisa Ngobrol Sama Atmin dan member lainya"
    @echo "[>] link komunitas : https://t.me/+NlHuKTzhZbRkMTJl"
    @python3 src/app.py

run: program
