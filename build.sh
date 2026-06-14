pyinstaller \
    --onefile \
    --name netmon \
    --add-data "netmon:netmon" \
    --hidden-import textual \
    --hidden-import psutil \
    --hidden-import textual.widgets._data_table \
    run.py