import os, zipfile

dir_name = "C:\\Users\\aimanov\\Desktop\\PR\\radiologs"
extension = ".zip"

os.chdir(dir_name)

for item in os.listdir(dir_name):
    print("done!")
    if item.endswith(extension):
        file_name = os.path.abspath(item)
        zip_ref = zipfile.ZipFile(file_name)
        zip_ref.extractall(dir_name)
        zip_ref.close()
        os.remove(file_name)
