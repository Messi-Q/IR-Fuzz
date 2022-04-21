import os
import shutil


def main():
    source = "../source_code"
    target = "../contracts"
    files =os.listdir(source)
    for file in files:
        src_name = file.split(".sol")[0]
        target_dir = os.path.join(target, src_name)
        if not os.path.exists(target_dir):
            os.mkdir(target_dir)
        fh = open(os.path.join(source, file))
        while True:
            line = fh.readline()
            if line.startswith("contract"):
                new_filename = line.split(" ", 2)[1].strip()
                if new_filename[-1] == "{":
                    new_filename = new_filename[:-1]
                new_filename += ".sol"
                shutil.copyfile(os.path.join(source, file), os.path.join(target_dir, new_filename))
            if not line:
                break
        fh.close()


if __name__ == '__main__':
    main()
