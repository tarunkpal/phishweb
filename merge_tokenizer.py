import os

def merge_parts(base_filename, output_file):
    part_num = 0
    with open(output_file, 'wb') as outfile:
        while True:
            part_file = f"{base_filename}.part{part_num:03d}"
            if not os.path.exists(part_file):
                break
            with open(part_file, 'rb') as pf:
                outfile.write(pf.read())
            print(f"Merged: {part_file}")
            part_num += 1

if __name__ == "__main__":
    merge_parts("html_tokenizer.pkl", "html_tokenizer.pkl")
