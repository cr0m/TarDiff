import os
import tarfile
import hashlib
import tempfile
import difflib
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

# List of file extensions to exclude from printing content
EXCLUDED_EXTENSIONS = {'.mp4', '.pdf', '.png', '.jpeg', '.jpg', '.gif', '.bmp', '.avi', '.mov', '.mkv', '.webm'}

def compute_md5(file_path):
    """Compute MD5 checksum of a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_file_size(file_path):
    """Get the size of a file."""
    return os.path.getsize(file_path)

def format_size(size):
    """Format the file size into human-readable units."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0

def extract_tar(tar_path, extract_path):
    """Extract tar file to a specified directory."""
    with tarfile.open(tar_path) as tar:
        tar.extractall(path=extract_path)

def get_files_with_md5_and_size(startpath):
    """Get a dictionary of files with their MD5 checksums and sizes."""
    file_info = {}
    for root, dirs, files in os.walk(startpath):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, startpath)
            md5_checksum = compute_md5(file_path)
            file_size = get_file_size(file_path)
            file_info[relative_path] = (md5_checksum, file_size)
    return file_info

def generate_diff(file1, file2):
    """Generate a diff between two files."""
    try:
        with open(file1, 'r', encoding='utf-8', errors='ignore') as f1, open(file2, 'r', encoding='utf-8', errors='ignore') as f2:
            f1_lines = f1.readlines()
            f2_lines = f2.readlines()
            diff = difflib.unified_diff(f1_lines, f2_lines, fromfile=file1, tofile=file2)
            return ''.join(diff)
    except UnicodeDecodeError:
        return "Binary files differ"

def cat_file(file_path):
    """Read the content of a file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except UnicodeDecodeError:
        return "Binary file content cannot be displayed."

def is_excluded_extension(file_path):
    """Check if the file has an excluded extension."""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in EXCLUDED_EXTENSIONS

def compare_files(tar1_files, tar2_files, extract_path1, extract_path2, output_file):
    """Compare files from two dictionaries and save differences to a file."""
    all_files = set(tar1_files.keys()).union(tar2_files.keys())

    with open(output_file, 'w', encoding='utf-8') as f:
        for file in all_files:
            info_tar1 = tar1_files.get(file)
            info_tar2 = tar2_files.get(file)

            if info_tar1 and info_tar2:
                md5_tar1, size_tar1 = info_tar1
                md5_tar2, size_tar2 = info_tar2
                if md5_tar1 != md5_tar2:
                    f.write("\n" + "-" * 60 + "\n")
                    f.write(f"File '{file}' differs between tar1 and tar2:\n")
                    f.write("-" * 60 + "\n")
                    f.write(f"  - tar1 MD5: {md5_tar1}, size: {format_size(size_tar1)}\n")
                    f.write(f"  - tar2 MD5: {md5_tar2}, size: {format_size(size_tar2)}\n")
                    diff = generate_diff(os.path.join(extract_path1, file), os.path.join(extract_path2, file))
                    f.write(f"Diff:\n{diff}\n")
            elif info_tar1:
                md5_tar1, size_tar1 = info_tar1
                f.write("\n" + "-" * 60 + "\n")
                f.write(f"File '{file}' is only in tar1:\n")
                f.write("-" * 60 + "\n")
                f.write(f"  - tar1 MD5: {md5_tar1}, size: {format_size(size_tar1)}\n")
                if not is_excluded_extension(file):
                    content = cat_file(os.path.join(extract_path1, file))
                    f.write(f"Content:\n{content}\n")
            elif info_tar2:
                md5_tar2, size_tar2 = info_tar2
                f.write("\n" + "-" * 60 + "\n")
                f.write(f"File '{file}' is only in tar2:\n")
                f.write("-" * 60 + "\n")
                f.write(f"  - tar2 MD5: {md5_tar2}, size: {format_size(size_tar2)}\n")
                if not is_excluded_extension(file):
                    content = cat_file(os.path.join(extract_path2, file))
                    f.write(f"Content:\n{content}\n")

def main(tar1_path, tar2_path, output_dir):
    timestamp = datetime.now().strftime("%H%M-%m%d%y")
    output_file = os.path.join(output_dir, f"differences_output_{timestamp}.txt")
    
    with tempfile.TemporaryDirectory() as extract_path1, tempfile.TemporaryDirectory() as extract_path2:
        extract_tar(tar1_path, extract_path1)
        extract_tar(tar2_path, extract_path2)

        tar1_files = get_files_with_md5_and_size(extract_path1)
        tar2_files = get_files_with_md5_and_size(extract_path2)

        compare_files(tar1_files, tar2_files, extract_path1, extract_path2, output_file)

    # Open the output file in Notepad++
    subprocess.run(['notepad++', output_file])

def browse_tar_file(var):
    """Open a file dialog to select a tar file."""
    file_path = filedialog.askopenfilename(filetypes=[("Tar files", "*.tar")])
    var.set(file_path)

def browse_output_dir(var):
    """Open a file dialog to select the output directory."""
    directory = filedialog.askdirectory()
    var.set(directory)

def run_comparison(tar1_path, tar2_path, output_dir):
    if not tar1_path or not tar2_path or not output_dir:
        messagebox.showerror("Error", "Please select both tar files and specify an output directory.")
        return
    main(tar1_path, tar2_path, output_dir)

def create_gui():
    root = tk.Tk()
    root.title("Backup Tar File Comparator")

    tk.Label(root, text="Select the first tar file:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
    tar1_path_var = tk.StringVar()
    tk.Entry(root, textvariable=tar1_path_var, width=50).grid(row=0, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=lambda: browse_tar_file(tar1_path_var)).grid(row=0, column=2, padx=10, pady=5)

    tk.Label(root, text="Select the second tar file:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
    tar2_path_var = tk.StringVar()
    tk.Entry(root, textvariable=tar2_path_var, width=50).grid(row=1, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=lambda: browse_tar_file(tar2_path_var)).grid(row=1, column=2, padx=10, pady=5)

    tk.Label(root, text="Select the output directory:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
    output_dir_var = tk.StringVar()
    tk.Entry(root, textvariable=output_dir_var, width=50).grid(row=2, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=lambda: browse_output_dir(output_dir_var)).grid(row=2, column=2, padx=10, pady=5)

    tk.Button(root, text="Run Comparison", command=lambda: run_comparison(tar1_path_var.get(), tar2_path_var.get(), output_dir_var.get())).grid(row=3, column=0, columnspan=3, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
