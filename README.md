# TarDiff

TarDiff is a Python-based tool that compares the contents of two tar files. It computes MD5 checksums and file sizes, identifies differences, and generates a detailed report. The tool features a user-friendly GUI for selecting tar files and specifying the output directory. The resulting report is automatically opened in Notepad++ for easy review.

## Features

- Compare two tar files and identify differences.
- Generate a detailed report with MD5 checksums and file sizes.
- Exclude specific file types (e.g., videos, PDFs, images) from content printing.
- User-friendly GUI for file selection and output directory specification.
- Automatically opens the report in Notepad++.

## Usage

1. Run the script:
    ```
    python tardiff.py
    ```
	
2. A GUI window will appear allowing you to:
    - Select the first tar file.
    - Select the second tar file.
    - Specify the output directory.
	
3. Click "Run Comparison" to generate the report.

The results will be saved to an automatically named output file with a timestamp in the specified directory, and the file will be opened in Notepad++ for review.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.
