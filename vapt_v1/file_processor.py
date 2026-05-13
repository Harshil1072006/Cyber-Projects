import os
import shutil
import zipfile
import tarfile
from pathlib import Path
import magic  # python-magic-bin

UPLOAD_DIR = Path("uploads")
WORK_DIR = Path("workdir")

WORK_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

class FileProcessor:
    @staticmethod
    def identify_file_type(file_path: str) -> str:
        """Uses python-magic to identify file explicitly by bytes."""
        try:
            return magic.from_file(file_path, mime=True)
        except Exception as e:
            return "application/octet-stream"

    @staticmethod
    def is_archive(mime_type: str) -> bool:
        archive_types = [
            "application/zip",
            "application/x-tar",
            "application/gzip",
            "application/x-gzip",
            "application/x-7z-compressed",
            "application/vnd.android.package-archive" # apk
        ]
        return mime_type in archive_types or "zip" in mime_type or "tar" in mime_type

    @staticmethod
    def extract_archive(file_path: str, extract_to: str) -> bool:
        """Extracts archives to specific work directory."""
        try:
            if file_path.endswith('.zip') or file_path.endswith('.apk'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
                return True
            elif file_path.endswith('.tar') or file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    
                    import os
                    
                    def is_within_directory(directory, target):
                        
                        abs_directory = os.path.abspath(directory)
                        abs_target = os.path.abspath(target)
                    
                        prefix = os.path.commonprefix([abs_directory, abs_target])
                        
                        return prefix == abs_directory
                    
                    def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                    
                        for member in tar.getmembers():
                            member_path = os.path.join(path, member.name)
                            if not is_within_directory(path, member_path):
                                raise Exception("Attempted Path Traversal in Tar File")
                    
                        tar.extractall(path, members, numeric_owner=numeric_owner) 
                        
                    safe_extract(tar_ref, extract_to)
                return True
            return False
        except Exception as e:
            print(f"Extraction error: {e}")
            return False

    @staticmethod
    def prepare_for_scan(file_path: str, scan_id: str) -> str:
        """
        Prepares a file for scanning. If argument is an archive, extracts it.
        Returns the path to the directory or file that should be scanned.
        """
        mime_type = FileProcessor.identify_file_type(file_path)
        
        target_dir = WORK_DIR / str(scan_id)
        target_dir.mkdir(exist_ok=True, parents=True)

        if FileProcessor.is_archive(mime_type):
            success = FileProcessor.extract_archive(file_path, str(target_dir))
            if success:
                return str(target_dir)
        
        # If not an archive, or extraction failed, just copy to target_dir
        dest = target_dir / Path(file_path).name
        shutil.copy2(file_path, dest)
        return str(dest)
