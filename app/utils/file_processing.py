import os
import aiofiles  # ✅ Async File Handling
from fastapi import UploadFile

# Upload directory define karein
UPLOAD_DIR = "uploaded_files"

# Agar directory nahi bani hui to bana dein
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# ✅ Change to 'async def'
async def save_upload_file(upload_file: UploadFile) -> str:
    try:
        # File ka path banayein
        file_path = os.path.join(UPLOAD_DIR, upload_file.filename)
        
        # ✅ ASYNC WRITE (Non-blocking logic)
        # shutil ki jagah aiofiles use karenge taake server hang na ho
        async with aiofiles.open(file_path, "wb") as out_file:
            # 1MB ke chunks mein read karein taake RAM full na ho
            while content := await upload_file.read(1024 * 1024):  
                await out_file.write(content)
            
        # Return absolute path
        print(f"✅ File Saved: {file_path}")
        return os.path.abspath(file_path)

    except Exception as e:
        print(f"❌ Error saving file: {e}")
        raise e
        
    finally:
        # File handle close karein (Async style)
        await upload_file.close()