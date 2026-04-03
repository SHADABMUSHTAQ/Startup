import os
import re

routes_dir = r"c:\Users\Lenovo\Desktop\Startup-backend\app\routes"

for filename in os.listdir(routes_dir):
    if filename.endswith(".py"):
        filepath = os.path.join(routes_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        changed = False

        # If it uses db=Depends(get_db), we need to import AsyncIOMotorDatabase
        if "Depends(get_db)" in content:
            if "AsyncIOMotorDatabase" not in content:
                # Add import right after FastAPI imports
                content = content.replace(
                    "from fastapi import ", 
                    "from motor.motor_asyncio import AsyncIOMotorDatabase\nfrom fastapi import ", 
                    1
                )
                if "from motor.motor_asyncio" not in content:
                    # fallback
                    content = "from motor.motor_asyncio import AsyncIOMotorDatabase\n" + content
                changed = True

            # Adjust the inline parameter
            new_content = re.sub(r'\bdb\s*=\s*Depends\(get_db\)', r'db: AsyncIOMotorDatabase = Depends(get_db)', content)
            
            # Also adjust cases where it might be db = Depends(get_db)
            if new_content != content:
                content = new_content
                changed = True

        if changed:
            print(f"Adding type hints to {filepath}...")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

print("Type hints added!")
